// `ward setup` (spec §6.4, §8): the one place Ward ever creates a vault key
// or a vault. Run by the developer in a trusted terminal; no other command
// calls the provider's create. The flow here is policy only: the lock and
// journal I/O is the injected session, and the store and provider are ports.
//
// Resume model: an interrupted setup is completed, never redone. The session
// journal pins the vault id before the key exists, so a rerun reuses the
// same id and the same key account. An existing vault whose key loads is an
// already-completed setup (the journal decides between "finish the cleanup"
// and "refuse a plain rerun"); an existing vault whose key does not load is
// a recovery condition, reported with the catalog's own text, and nothing
// is created. A create whose write is unconfirmed is resolved with load()
// and never by writing again (WCLI-5 review).
import { WardError } from "../contract/errors.ts";
import { generateVaultKey, isVaultId } from "../domain/envelope.ts";
import type { KeyProvider } from "./key-provider.ts";
import type { VaultStore } from "./vault-store.ts";

export interface SetupSession {
  journalVaultId(): string | undefined;
  recordVaultId(vaultId: string): void;
  release(): void;
  complete(): void;
}

export interface SetupResult {
  vaultId: string;
  revision: number;
  // True when the run finished an interrupted setup rather than starting
  // fresh, including one that had already completed.
  resumed: boolean;
}

// The minimal self-describing vault document. The full state schema is the
// next layer's contract (WCLI-7): setup seals only this skeleton.
export function initialVaultSnapshot(): Uint8Array {
  return new TextEncoder().encode('{"formatVersion":1}');
}

export async function runSetup(options: {
  session: SetupSession;
  keyProvider: KeyProvider;
  store: VaultStore;
}): Promise<SetupResult> {
  const { session, keyProvider, store } = options;
  let completed = false;
  let key: Uint8Array | undefined;
  try {
    const header = store.header();
    if (header !== undefined) {
      // A vault exists. Its key must load; anything else is a recovery
      // condition and nothing is created or replaced.
      const existing = await keyProvider.load(header.vaultId);
      existing.fill(0);
      if (session.journalVaultId() === undefined)
        throw new WardError("vault_exists");
      // The previous run finished the vault but died before removing the
      // journal: finish the cleanup and report the completed setup.
      session.complete();
      completed = true;
      return {
        vaultId: header.vaultId,
        revision: header.revision,
        resumed: true,
      };
    }

    // No vault. Pin the id first: a fresh one, or the one an interrupted
    // run recorded, durably, before the key exists.
    const journalId = session.journalVaultId();
    const vaultId = journalId ?? crypto.randomUUID();
    if (!isVaultId(vaultId)) throw new WardError("vault_record_malformed");
    session.recordVaultId(vaultId);

    // The key: reuse one an interrupted run already stored, otherwise
    // generate and store it. An existing key is never replaced.
    try {
      key = await keyProvider.load(vaultId);
    } catch (error) {
      if (!(error instanceof WardError) || error.code !== "vault_key_missing")
        throw error;
      key = generateVaultKey();
      try {
        await keyProvider.create(vaultId, key);
      } catch (createError) {
        if (
          createError instanceof WardError &&
          createError.code === "vault_key_write_unconfirmed"
        ) {
          // The write may have landed. Resolve with load(); never write
          // again. `key` is zeroed below in the finally; the provider
          // copied its own bytes, and a pending native write reads those,
          // not this buffer.
          try {
            const stored = await keyProvider.load(vaultId);
            key.fill(0);
            key = stored;
          } catch {
            throw createError;
          }
        } else {
          throw createError;
        }
      }
    }

    const created = store.create(vaultId, key, initialVaultSnapshot());
    session.complete();
    completed = true;
    return {
      vaultId,
      revision: created.revision,
      resumed: journalId !== undefined,
    };
  } finally {
    key?.fill(0);
    if (!completed) session.release();
  }
}
