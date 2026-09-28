import { AsyncEntry } from "@napi-rs/keyring";
import type { KeyProvider } from "../application/key-provider.ts";
import { WardError } from "../contract/errors.ts";
import { envelopeLimits, isVaultId } from "../domain/envelope.ts";

// The vault key as a generic-password item in the OS credential store,
// through @napi-rs/keyring (docs/adr/0001). On macOS the item lands in the
// legacy file-based login keychain, and its ACL trusts only the build that
// created it; measured under WCLI-5.
export const keychainService = "opum.ward";

// Every credential-store call is bounded. A locked keychain or a hidden
// approval prompt must not hold a noninteractive command indefinitely.
export const defaultKeyTimeoutMs = 10_000;

export interface SecretEntry {
  getSecret(signal?: AbortSignal): Promise<unknown>;
  setSecret(secret: Uint8Array, signal?: AbortSignal): Promise<void>;
}

export type EntryFactory = (service: string, account: string) => SecretEntry;

function nativeEntry(service: string, account: string): SecretEntry {
  // bun test sets NODE_ENV=test, and the compiled executable inlines
  // "development". A test that reached the real production item would
  // touch the developer's actual vault key, so it fails here instead.
  if (service === keychainService && process.env.NODE_ENV === "test")
    throw new Error("tests must not use the production keychain service");
  return new AsyncEntry(service, account);
}

function accountFor(vaultId: string): string {
  if (!isVaultId(vaultId)) throw new WardError("vault_record_malformed");
  return `vault-${vaultId}`;
}

// A native call can outlive its abort: the signal is passed through, but
// the timer here is what bounds the wait. A caller that times out should
// exit rather than wait for the process to drain, because a native call
// may still be pending on a worker thread.
async function bounded<T>(
  timeoutMs: number,
  run: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new WardError("vault_key_unavailable"));
    }, timeoutMs);
  });
  const call = (async () => {
    try {
      return await run(controller.signal);
    } catch {
      // The store's message is not passed on: it can name items or paths.
      throw new WardError("vault_key_unavailable");
    }
  })();
  try {
    return await Promise.race([call, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// The binding resolves a plain number[] (not the Uint8Array its types
// declare) and null for an absent item; both measured under WCLI-5. The
// source array is overwritten afterwards, as best effort only.
function keyFrom(raw: unknown): Uint8Array {
  const bytes =
    raw instanceof Uint8Array || Array.isArray(raw)
      ? (raw as ArrayLike<unknown>)
      : undefined;
  if (bytes === undefined) throw new WardError("vault_key_invalid");
  const valid =
    bytes.length === envelopeLimits.keyBytes &&
    Array.prototype.every.call(
      bytes,
      (byte: unknown) =>
        typeof byte === "number" &&
        Number.isInteger(byte) &&
        byte >= 0 &&
        byte <= 255,
    );
  const key = valid ? Uint8Array.from(bytes as ArrayLike<number>) : undefined;
  if (Array.isArray(raw)) raw.fill(0);
  else if (raw instanceof Uint8Array) raw.fill(0);
  if (key === undefined) throw new WardError("vault_key_invalid");
  return key;
}

export function createKeychainKeyProvider(
  options: { service?: string; timeoutMs?: number; entry?: EntryFactory } = {},
): KeyProvider {
  const service = options.service ?? keychainService;
  const timeoutMs = options.timeoutMs ?? defaultKeyTimeoutMs;
  const entryFor = options.entry ?? nativeEntry;

  async function read(entry: SecretEntry): Promise<Uint8Array | undefined> {
    const raw = await bounded(timeoutMs, (signal) => entry.getSecret(signal));
    return raw === null || raw === undefined ? undefined : keyFrom(raw);
  }

  return {
    async load(vaultId) {
      const key = await read(entryFor(service, accountFor(vaultId)));
      if (key === undefined) throw new WardError("vault_key_missing");
      return key;
    },

    // Check, write, read back. The check and the write are not atomic in
    // the credential store, so two concurrent setups could race; `ward
    // setup` (WCLI-20) must serialize itself before calling this.
    async create(vaultId, key) {
      const entry = entryFor(service, accountFor(vaultId));
      if (!(key instanceof Uint8Array))
        throw new WardError("vault_key_invalid");
      const owned = new Uint8Array(key);
      if (owned.length !== envelopeLimits.keyBytes)
        throw new WardError("vault_key_invalid");
      let existing: Uint8Array | undefined;
      try {
        existing = await read(entry);
      } catch (error) {
        // An unreadable existing item still exists: never write over it.
        if (error instanceof WardError && error.code === "vault_key_invalid")
          throw new WardError("vault_key_exists");
        throw error;
      }
      if (existing !== undefined) {
        existing.fill(0);
        throw new WardError("vault_key_exists");
      }
      await bounded(timeoutMs, (signal) => entry.setSecret(owned, signal));
      const stored = await read(entry);
      const same =
        stored !== undefined &&
        stored.length === owned.length &&
        stored.every((byte, index) => byte === owned[index]);
      stored?.fill(0);
      owned.fill(0);
      if (!same) throw new WardError("vault_key_unavailable");
    },
  };
}
