import { AsyncEntry } from "@napi-rs/keyring";
import type { KeyProvider } from "../application/key-provider.ts";
import { WardError } from "../contract/errors.ts";
import { envelopeLimits, isVaultId } from "../domain/envelope.ts";

// The vault key as a generic-password item in the OS credential store,
// through @napi-rs/keyring (docs/adr/0001). On macOS the item lands in the
// legacy file-based login keychain, and its ACL trusts only the build that
// created it; measured under WCLI-5.
//
// The production service name is passed in by the CLI composition root; this
// module has no default, so a test cannot reach the real item by omission.
//
// It is fixed when the executable is compiled, never read at runtime:
// scripts/build.ts always defines WARD_KEYCHAIN_SERVICE, to "opum.ward" for the
// shipped build and to a distinct `opum.ward.qualify-<random>` for the
// qualification build (WCLI-15, DEC-217 (a2)). The compiler folds the check
// below, so the shipped binary carries one literal and no override: no
// environment variable, argument or file can redirect it to another service.
// Run from source, where nothing is defined, it is the production name.
declare const WARD_KEYCHAIN_SERVICE: string | undefined;
export const keychainService: string =
  typeof WARD_KEYCHAIN_SERVICE === "string"
    ? WARD_KEYCHAIN_SERVICE
    : "opum.ward";

// Every credential-store call is bounded. This bounds the promise only: a
// native call can outlive its abort and keep the process alive, so a
// command that receives vault_key_unavailable must exit explicitly rather
// than wait for the event loop to drain (WCLI-20).
export const defaultKeyTimeoutMs = 10_000;

export interface SecretEntry {
  getSecret(signal?: AbortSignal): Promise<unknown>;
  setSecret(secret: Uint8Array, signal?: AbortSignal): Promise<void>;
}

export type EntryFactory = (service: string, account: string) => SecretEntry;

// macOS only until WCLI-21 and WCLI-22 qualify another backend. On Linux the
// binding silently falls back to the kernel keyutils keyring, which does not
// survive a reboot; spec §6.4 forbids that substitution.
function nativeEntryFor(platform: string): EntryFactory {
  return (service, account) => {
    if (platform !== "darwin")
      throw new WardError("vault_key_store_unsupported");
    return new AsyncEntry(service, account);
  };
}

function accountFor(vaultId: string): string {
  if (!isVaultId(vaultId)) throw new WardError("vault_record_malformed");
  return `vault-${vaultId}`;
}

function zero(value: unknown): void {
  try {
    if (Array.isArray(value) || value instanceof Uint8Array) value.fill(0);
  } catch {
    // Best effort: a frozen or exotic value is left as it is.
  }
}

async function bounded<T>(
  timeoutMs: number,
  failure: "vault_key_unavailable" | "vault_key_write_unconfirmed",
  run: (signal: AbortSignal) => Promise<T>,
  onAbandon?: () => void,
): Promise<T> {
  const controller = new AbortController();
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      // The bound gave up on a call that may still be running natively.
      onAbandon?.();
      reject(new WardError(failure));
    }, timeoutMs);
  });
  const call = (async () => {
    try {
      const value = await run(controller.signal);
      // A key that arrives after the caller gave up is not used by anyone.
      if (timedOut) zero(value);
      return value;
    } catch {
      // The store's message is not passed on: it can name items or paths.
      throw new WardError(failure);
    }
  })();
  try {
    return await Promise.race([call, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// The binding resolves a plain number[] (not the Uint8Array its types
// declare) and null for an absent item; both measured under WCLI-5. Every
// index is checked, including holes, and the source is overwritten after
// copying, as best effort only.
function keyFrom(raw: unknown): Uint8Array {
  const candidate =
    raw instanceof Uint8Array || Array.isArray(raw)
      ? (raw as ArrayLike<unknown>)
      : undefined;
  let key: Uint8Array | undefined;
  if (candidate !== undefined && candidate.length === envelopeLimits.keyBytes) {
    const copy = new Uint8Array(envelopeLimits.keyBytes);
    let valid = true;
    for (let index = 0; index < envelopeLimits.keyBytes; index++) {
      const byte = index in candidate ? candidate[index] : undefined;
      if (
        typeof byte !== "number" ||
        !Number.isInteger(byte) ||
        byte < 0 ||
        byte > 255
      ) {
        valid = false;
        break;
      }
      copy[index] = byte;
    }
    if (valid) key = copy;
    else copy.fill(0);
  }
  zero(raw);
  if (key === undefined) throw new WardError("vault_key_invalid");
  return key;
}

export function createKeychainKeyProvider(options: {
  service: string;
  timeoutMs?: number;
  entry?: EntryFactory;
  platform?: string;
}): KeyProvider {
  const { service } = options;
  const timeoutMs = options.timeoutMs ?? defaultKeyTimeoutMs;
  const entryFor =
    options.entry ?? nativeEntryFor(options.platform ?? process.platform);
  let abandoned = false;
  const onAbandon = () => {
    abandoned = true;
  };

  async function read(
    entry: SecretEntry,
    failure: "vault_key_unavailable" | "vault_key_write_unconfirmed",
  ): Promise<Uint8Array | undefined> {
    const raw = await bounded(
      timeoutMs,
      failure,
      (signal) => entry.getSecret(signal),
      onAbandon,
    );
    return raw === null || raw === undefined ? undefined : keyFrom(raw);
  }

  return {
    async load(vaultId) {
      const entry = entryFor(service, accountFor(vaultId));
      const key = await read(entry, "vault_key_unavailable");
      if (key === undefined) throw new WardError("vault_key_missing");
      return key;
    },

    // Check, write, read back. The check and the write are not atomic in the
    // store: another writer between them is overwritten. `ward setup`
    // (WCLI-20) serializes Ward against itself; nothing here can stop a
    // writer outside Ward.
    async create(vaultId, key) {
      const entry = entryFor(service, accountFor(vaultId));
      if (!(key instanceof Uint8Array))
        throw new WardError("vault_key_invalid");
      const owned = new Uint8Array(key);
      if (owned.length !== envelopeLimits.keyBytes) {
        owned.fill(0);
        throw new WardError("vault_key_invalid");
      }
      let existing: Uint8Array | undefined;
      try {
        existing = await read(entry, "vault_key_unavailable");
      } catch (error) {
        owned.fill(0);
        // An unreadable existing item still exists: never write over it.
        if (error instanceof WardError && error.code === "vault_key_invalid")
          throw new WardError("vault_key_exists");
        throw error;
      }
      if (existing !== undefined) {
        existing.fill(0);
        owned.fill(0);
        throw new WardError("vault_key_exists");
      }
      // From here a failure is indeterminate: the write may have landed.
      // `owned` is not zeroed on that path, because a native write still
      // pending might read it.
      await bounded(
        timeoutMs,
        "vault_key_write_unconfirmed",
        (signal) => entry.setSecret(owned, signal),
        onAbandon,
      );
      let stored: Uint8Array | undefined;
      try {
        stored = await read(entry, "vault_key_write_unconfirmed");
      } catch {
        throw new WardError("vault_key_write_unconfirmed");
      }
      const same =
        stored !== undefined &&
        stored.length === owned.length &&
        stored.every((byte, index) => byte === owned[index]);
      stored?.fill(0);
      owned.fill(0);
      if (!same) throw new WardError("vault_key_write_unconfirmed");
    },

    // True once any call was abandoned at its bound, so the entry point can
    // exit explicitly instead of waiting out a pending native call.
    abandonedCall: () => abandoned,
  };
}
