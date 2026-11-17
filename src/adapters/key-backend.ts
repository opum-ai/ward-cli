import { join } from "node:path";
import type {
  KeyBackendId,
  KeyProvider,
  KeyRefusalState,
} from "../application/key-provider.ts";
import { type KeyStoreName, WardError } from "../contract/errors.ts";
import { isVaultId } from "../domain/envelope.ts";
import { createKeychainKeyProvider, keychainService } from "./keychain.ts";
import {
  createTpm2KeyProvider,
  TpmKeyError,
  translateTpm2Error,
  type Tpm2ProviderOptions,
} from "./tpm2-provider.ts";
import {
  detectTpm2,
  holdsSealedKey,
  preparePrivateDirectory,
  Tpm2Error,
  tpm2ErrorCodes,
  tpm2StateFor,
  type Tpm2Warning,
} from "./tpm2-tools.ts";

// Which credential store holds a vault's key (DEC-262 a16 Q2 rules 1, 2, 3 and
// 5, with a22). Ward picks by presence of the key itself and reports the choice;
// it never switches silently and never falls back. Nothing is written into the
// vault, so its format is unchanged (rule 5).

export interface KeyBackend {
  readonly name: KeyStoreName;
  // How a report names this store (DEC-262 a24).
  readonly id: KeyBackendId;
  readonly provider: KeyProvider;
  // Whether this store holds the vault's key. A store that cannot say rejects,
  // and the refusal names it; it is never read as "not held". A backend that
  // had to read the key to find out hands it back so it is not read twice.
  probe(
    vaultId: string,
  ): Promise<{ held: false } | { held: true; key?: Uint8Array }>;
}

// Names the store in a refusal. A TPM refusal keeps its subclass and its
// Tpm2Error (doctor reads them), and a platform with no backend at all is not
// pinned on a store it never had.
function named(error: unknown, store: KeyStoreName): unknown {
  if (!(error instanceof WardError)) return error;
  if (error.code === "vault_key_store_unsupported") return error;
  if (error instanceof TpmKeyError)
    return new TpmKeyError(error.code, error.tpm2, error.notes, [store]);
  return new WardError(error.code, undefined, undefined, [store]);
}

export function createRoutingKeyProvider(options: {
  backends: readonly KeyBackend[];
  // Where a NEW key goes. Throws when no backend can take one.
  initialisation: () => KeyBackend;
}): KeyProvider {
  // The store the last load settled on; null when none could be (two held the
  // key); undefined before any load or when no store held it, which reads as
  // the store a new key would go to.
  let settled: KeyBackendId | null | undefined;
  return {
    async load(vaultId) {
      settled = undefined;
      const holders: { backend: KeyBackend; key?: Uint8Array }[] = [];
      try {
        for (const backend of options.backends) {
          let result: Awaited<ReturnType<KeyBackend["probe"]>>;
          try {
            result = await backend.probe(vaultId);
          } catch (error) {
            throw named(error, backend.name);
          }
          if (result.held)
            holders.push({
              backend,
              ...(result.key === undefined ? {} : { key: result.key }),
            });
        }
        if (holders.length > 1) {
          settled = null;
          throw new WardError(
            "vault_key_ambiguous",
            undefined,
            undefined,
            holders.map((holder) => holder.backend.name),
          );
        }
      } catch (error) {
        for (const holder of holders) holder.key?.fill(0);
        throw error;
      }
      const holder = holders[0];
      if (holder === undefined) throw new WardError("vault_key_missing");
      settled = holder.backend.id;
      if (holder.key !== undefined) return holder.key;
      try {
        return await holder.backend.provider.load(vaultId);
      } catch (error) {
        throw named(error, holder.backend.name);
      }
    },

    async create(vaultId, key) {
      await options.initialisation().provider.create(vaultId, key);
    },

    abandonedCall: () =>
      options.backends.some((backend) => backend.provider.abandonedCall?.()),

    backend() {
      if (settled !== undefined) return settled;
      try {
        return options.initialisation().id;
      } catch {
        return null;
      }
    },
  };
}

export function keychainBackend(provider: KeyProvider): KeyBackend {
  return {
    name: "macOS Keychain",
    id: "macos-keychain",
    provider,
    async probe(vaultId) {
      try {
        return { held: true, key: await provider.load(vaultId) };
      } catch (error) {
        if (error instanceof WardError && error.code === "vault_key_missing")
          return { held: false };
        throw error;
      }
    },
  };
}

export function tpm2Backend(
  provider: KeyProvider,
  directoryFor: (vaultId: string) => string,
): KeyBackend {
  return {
    name: "TPM2",
    id: "tpm2",
    provider,
    async probe(vaultId) {
      if (!isVaultId(vaultId)) throw new WardError("vault_record_malformed");
      try {
        return { held: holdsSealedKey(directoryFor(vaultId)) };
      } catch (error) {
        throw translateTpm2Error(error);
      }
    },
  };
}

// <wardDir>/tpm/<vaultId>/ (a22 Q-B). The vault id is the stable identifier,
// checked here as well as in the provider, never a path or a display name.
export function tpm2DirectoryFor(
  wardDirectory: string,
): (vaultId: string) => string {
  return (vaultId) => {
    if (!isVaultId(vaultId)) throw new WardError("vault_record_malformed");
    return join(wardDirectory, "tpm", vaultId);
  };
}

// A pre-existing directory that is not this user's or not 0700 refuses with
// blob_not_user_private and is never chmodded into compliance (a22 Q-B 2).
function tpm2PrepareDirectory(wardDirectory: string): () => void {
  return () => {
    preparePrivateDirectory(wardDirectory);
    preparePrivateDirectory(join(wardDirectory, "tpm"));
  };
}

export interface KeySelection {
  readonly platform?: string;
  // Test seams. Production leaves them unset.
  readonly keychain?: KeyProvider;
  // The blob directory is policy, never a seam: directoryFor and
  // prepareDirectory cannot be replaced from here.
  readonly tpm2?: Omit<
    Partial<Tpm2ProviderOptions>,
    "directoryFor" | "prepareDirectory"
  >;
}

// How a possibly leaked TPM session slot is told (DEC-262 a23): under --json
// exactly one line carrying the code and nothing else; in human mode a sentence
// with the code and what clears it. Neither carries a path or a handle.
export function formatKeyWarning(warning: Tpm2Warning, json: boolean): string {
  return json
    ? `${JSON.stringify({ warning: warning.code })}\n`
    : `warning: ${warning.code}: a TPM session slot may be leaked; it is cleared by a reset or reboot.\n`;
}

// The sink used when the caller supplies none: human wording on stderr.
function warnOnStderr(warning: Tpm2Warning): void {
  process.stderr.write(formatKeyWarning(warning, false));
}

export function selectKeyProvider(
  wardDirectory: string,
  selection: KeySelection = {},
): KeyProvider {
  const platform = selection.platform ?? process.platform;
  const keychain = keychainBackend(
    selection.keychain ??
      createKeychainKeyProvider({ service: keychainService, platform }),
  );
  if (platform !== "linux") {
    // macOS holds keys in the Keychain. Any other platform reaches the same
    // provider, which refuses it as vault_key_store_unsupported.
    return createRoutingKeyProvider({
      backends: [keychain],
      initialisation: () => keychain,
    });
  }
  const directoryFor = tpm2DirectoryFor(wardDirectory);
  const detect = selection.tpm2?.detect ?? (() => detectTpm2());
  const tpm2 = tpm2Backend(
    createTpm2KeyProvider({
      onWarning: warnOnStderr,
      ...selection.tpm2,
      // After the spread, so a caller that smuggles either in is ignored.
      directoryFor,
      prepareDirectory: tpm2PrepareDirectory(wardDirectory),
      detect,
    }),
    directoryFor,
  );
  // Secret Service is a NAMED GAP (a22 Q-A): not implemented, so a desktop
  // initialises on TPM2 like any other Linux host, and presence keeps it there.
  return createRoutingKeyProvider({
    backends: [tpm2],
    initialisation: () => {
      try {
        detect();
      } catch (error) {
        if (error instanceof Tpm2Error)
          throw new TpmKeyError(tpm2ErrorCodes[error.reason], error, [
            "secret_service_not_implemented",
          ]);
        throw error;
      }
      return tpm2;
    },
  });
}

// The report-side reading of a TPM2 load failure: the doctor state of the
// Tpm2Error the provider kept, never of the WardError (whose catalog text
// carries no path or version). Anything else has no backend detail.
export function keyRefusalState(error: unknown): KeyRefusalState | undefined {
  return error instanceof TpmKeyError ? tpm2StateFor(error.tpm2) : undefined;
}
