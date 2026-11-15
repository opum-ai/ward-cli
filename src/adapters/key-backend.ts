import { join } from "node:path";
import type { KeyProvider } from "../application/key-provider.ts";
import { type KeyStoreName, WardError } from "../contract/errors.ts";
import { isVaultId } from "../domain/envelope.ts";
import { createKeychainKeyProvider, keychainService } from "./keychain.ts";
import {
  createTpm2KeyProvider,
  translateTpm2Error,
  type Tpm2ProviderOptions,
} from "./tpm2-provider.ts";
import {
  detectTpm2,
  holdsSealedKey,
  preparePrivateDirectory,
  Tpm2Error,
  type Tpm2Warning,
} from "./tpm2-tools.ts";

// Which credential store holds a vault's key (DEC-262 a16 Q2 rules 1, 2, 3 and
// 5, with a22). Ward picks by presence of the key itself and reports the choice;
// it never switches silently and never falls back. Nothing is written into the
// vault, so its format is unchanged (rule 5).

export interface KeyBackend {
  readonly name: KeyStoreName;
  readonly provider: KeyProvider;
  // Whether this store holds the vault's key. A store that cannot say rejects,
  // and the refusal names it; it is never read as "not held". A backend that
  // had to read the key to find out hands it back so it is not read twice.
  probe(
    vaultId: string,
  ): Promise<{ held: false } | { held: true; key?: Uint8Array }>;
}

function named(error: unknown, store: KeyStoreName): unknown {
  return error instanceof WardError
    ? new WardError(error.code, undefined, undefined, [store])
    : error;
}

export function createRoutingKeyProvider(options: {
  backends: readonly KeyBackend[];
  // Where a NEW key goes. Throws when no backend can take one.
  initialisation: () => KeyBackend;
}): KeyProvider {
  return {
    async load(vaultId) {
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
        if (holders.length > 1)
          throw new WardError(
            "vault_key_ambiguous",
            undefined,
            undefined,
            holders.map((holder) => holder.backend.name),
          );
      } catch (error) {
        for (const holder of holders) holder.key?.fill(0);
        throw error;
      }
      const holder = holders[0];
      if (holder === undefined) throw new WardError("vault_key_missing");
      return holder.key ?? (await holder.backend.provider.load(vaultId));
    },

    async create(vaultId, key) {
      await options.initialisation().provider.create(vaultId, key);
    },

    abandonedCall: () =>
      options.backends.some((backend) => backend.provider.abandonedCall?.()),
  };
}

export function keychainBackend(provider: KeyProvider): KeyBackend {
  return {
    name: "macOS Keychain",
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
  readonly tpm2?: Partial<Tpm2ProviderOptions>;
}

// The default sink for a possibly leaked TPM session slot: one JSON line with
// the code and nothing else, on stderr.
function warnOnStderr(warning: Tpm2Warning): void {
  process.stderr.write(`${JSON.stringify({ warning: warning.code })}\n`);
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
      directoryFor,
      onWarning: warnOnStderr,
      prepareDirectory: tpm2PrepareDirectory(wardDirectory),
      ...selection.tpm2,
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
        if (error instanceof Tpm2Error) throw translateTpm2Error(error);
        throw error;
      }
      return tpm2;
    },
  });
}
