import type { KeyProvider } from "../application/key-provider.ts";
import { WardError } from "../contract/errors.ts";
import { envelopeLimits, isVaultId } from "../domain/envelope.ts";
import {
  detectTpm2,
  sealKey,
  type Tpm2Presence,
  Tpm2Error,
  type Tpm2Warning,
  unsealKey,
  wardErrorFor,
} from "./tpm2-tools.ts";

// The vault key sealed to this machine's TPM2 (DEC-262 a16, slice 3d-1a). It
// implements the KeyProvider port over the adapter in tpm2-tools.ts and is not
// wired to any command yet: backend selection and the blob directory policy
// arrive with 3d-1b. The directory is an injected input, one per vault.

// A WardError that keeps the Tpm2Error it was made from. doctor reads
// reason, detail, path and flushFailure from `tpm2` (tpm2StateFor), never from
// the WardError, whose catalog text carries none of them.
export class TpmKeyError extends WardError {
  readonly tpm2: Tpm2Error;
  constructor(
    code: ConstructorParameters<typeof WardError>[0],
    tpm2: Tpm2Error,
    notes: ConstructorParameters<typeof WardError>[4] = [],
  ) {
    super(code, undefined, undefined, [], notes);
    this.name = "TpmKeyError";
    this.tpm2 = tpm2;
  }
}

export interface Tpm2ProviderOptions {
  // The directory holding this vault's sealed pair. No path policy lives here.
  directoryFor: (vaultId: string) => string;
  // Hears of a possibly leaked saved-session slot. It receives the code only.
  onWarning?: (warning: Tpm2Warning) => unknown;
  timeoutMs?: number;
  // Creates this vault's parent directories before a seal, refusing one that
  // is not private (blob_not_user_private) and never repairing it. Absent means
  // the caller owns the whole path.
  prepareDirectory?: (vaultId: string) => void;
  // Seams for tests: detection and the two tools-level operations.
  detect?: () => Tpm2Presence;
  unseal?: typeof unsealKey;
  seal?: typeof sealKey;
}

// How each refusal reaches the KeyProvider contract. A missing sealed key is
// the contract's missing key; a lone private blob is NEVER that, because it is
// a recovery condition and setup must not run over it (N3 a).
export function translateTpm2Error(error: unknown): WardError {
  const tpm2 =
    error instanceof Tpm2Error
      ? error
      : new Tpm2Error("tool_failed", undefined);
  switch (tpm2.reason) {
    case "key_not_sealed":
      return new TpmKeyError("vault_key_missing", tpm2);
    case "key_exists":
      return new TpmKeyError("vault_key_exists", tpm2);
    default:
      return new TpmKeyError(wardErrorFor(tpm2).code, tpm2);
  }
}

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

export function createTpm2KeyProvider(
  options: Tpm2ProviderOptions,
): KeyProvider {
  const detect = options.detect ?? (() => detectTpm2());
  const unseal = options.unseal ?? unsealKey;
  const seal = options.seal ?? sealKey;
  // N7 (NB4): a timeout can strand a saved session, because the killed tool
  // never reached its flush. Nothing here recovers it; the only report is
  // doctor's saved-session count (diagnoseTpm2). The test that pins the abandon
  // path is "a timed-out tool marks the call abandoned" in
  // test/tpm2-provider.test.ts.
  let abandoned = false;

  // Fresh detection on every call: access can be revoked between two calls,
  // and a stale presence would let that read as an unloadable key.
  function directoryOf(vaultId: string): string {
    if (!isVaultId(vaultId)) throw new WardError("vault_record_malformed");
    return options.directoryFor(vaultId);
  }

  function note(error: unknown): void {
    // A timed-out flush after a failed unseal is a timeout too: the killed
    // flush may have stranded a session, and the CLI must exit explicitly.
    if (
      error instanceof Tpm2Error &&
      (error.reason === "tool_timeout" || error.flushFailure === "tool_timeout")
    )
      abandoned = true;
  }

  async function read(directory: string): Promise<Uint8Array> {
    const presence = detect();
    return await unseal(presence, directory, {
      timeoutMs: options.timeoutMs,
      onWarning: options.onWarning,
    });
  }

  return {
    async load(vaultId) {
      const directory = directoryOf(vaultId);
      try {
        return await read(directory);
      } catch (error) {
        note(error);
        throw translateTpm2Error(error);
      }
    },

    async create(vaultId, key) {
      const directory = directoryOf(vaultId);
      if (!(key instanceof Uint8Array))
        throw new WardError("vault_key_invalid");
      const owned = new Uint8Array(key);
      if (owned.length !== envelopeLimits.keyBytes) {
        owned.fill(0);
        throw new WardError("vault_key_invalid");
      }
      try {
        let presence: Tpm2Presence;
        try {
          options.prepareDirectory?.(vaultId);
          presence = detect();
        } catch (error) {
          note(error);
          throw translateTpm2Error(error);
        }
        try {
          await seal(presence, owned, directory, {
            timeoutMs: options.timeoutMs,
          });
        } catch (error) {
          note(error);
          // A refusal before anything was written is the refusal itself. A
          // tool that timed out or failed mid-seal may have left a pair.
          if (
            error instanceof Tpm2Error &&
            (error.reason === "tool_timeout" ||
              error.reason === "tool_failed" ||
              error.reason === "tool_output_too_large")
          )
            throw new TpmKeyError("vault_key_write_unconfirmed", error);
          throw translateTpm2Error(error);
        }
        let stored: Uint8Array | undefined;
        try {
          stored = await read(directory);
        } catch (error) {
          note(error);
          throw new TpmKeyError(
            "vault_key_write_unconfirmed",
            error instanceof Tpm2Error ? error : new Tpm2Error("tool_failed"),
          );
        }
        const same = sameBytes(stored, owned);
        stored.fill(0);
        if (!same)
          throw new TpmKeyError(
            "vault_key_write_unconfirmed",
            new Tpm2Error("tool_failed", "read-back differs"),
          );
      } finally {
        owned.fill(0);
      }
    },

    abandonedCall: () => abandoned,
  };
}
