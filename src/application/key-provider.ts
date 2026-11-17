// The port through which Ward reaches the vault key (spec §6.4). The key is
// held in memory for one invocation at most; no implementation caches it
// across processes.
// The credential store a vault's key lives in, as a report names it (DEC-262
// a24). Linux's Secret Service is a named gap, not a backend.
export type KeyBackendId = "macos-keychain" | "tpm2";

export interface KeyProvider {
  // Resolves the 32-byte vault key, and never creates one. Rejects with
  // vault_key_missing, vault_key_unavailable, vault_key_invalid,
  // vault_key_store_unsupported or vault_record_malformed (a bad vault id).
  // The TPM2 backend adds its tpm_* codes, and a lone private blob is
  // tpm_key_incomplete, never vault_key_missing: it is a recovery condition.
  // The selecting provider adds vault_key_ambiguous.
  load(vaultId: string): Promise<Uint8Array>;
  // Stores a key when none is visible for this vault, and rejects with
  // vault_key_exists when one is, readable or not. The check is not atomic
  // with the write, so callers serialize against each other. Rejects with
  // vault_key_write_unconfirmed when the write may or may not have landed;
  // the caller resolves that with load(), never by writing again. Also
  // rejects as load() does, and with vault_key_invalid for a bad key. An
  // implementation copies the key before any await, so a caller may zero
  // its own buffer as soon as create settles, even on a timed-out write
  // path (the pending native write reads the implementation's copy).
  create(vaultId: string, key: Uint8Array): Promise<void>;
  // Present when the implementation can report it: true once any
  // credential-store call was abandoned because its bound expired. A
  // pending native call may still be running, so the process should exit
  // explicitly once the command's output is written, even on success.
  abandonedCall?(): boolean;
  // The store the last load found the key in, or where a new key would go when
  // none was found; null when no store is usable (or two held the key). A
  // provider that cannot say leaves it out and the report falls back to the
  // platform's own store.
  backend?(): KeyBackendId | null;
}

// What a backend's refusal means for a report, carried beside the observation
// so a renderer never parses a message (DEC-262 a15, a18, a19, a20). The shape
// matches the TPM2 adapter's doctor state; the application layer holds only
// this structural type and receives the classifier from the composition root.
export interface KeyRefusalState {
  readonly state: string;
  readonly code?: string;
  // tool_untrusted: the tool or directory that failed the trust walk.
  readonly path?: string;
  // tool_incompatible: the tpm2-tools version, "unknown" when unreadable.
  readonly version?: string;
  // key_unloadable only: the wording a report must use unchanged.
  readonly summary?: string;
  readonly hint?: string;
}

// Classifies a key load failure. Undefined means the error carries no backend
// detail (a Keychain refusal, or an error that is not from a TPM2 load).
export type KeyRefusalClassifier = (
  error: unknown,
) => KeyRefusalState | undefined;
