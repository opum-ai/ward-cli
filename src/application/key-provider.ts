// The port through which Ward reaches the vault key (spec §6.4). The key is
// held in memory for one invocation at most; no implementation caches it
// across processes.
export interface KeyProvider {
  // Resolves the 32-byte vault key, and never creates one. Rejects with
  // vault_key_missing, vault_key_unavailable, vault_key_invalid,
  // vault_key_store_unsupported or vault_record_malformed (a bad vault id).
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
}
