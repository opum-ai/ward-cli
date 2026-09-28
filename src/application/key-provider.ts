// The port through which Ward reaches the vault key (spec §6.4). The key is
// held in memory for one invocation at most; no implementation caches it
// across processes.
export interface KeyProvider {
  // Resolves the 32-byte vault key. Rejects with vault_key_missing,
  // vault_key_unavailable or vault_key_invalid, and never creates a key.
  load(vaultId: string): Promise<Uint8Array>;
  // Stores a key only when none exists for this vault. Rejects with
  // vault_key_exists rather than replacing one.
  create(vaultId: string, key: Uint8Array): Promise<void>;
}
