// The port through which Ward reaches the encrypted vault (spec §6.1-6.3).
// A store holds one sealed snapshot per vault and never sees plaintext
// outside a call; what the snapshot's bytes mean belongs to the layers above.
export interface VaultHeader {
  vaultId: string;
  revision: number;
  // The sealed record's own format version. Readable without the key, so a
  // report can name the schema it would have to read (`ward status`,
  // `ward doctor`) even when the key is missing.
  formatVersion: number;
}

export interface VaultSnapshot extends VaultHeader {
  plaintext: Uint8Array;
}

// Synchronous by design. The write transaction is open while a change runs,
// so a change cannot await a network request inside it (spec §6.3).
export type VaultChange = (plaintext: Uint8Array) => Uint8Array;

export interface VaultStore {
  // The stored header, read without the key, or undefined when no vault has
  // been created. Never creates a directory or file.
  header(): VaultHeader | undefined;
  // Seals the plaintext as revision 1 of a new vault. Rejects with
  // vault_exists when a vault is present, and never replaces it.
  create(vaultId: string, key: Uint8Array, plaintext: Uint8Array): VaultHeader;
  // Authenticates the latest snapshot and returns its plaintext.
  read(key: Uint8Array): VaultSnapshot;
  // Reads and authenticates the latest snapshot, applies the change, and
  // seals the result as the next revision, all in one immediate transaction.
  // Anything the change throws rolls the transaction back and is rethrown.
  // The buffer passed to the change is zeroed, best effort, once the new
  // revision is sealed, so a change copies anything it must keep.
  mutate(key: Uint8Array, change: VaultChange): VaultHeader;
}
