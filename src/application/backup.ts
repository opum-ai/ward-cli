// `ward backup` and `ward restore` (spec §10, docs/adr/0006). Policy only:
// the passphrase arrives through a port (an interactive terminal in
// production, a fixed value in tests), the container belongs to
// domain/backup.ts, and the store and key provider are ports.
//
// Two rules decide everything here. A backup is created only from an
// interactive terminal — never from an argument, the environment or a pipe —
// and it is only ciphertext that reaches the file. A restore goes only into
// an empty destination, under a fresh vault key and a fresh vault id, with
// the project records preserved and every local binding cleared, so
// restoring an old backup cannot silently revive authority that was granted,
// or revoked, since it was taken.
//
// A restore leaves approvals and sharing grants inactive too: both are
// cleared (docs/adr/0020, DEC-217 Q2). The state document below is rebuilt as
// a fixed projection of the backup — projects carried over, bindings,
// approvals and grants emptied — so any field a later layer adds is dropped
// on restore until this function is taught to carry it deliberately.
import { WardError } from "../contract/errors.ts";
import {
  backupLimits,
  deriveBackupKey,
  encodeBackup,
  newBackupKdf,
  openBackup,
  parseBackup,
  sealBackup,
} from "../domain/backup.ts";
import { generateVaultKey } from "../domain/envelope.ts";
import { isOpaqueId } from "../domain/identifiers.ts";
import { parseVaultState, serializeVaultState } from "../domain/vault-state.ts";
import type { KeyProvider } from "./key-provider.ts";
import type { VaultStore } from "./vault-store.ts";

export interface PassphraseSource {
  // True when an interactive terminal can be asked. Checked before the vault
  // key is read, so a non-interactive caller never reaches the credential
  // store to answer a question it will not be allowed to finish.
  available(): boolean;
  // The passphrase bytes, with echo suppressed by the implementation; the
  // caller owns the result and zeroes it. `confirm` reads it twice and
  // requires the readings to match (creating a backup); opening reads it
  // once. Returns undefined when no terminal is available, and throws
  // backup_passphrase_rejected for an empty reading, a mismatch, or a
  // cancelled prompt, and backup_passphrase_too_large for a reading past the
  // reader's bound — never a silently truncated one.
  read(options: { confirm: boolean }): Uint8Array | undefined;
}

export interface BackupFiles {
  // Creates a new file with owner-only mode and writes the container once.
  // Refuses an existing path, a link, and anything that is not a regular
  // file: backup_file_exists, backup_file_unwritable.
  create(path: string, bytes: Uint8Array): void;
  // The file's bytes, bounded by maxBytes: backup_not_found,
  // backup_too_large, backup_file_unwritable.
  read(path: string, maxBytes: number): Uint8Array;
}

export interface BackupResult {
  readonly path: string;
  readonly bytes: number;
  readonly vaultId: string;
  readonly revision: number;
  readonly kdf: {
    readonly name: "scrypt";
    readonly N: number;
    readonly r: number;
    readonly p: number;
  };
}

export interface RestoreResult {
  readonly vaultId: string;
  readonly revision: number;
  readonly projects: number;
  readonly bindings: "cleared";
  readonly approvals: "cleared";
  readonly grants: "cleared";
  readonly backupVaultId: string;
}

export async function runBackup(options: {
  store: VaultStore;
  keyProvider: KeyProvider;
  passphrases: PassphraseSource;
  files: BackupFiles;
  path: string;
}): Promise<BackupResult> {
  const header = options.store.header();
  if (header === undefined) throw new WardError("vault_not_found");
  // The terminal is checked before the credential store is reached, so a
  // non-interactive caller is refused without a key read.
  if (!options.passphrases.available())
    throw new WardError("backup_requires_terminal");
  const passphrase = options.passphrases.read({ confirm: true });
  if (passphrase === undefined) throw new WardError("backup_requires_terminal");

  let key: Uint8Array | undefined;
  let derived: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    key = await options.keyProvider.load(header.vaultId);
    // The plaintext's own revision is what the container records: another
    // writer can commit between the header read above and this one, and the
    // container states the origin it actually carries. The header above is
    // still what decides which key opens the vault, which no concurrent
    // writer changes.
    const snapshot = options.store.read(key);
    plaintext = snapshot.plaintext;
    // A backup is written only when restore can open it (WCLI-52). The read
    // above authenticates the envelope and refuses a vault this build cannot
    // open at all; this parse refuses one whose document decrypts and does
    // not parse, before the KDF, the seal and the file, so `ward backup`
    // never creates a file that `ward restore` would refuse. It answers what
    // every other read of the state document answers: `vault_state_malformed`.
    // `vault_format_unsupported` cannot come from here — the sealed envelope's
    // header is that code's only remaining site, and the read above already
    // refused it — so a stored approval whose snapshot version this build does
    // not implement is not a parse failure any more; it is held inert
    // (DEC-246 a2). What it costs is
    // recorded in ADR 0010: preserving the bytes of a damaged vault means
    // copying the vault file, not taking a Ward backup, because this build
    // has no recovery surface for one.
    parseVaultState(plaintext);
    const kdf = newBackupKdf();
    derived = deriveBackupKey(passphrase, kdf);
    const sealed = sealBackup(
      derived,
      { vaultId: snapshot.vaultId, revision: snapshot.revision, kdf },
      plaintext,
    );
    const bytes = encodeBackup(sealed);
    options.files.create(options.path, bytes);
    return {
      path: options.path,
      bytes: bytes.length,
      vaultId: snapshot.vaultId,
      revision: snapshot.revision,
      kdf: {
        name: kdf.name,
        N: kdf.N,
        r: kdf.r,
        p: kdf.p,
      },
    };
  } finally {
    passphrase.fill(0);
    derived?.fill(0);
    key?.fill(0);
    plaintext?.fill(0);
  }
}

export async function runRestore(options: {
  store: VaultStore;
  keyProvider: KeyProvider;
  passphrases: PassphraseSource;
  files: BackupFiles;
  path: string;
  newVaultId: () => string;
}): Promise<RestoreResult> {
  // The destination must be empty. A restore never merges into, or replaces,
  // a vault that exists — checked first, before anything is read, asked for
  // or created.
  if (options.store.header() !== undefined) throw new WardError("vault_exists");
  if (!options.passphrases.available())
    throw new WardError("backup_requires_terminal");
  const passphrase = options.passphrases.read({ confirm: false });
  if (passphrase === undefined) throw new WardError("backup_requires_terminal");

  let derived: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  try {
    // The complete backup is verified and decoded before any state is
    // committed: unsupported parameters are refused before a derivation
    // allocates for them, the tag is checked before the plaintext is used,
    // and the document is parsed before a key exists.
    const container = options.files.read(
      options.path,
      backupLimits.maxContainerBytes,
    );
    const record = parseBackup(container);
    derived = deriveBackupKey(passphrase, record.kdf);
    plaintext = openBackup(derived, record);
    const backup = parseVaultState(plaintext);

    const vaultId = options.newVaultId();
    if (!isOpaqueId(vaultId)) throw new WardError("uncaught");
    // The key is stored before the vault is created, so an interrupted
    // restore leaves at worst a key nothing points at; the other order would
    // leave a vault whose key does not exist, which is the recovery
    // condition setup already refuses to paper over (WCLI-20).
    key = generateVaultKey();
    await options.keyProvider.create(vaultId, key);
    const created = options.store.create(
      vaultId,
      key,
      serializeVaultState({
        formatVersion: backup.formatVersion,
        projects: backup.projects,
        // Bindings name directories on this machine and are never carried by
        // a backup; secret records are the projects' data and are. Clearing
        // the first must not drop the second.
        localBindings: [],
        // A profile approval is authority for one binding, so it goes with
        // the bindings rather than surviving without one. Clearing the
        // binding alone would be enough to make an approval unreachable
        // today, but re-registering this same directory would make the
        // stored approval live again — and T21 requires a restored vault's
        // approvals to be inactive until they are reviewed explicitly.
        profileApprovals: [],
        // A stale approval is not carried, though the backup can read one:
        // it records that some other build approved a profile in the vault
        // this restore is replacing, and a restored vault carries no
        // approvals of any kind. The restore output names it, with the
        // active approvals it clears, as `approvals: "cleared"`.
        staleProfileApprovals: [],
        // A grant gives one project the use of another's secret, and it is
        // cleared with the approvals it served: restoring an older backup must
        // not revive access that was granted or revoked since it was taken
        // (docs/adr/0020). The owner grants again after re-registering.
        sharingGrants: [],
        secrets: backup.secrets,
        // The audit history is carried, unlike the bindings and approvals
        // above it, because of what separates them: a restore deactivates
        // authority, and an audit record is not authority. It says a run
        // happened, and it did. Erasing it would leave the restored vault
        // asserting that runs which consumed credentials never occurred,
        // which is a claim about the past rather than a decision about what
        // this machine may do next. The records it carries name opaque
        // secret ids the restore also carries, so they keep referring to the
        // same records; they reach no project until one is registered here.
        auditRecords: backup.auditRecords,
      }),
    );
    return {
      vaultId,
      revision: created.revision,
      projects: backup.projects.length,
      bindings: "cleared",
      approvals: "cleared",
      grants: "cleared",
      backupVaultId: record.vaultId,
    };
  } finally {
    passphrase.fill(0);
    derived?.fill(0);
    plaintext?.fill(0);
    key?.fill(0);
  }
}
