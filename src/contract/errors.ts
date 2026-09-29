import type { ErrorEnvelope, ErrorType } from "./envelope.ts";

// Every diagnostic Ward can emit is declared here with fixed text. Callers
// choose a code; they cannot pass a message. That keeps argv, upstream bodies
// and exception text out of stderr by construction rather than by redaction.
export const errorCatalog = {
  uncaught: {
    type: "uncaught",
    message:
      "Ward hit an internal error. No details are printed because they could contain sensitive data.",
  },
  unknown_command: {
    type: "usage",
    message: "Unknown command.",
    hint: "Run `ward help` for the command list.",
  },
  unknown_option: {
    type: "usage",
    message: "Unknown option.",
    hint: "Run `ward help <command>` for this command's options.",
  },
  missing_option_value: {
    type: "usage",
    message: "An option that requires a value was given none.",
  },
  unexpected_option_value: {
    type: "usage",
    message: "An option that takes no value was given one.",
  },
  repeated_option: {
    type: "usage",
    message: "An option that may appear once was repeated.",
  },
  missing_argument: {
    type: "usage",
    message: "A required argument is missing.",
  },
  missing_required_option: {
    type: "usage",
    message: "An option this command requires is missing.",
    hint: "Run `ward help <command>` for this command's options.",
  },
  unexpected_argument: {
    type: "usage",
    message: "Too many arguments.",
  },
  unknown_topic: {
    type: "not_found",
    message: "Unknown instructions topic.",
    hint: "Run `ward instructions --list` for the topic list.",
  },
  // Vault envelope (spec §6.3). None of these carries a byte of the record.
  vault_key_invalid: {
    type: "validation",
    message: "The vault key is not a 32-byte key.",
  },
  vault_format_unsupported: {
    type: "validation",
    message: "The vault record uses a format this version of Ward cannot read.",
  },
  vault_record_malformed: {
    type: "validation",
    message: "The vault record is malformed.",
  },
  vault_record_too_large: {
    type: "validation",
    message: "The vault data exceeds the size limit.",
  },
  // Key provider (spec §6.4). Nothing that reports one of these creates a key.
  vault_key_missing: {
    type: "not_found",
    message: "No vault key was found in the credential store.",
    hint: "If Ward was never set up, run `ward setup` in a trusted terminal. If a vault already exists, a missing key is a recovery condition, and Ward will not create a new key for it.",
  },
  vault_key_unavailable: {
    type: "indeterminate",
    message:
      "The credential store did not provide the vault key. It may be locked, access may have been refused, it may be unavailable, or it did not answer in time.",
  },
  vault_key_exists: {
    type: "conflict",
    message:
      "A vault key already exists in the credential store. Ward does not replace an existing key.",
  },
  vault_key_write_unconfirmed: {
    type: "indeterminate",
    message:
      "Ward could not confirm that the vault key was stored. A key may or may not now exist in the credential store.",
  },
  vault_key_store_unsupported: {
    type: "validation",
    message:
      "Ward does not yet support a credential store on this platform. The developer preview supports macOS only.",
  },
  vault_authentication_failed: {
    type: "validation",
    message:
      "The vault record failed authentication: it was modified, is corrupt, or was sealed under a different key.",
  },
  // Vault store (spec §6.1-6.3). None of these names a path or a SQL error.
  vault_not_found: {
    type: "not_found",
    message: "No vault exists yet.",
    hint: "Run `ward setup` in a trusted terminal.",
  },
  vault_exists: {
    type: "conflict",
    message: "A vault already exists. Ward does not replace an existing vault.",
  },
  vault_busy: {
    type: "conflict",
    message:
      "Another Ward process held the vault for too long. Nothing was changed.",
    hint: "Retry once the other Ward command has finished.",
  },
  vault_store_insecure: {
    type: "validation",
    message:
      "The vault location is not a private directory and file owned by this user, one of them is a link, or an inherited access control list could not be removed from it. Ward will not use it.",
    hint: "The vault directory must be mode 0700 and its database files mode 0600, both owned by you, and neither may be a symbolic link.",
  },
  vault_store_unrecognized: {
    type: "validation",
    message:
      "The vault database is not a Ward vault, uses a layout this version of Ward cannot read, or is damaged. Ward did not change it.",
  },
  vault_store_failed: {
    type: "indeterminate",
    message:
      "Ward could not read or write the vault database. If a change was being made, it may not have been saved.",
  },
  // Setup (spec §6.4). Ward never creates a key outside `ward setup`.
  setup_in_progress: {
    type: "conflict",
    message:
      "Another Ward setup appears to be running on this machine. Nothing was changed.",
    hint: "Wait for that setup to finish, or stop the process holding it, then run `ward setup` again. If the lock file was left behind by a crash and Ward still refuses, remove the setup lock file and retry.",
  },
  setup_state_invalid: {
    type: "validation",
    message: "Ward's setup bookkeeping is damaged. Ward will not overwrite it.",
    hint: "The setup record is the setup.json file in the Ward directory. Inspect it, remove it if it is damaged, then run `ward setup` again.",
  },
  // Project binding (spec §7.1). None of these names a path or a project.
  worktree_not_found: {
    type: "not_found",
    message:
      "The current directory is not inside a Git worktree. Ward binds a project to a repository root, and found none here.",
    hint: "Run `ward init` from inside a Git repository whose `.git` entry is a directory or a worktree file.",
  },
  project_manifest_malformed: {
    type: "validation",
    message:
      "The project manifest is not a valid Ward project document. Ward did not change it.",
    hint: "The manifest is .ward/project.json in the repository root. Repair or remove it, then run `ward init` again.",
  },
  project_manifest_unsupported: {
    type: "validation",
    message:
      "The project manifest uses a schema this version of Ward cannot read, so Ward did not act on it.",
    hint: "It may have been written by a newer Ward, or hold fields this build does not implement yet. Do not delete it without checking what it holds.",
  },
  project_path_unsafe: {
    type: "conflict",
    message:
      "A path Ward would use is unsafe: a symbolic link that leaves the repository, a file or directory of the wrong kind, or a vault directory that overlaps the repository. Ward did not change it.",
    hint: "Replace a link that leaves the repository with a real file or directory inside it, and keep the vault directory outside the repository. Then run the command again.",
  },
  project_file_unwritable: {
    type: "denied",
    message:
      "Ward could not read or write a project file. Nothing was changed.",
    hint: "Check that the repository directory is writable by you and not read-only.",
  },
  instructions_markers_conflict: {
    type: "conflict",
    message:
      "An instruction file's Ward block markers are incomplete, duplicated, or out of order. Ward did not change the file.",
    hint: "A file may hold one `<!-- ward:begin -->` and one `<!-- ward:end -->`, in that order. Repair or remove the extra markers, then run the command again.",
  },
  binding_conflict: {
    type: "conflict",
    message:
      "This checkout's project manifest and its vault binding name different projects, so Ward stopped.",
    hint: "The binding is the authority for a checkout. Restore the bound project's manifest, or remove .ward/project.json and run `ward init` again to have the vault's project id written back. If the binding itself is wrong, a developer must review it.",
  },
  binding_requires_terminal: {
    type: "denied",
    message:
      "Registering a checkout needs an interactive terminal, and this run has none to ask on.",
    hint: "Run `ward init` yourself in a terminal to register this checkout, or run `ward init --no-register` to prepare the project files without granting access.",
  },
  // Secrets (spec §6.2, §8, §7.1). None of these echoes an alias or names a
  // value: an alias came from argv, and a value is never text an error could
  // carry. None of them claims that nothing was changed, because a multi-file
  // truth is not always available to a message that cannot name what happened.
  project_not_registered: {
    type: "denied",
    message:
      "This checkout is not registered with Ward, so it has no access to this project's secrets.",
    hint: "Run `ward init` in a terminal to register this checkout.",
  },
  secret_action_unknown: {
    type: "usage",
    message: "Unknown secret action.",
    hint: "Use set, list, inspect or delete. Run `ward help secret` for usage.",
  },
  secret_alias_invalid: {
    type: "usage",
    message:
      "A secret alias must start with a letter, be at most 64 characters, and use only letters, digits, dot, underscore or dash.",
  },
  secret_option_unexpected: {
    type: "usage",
    message: "That option does not apply to this secret action.",
    hint: "Run `ward help secret` for usage.",
  },
  secret_requires_terminal: {
    type: "denied",
    message:
      "Entering a secret value needs an interactive terminal, and this run has none to read one on.",
    hint: "Run the command yourself in a terminal, or pipe the value with --stdin.",
  },
  secret_stdin_terminal: {
    type: "usage",
    message:
      "Standard input is an interactive terminal, where anything typed would be echoed. Pipe the value in instead.",
    hint: "Leave --stdin off to enter the value hidden.",
  },
  secret_value_rejected: {
    type: "validation",
    message: "The secret value was empty, or the terminal read was cancelled.",
  },
  secret_value_too_large: {
    type: "validation",
    message: "The secret value is larger than 64 KiB.",
  },
  secret_not_found: {
    type: "not_found",
    message: "No secret with that alias exists in this project.",
    hint: "List this project's aliases with `ward secret list`.",
  },
  secret_changed: {
    type: "conflict",
    message:
      "The secret changed while this command was running, so Ward did not write it.",
    hint: "Run the command again to see the current state and confirm a replacement.",
  },
  vault_state_malformed: {
    type: "validation",
    message:
      "The vault's contents are not a state document this Ward can read.",
  },
  // Backup and restore (spec §10). None of these names a path, a passphrase
  // or a byte of either, and none claims an old backup was erased or a
  // provider revoked anything.
  backup_requires_terminal: {
    type: "denied",
    message:
      "Creating or opening a backup needs an interactive terminal, and this run has none Ward can read a passphrase from.",
    hint: "Run the command yourself in a terminal. Ward never reads a backup passphrase from an argument, the environment or a pipe.",
  },
  backup_passphrase_rejected: {
    type: "validation",
    message:
      "The backup passphrase was empty, the confirmation did not match, or the prompt was cancelled.",
    hint: "A backup passphrase is only as strong as its entropy; length alone does not make it strong. Nothing was created or opened.",
  },
  backup_file_exists: {
    type: "conflict",
    message:
      "Something already exists at the backup path — a file or a directory — and Ward does not replace or write through it.",
    hint: "Choose another path, or move what is there, then run the command again.",
  },
  backup_file_unwritable: {
    type: "denied",
    message:
      "Ward could not create or write the backup file. There is no usable backup at that path.",
    hint: "Check that the directory exists and is writable by you, and that the path is not a link.",
  },
  backup_file_unreadable: {
    type: "denied",
    message:
      "Ward could not read the backup file. There is no usable backup at that path.",
    hint: "Check that the path names a regular file you can read, and that it is not a directory, a link, or another kind of entry.",
  },
  backup_not_found: {
    type: "not_found",
    message: "No backup file was found at that path.",
    hint: "Check the path passed to --input.",
  },
  backup_malformed: {
    type: "validation",
    message:
      "The file is not a Ward backup document of a shape this version understands. Nothing was changed.",
    hint: "Check that the path names a file `ward backup` wrote, and that the file was copied without modification.",
  },
  backup_unsupported: {
    type: "validation",
    message:
      "The backup names a format version or key-derivation parameters this version of Ward does not read, so Ward did not try to open it.",
  },
  backup_too_large: {
    type: "validation",
    message:
      "The backup is larger than this version of Ward reads. Ward did not try to open it.",
  },
  backup_open_failed: {
    type: "validation",
    message:
      "The backup could not be opened: the passphrase is wrong, or the file is damaged. Nothing was changed.",
  },
} as const satisfies Record<
  string,
  { type: ErrorType; message: string; hint?: string }
>;

export type ErrorCode = keyof typeof errorCatalog;

export class WardError extends Error {
  readonly code: ErrorCode;
  // Where in argv the fault was found. A position is safe to report; the value
  // at that position is not.
  readonly argumentPosition: number | undefined;

  constructor(code: ErrorCode, argumentPosition?: number) {
    super(errorCatalog[code].message);
    this.name = "WardError";
    this.code = code;
    this.argumentPosition = argumentPosition;
  }
}

export function errorEnvelope(error: WardError): ErrorEnvelope {
  const entry: { type: ErrorType; message: string; hint?: string } =
    errorCatalog[error.code];
  const message =
    error.argumentPosition === undefined
      ? entry.message
      : `${entry.message} (argument ${error.argumentPosition})`;
  return {
    error_type: entry.type,
    code: error.code,
    message,
    ...(entry.hint === undefined ? {} : { hint: entry.hint }),
    principal: null,
  };
}
