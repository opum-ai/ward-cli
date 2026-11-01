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
  // The bridge form is exactly one of --check or --update-instructions, and
  // the target is one of the two hosts Ward keeps a block for. Named the way
  // the neighbouring usage errors are (`secret_action_unknown`,
  // `profile_action_unknown`), and neither echoes the value supplied.
  agent_form_invalid: {
    type: "usage",
    message: "Name exactly one of --check or --update-instructions.",
    hint: "`ward agents --check --target claude` reports; `ward agents --update-instructions --target claude` writes.",
  },
  agent_target_unknown: {
    type: "usage",
    message: "Unknown bridge target.",
    hint: "Ward keeps a guidance block for `claude` (CLAUDE.md) and `codex` (AGENTS.md); pass one with --target.",
  },
  // DEC-48/DEC-52: the init multiselect was interrupted (Ctrl-C, or the
  // terminal stream ended) before a choice was made. Nothing has been
  // written at that point, and the run stops rather than continuing to the
  // registration question the developer just interrupted.
  init_cancelled: {
    type: "usage",
    message:
      "The instruction-file choice was cancelled, and nothing was written.",
    hint: "Run `ward init --claude --codex` for the non-interactive path, or run `ward init` again in a terminal.",
  },
  agent_option_unexpected: {
    type: "usage",
    message: "That option does not apply to the form you named.",
    hint: "--require-installed is a --check option; --force is an --update-instructions option. `ward agents --check` reports, and `ward agents --update-instructions` writes.",
  },
  // Vault envelope (spec §6.3). None of these carries a byte of the record.
  vault_key_invalid: {
    type: "validation",
    message: "The vault key is not a 32-byte key.",
  },
  // One site raises it now, down from three, and it is the only one that is
  // not this document format: the sealed envelope's version, which is bound
  // as authenticated data. The vault state document's own version became an
  // ordinary field validation answered `vault_state_malformed`, because Ward
  // has a single document format (DEC-38 A), and a stored profile approval's
  // snapshot version became an inert record rather than an error (DEC-246
  // a2), so neither reaches this code. The sentence names no site and states
  // the non-modification guarantee the way the rest of this catalog does. It
  // carries no hint and no version numbers: a vault from another build has no
  // recovery path, so there is no command to point at, and DEC-30 A fixed
  // this exact wording (WCLI-11, DEC-26 A; the no-hint half survives DEC-38,
  // which called DEC-25 vacuous rather than repealing it).
  vault_format_unsupported: {
    type: "validation",
    message:
      "This vault was written by a different version of Ward, and this build cannot read it. Ward did not change it.",
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
    // The reassurance names the vault, not the run: `ward init` writes the
    // project files before it registers the checkout, so a busy vault is
    // reached by a command that has already changed something (WCLI-27).
    // What is always true is that the vault transaction rolled back.
    message:
      "Another Ward process held the vault for too long. The vault was not changed.",
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
      "Another Ward setup appears to be running on this machine. Ward did not create a key or a vault.",
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
    // Scoped to the file, not the run: `ward init` writes the manifest and
    // then each selected bridge file, so a later target failing here follows
    // an earlier one that landed (WCLI-27).
    message:
      "Ward could not read or write a project file. Ward did not change it.",
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
  unregister_requires_terminal: {
    type: "denied",
    message:
      "Unregistering a checkout needs an interactive terminal, and this run has none to ask on.",
    hint: "Run `ward unregister` yourself in a terminal from the checkout. An agent cannot withdraw or change a checkout's registration; the developer does.",
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
  // Cross-project grants (spec §7.2, docs/adr/0020). None of these echoes an
  // alias or a project id: both come from the command line.
  secret_granted_readonly: {
    type: "denied",
    message:
      "That alias is granted to this project from another project, and it is use-only here.",
    hint: "Only the owning project can change, delete, share or revoke it. Run the command in the owner's checkout.",
  },
  grant_project_invalid: {
    type: "usage",
    message: "The target project id is not a valid project id.",
    hint: "Use the project id from the target repository's `.ward/project.json`.",
  },
  grant_target_unknown: {
    type: "not_found",
    message: "This vault has no registered project with that id.",
    hint: "Register the target checkout with `ward init` there first; a grant names a project this vault already knows.",
  },
  grant_target_is_owner: {
    type: "validation",
    message: "A project cannot be granted its own secret.",
  },
  grant_exists: {
    type: "conflict",
    message: "That secret is already granted to that project.",
    hint: "Revoke it with `ward secret revoke` before granting it again under another alias.",
  },
  grant_alias_conflict: {
    type: "conflict",
    message:
      "The target project already has a secret or a grant under that alias.",
    hint: "Choose another alias with --as.",
  },
  grant_not_found: {
    type: "not_found",
    message: "There is no active grant of that secret to that project.",
  },
  grant_requires_terminal: {
    type: "denied",
    message:
      "Granting a secret needs an interactive terminal, and this run has none to ask on.",
    hint: "Run `ward secret grant` yourself in a terminal. An agent cannot extend a secret to another project; the developer does.",
  },
  grant_declined: {
    type: "denied",
    message: "The grant was not approved, so Ward did not record it.",
  },
  grant_revoked: {
    type: "denied",
    message:
      "The grant behind that alias has been revoked, or its owner secret was deleted.",
    hint: "Ask the owning project's developer to grant it again, then approve the profile if it has expired or changed.",
  },
  // HTTPS profiles (spec §9.1-9.2, §8, docs/adr/0003). None of these echoes
  // a profile name, a URL, a header value or an alias: a declaration came
  // from a file Ward did not write, and a message is not a place to quote it.
  profile_action_unknown: {
    type: "usage",
    message: "Unknown profile action.",
    hint: "Use list, approve or revoke. Run `ward help profile` for usage.",
  },
  profile_name_invalid: {
    type: "usage",
    message:
      "A profile name must start with a letter, be at most 64 characters, and use only letters, digits, dot, underscore or dash.",
  },
  profile_not_found: {
    type: "not_found",
    message:
      "No profile with that name is declared in this project's manifest.",
    hint: "Profiles are declared under `profiles` in .ward/project.json. List this project's profiles with `ward profile list`.",
  },
  profile_not_approved: {
    type: "not_found",
    message:
      "This checkout has no approval for that profile, so there is nothing to revoke.",
    hint: "List this project's profiles and their approval state with `ward profile list`.",
  },
  profile_requires_terminal: {
    type: "denied",
    message:
      "Approving or revoking a profile needs an interactive terminal, and this run has none to ask on.",
    hint: "Run `ward profile approve` or `ward profile revoke` yourself in a terminal. An agent cannot approve an operation for itself; the developer approves it.",
  },
  profile_invalid: {
    type: "validation",
    message: "The profile declaration is not valid, so Ward did not act on it.",
    hint: "Check the profile's fields in .ward/project.json. Ward validates the whole declaration before it asks anyone to approve it.",
  },
  profile_unsupported: {
    type: "validation",
    message:
      "The profile declaration uses an operation this version of Ward does not support, so Ward did not act on it.",
    hint: "This build implements HTTPS with Bearer authentication or a secret in one named header, one of DELETE, GET, HEAD, PATCH, POST or PUT, a request body of none or json-stdin, and status-only output. An authentication scheme it does not implement yet (HTTP Basic) is refused rather than approximated.",
  },
  profile_changed: {
    type: "conflict",
    message:
      "The profile changed while this command was running, so Ward did not record the approval.",
    hint: "Run the command again to review the profile as it is now.",
  },
  // Running an approved profile (spec §9.3-§9.4). Every message here names a
  // code or a next step and never a destination, a header, an upstream
  // message or a status text: a run's diagnostics travel through an agent's
  // transcript, and spec §9.4 keeps a run's output to Ward-owned values.
  // `ward run --actor-label` and `--task-label` (WCLI-11, DEC-33 option A). A
  // label is bounded by the alias grammar, and this is the refusal for a value
  // outside it — one code for both flags, named for its subject the way
  // secret_alias_invalid and profile_name_invalid are. It is a usage fault
  // rather than a validation one because the value is the caller's own
  // argument, and it is answered before the vault is opened.
  run_label_invalid: {
    type: "usage",
    message:
      "A run label must start with a letter, be at most 64 characters, and use only letters, digits, dot, underscore or dash.",
  },
  profile_approval_expired: {
    type: "denied",
    message:
      "This checkout's approval of the profile has expired, so Ward did not run it.",
    hint: "A developer approves again in a terminal with `ward profile approve <name>`. An approval lasts 24 hours unless approved with `--ttl`.",
  },
  profile_ttl_invalid: {
    type: "usage",
    message:
      "The approval lifetime must be a whole number and one unit (m, h or d), from 1m to 30d.",
    hint: "For example `--ttl 8h`. Without `--ttl` an approval lasts 24 hours.",
  },
  profile_option_unexpected: {
    type: "usage",
    message: "That option belongs to another `ward profile` action.",
    hint: "Run `ward help profile` for usage.",
  },
  profile_approval_stale: {
    type: "denied",
    message:
      "The declared profile no longer matches what this checkout approved, so Ward did not run it.",
    hint: "A change to the destination, method, authentication reference, headers, body policy or output policy needs approval again. `ward check` names the fields that differ; a developer approves in a terminal with `ward profile approve <name>`.",
  },
  run_credential_invalid: {
    type: "validation",
    message:
      "The stored credential cannot be written into an HTTP header, so Ward did not send it.",
    hint: "A credential Ward sends belongs on one line of text: it must be non-empty and carry no control bytes. Store the value the provider issued, for a Bearer or named-header credential, with `ward secret set <alias>`.",
  },
  run_auth_unsupported: {
    type: "validation",
    message:
      "The approved operation uses an authentication scheme this version of Ward does not implement, so Ward did not run it.",
  },
  run_body_unsupported: {
    type: "validation",
    message:
      "This profile is approved to accept a request body from stdin, which this version of Ward does not implement, so Ward did not run it.",
    hint: "This build sends no request body. It refuses an approved body policy it cannot honour rather than sending the request without the body the endpoint expects.",
  },
  run_destination_refused: {
    type: "denied",
    message:
      "The approved destination is not a public address, so Ward did not connect to it.",
    hint: "Ward connects only to public destinations: loopback, private, link-local, multicast and metadata addresses are refused, in their IPv4 and IPv6 spellings alike. A local or private service needs an adapter Ward does not have yet.",
  },
  run_destination_unresolved: {
    type: "validation",
    message:
      "The approved destination could not be resolved, so Ward sent nothing.",
    hint: "Check the destination and this machine's network and name resolution.",
  },
  run_connection_failed: {
    type: "validation",
    message:
      "Ward could not connect to the approved destination, so it sent nothing.",
  },
  run_tls_failed: {
    type: "validation",
    message:
      "The approved destination's certificate was not valid for it, so Ward sent nothing.",
  },
  run_request_invalid: {
    type: "validation",
    message:
      "The approved operation could not be turned into a request Ward would send, so it sent nothing.",
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
  backup_passphrase_too_large: {
    type: "validation",
    message: "The backup passphrase is longer than 1024 bytes.",
    hint: "Nothing was created or opened. A shorter passphrase of equal entropy is just as strong; length alone does not make it strong.",
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

// The only header names an error may print (WCLI-98, opum-doc ruling
// 2026-10-30): Ward's own canonical spelling of a refused name, never the
// profile's bytes. `Proxy-*` stands for the whole family. The profile
// normalizer maps a refused declaration onto an entry of this list by lookup,
// so what is printed is always a member of it, whatever was declared.
export const refusedHeaderCanonicalNames = Object.freeze([
  "Authorization",
  "Cookie",
  "Host",
  "Content-Length",
  "Transfer-Encoding",
  "Connection",
  "Keep-Alive",
  "TE",
  "Trailer",
  "Upgrade",
  "Expect",
  "Proxy-Connection",
  "Proxy-*",
  "X-HTTP-Method-Override",
  "X-HTTP-Method",
  "X-Method-Override",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Forwarded-Host",
  "X-Forwarded-Proto",
  "X-Forwarded-For",
  "Forwarded",
  "X-Forwarded-Port",
  "X-Forwarded-Prefix",
  "X-Original-Host",
  "X-Host",
] as const);

export type RefusedHeaderName = (typeof refusedHeaderCanonicalNames)[number];

export class WardError extends Error {
  readonly code: ErrorCode;
  // Where in argv the fault was found. A position is safe to report; the value
  // at that position is not.
  readonly argumentPosition: number | undefined;
  // Which refused header a declaration used, as Ward's canonical spelling. The
  // constructor keeps it only when it is a member of the list above, so the
  // field cannot carry anything the declaration supplied.
  readonly refusedHeader: RefusedHeaderName | undefined;

  constructor(
    code: ErrorCode,
    argumentPosition?: number,
    refusedHeader?: RefusedHeaderName,
  ) {
    super(errorCatalog[code].message);
    this.name = "WardError";
    this.code = code;
    this.argumentPosition = argumentPosition;
    this.refusedHeader = refusedHeaderCanonicalNames.find(
      (known) => known === refusedHeader,
    );
  }
}

export function errorEnvelope(error: WardError): ErrorEnvelope {
  const entry: { type: ErrorType; message: string; hint?: string } =
    errorCatalog[error.code];
  const positioned =
    error.argumentPosition === undefined
      ? entry.message
      : `${entry.message} (argument ${error.argumentPosition})`;
  const message =
    error.refusedHeader === undefined
      ? positioned
      : `${positioned} (refused header: ${error.refusedHeader})`;
  return {
    error_type: entry.type,
    code: error.code,
    message,
    ...(entry.hint === undefined ? {} : { hint: entry.hint }),
    principal: null,
  };
}
