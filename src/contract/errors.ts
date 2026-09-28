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
    hint: "If no other setup is running, delete the setup lock file from the Ward directory and run `ward setup` again.",
  },
  setup_state_invalid: {
    type: "validation",
    message: "Ward's setup bookkeeping is damaged. Ward will not overwrite it.",
    hint: "An interrupted setup may be involved. Inspect the Ward directory, then run `ward setup` again.",
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
