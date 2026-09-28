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
