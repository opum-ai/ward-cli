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
