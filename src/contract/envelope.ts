// The fleet's machine contract: results on stdout, diagnostics on stderr.
//
// Unlike lore and quest, a Ward diagnostic carries no `input` field. Ward's
// arguments can be credential-shaped by mistake, so an error never echoes what
// the caller supplied (spec §8).

export const schemaVersion = 1;

export const exitCodes = {
  success: 0,
  uncaught: 1,
  usage: 2,
  notFound: 3,
  denied: 4,
  conflict: 5,
  validation: 6,
  indeterminate: 7,
} as const;

export type ExitCode = (typeof exitCodes)[keyof typeof exitCodes];

export type ErrorType =
  | "uncaught"
  | "usage"
  | "not_found"
  | "denied"
  | "conflict"
  | "validation"
  | "indeterminate";

export const exitCodeForErrorType: Record<ErrorType, ExitCode> = {
  uncaught: exitCodes.uncaught,
  usage: exitCodes.usage,
  not_found: exitCodes.notFound,
  denied: exitCodes.denied,
  conflict: exitCodes.conflict,
  validation: exitCodes.validation,
  indeterminate: exitCodes.indeterminate,
};

export type ResultKind = `${string}.${string}`;

export interface ResultEnvelope<T> {
  schemaVersion: typeof schemaVersion;
  kind: ResultKind;
  data: T;
  principal: null;
}

export interface ErrorEnvelope {
  error_type: ErrorType;
  code: string;
  message: string;
  hint?: string;
  principal: null;
}

export function success<T>(kind: ResultKind, data: T): ResultEnvelope<T> {
  return { schemaVersion, kind, data, principal: null };
}
