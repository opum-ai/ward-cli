// A stored secret (spec §6.2, §8): an opaque id, the project that owns it,
// a local alias, opaque value bytes, and the times and revision of the value
// at rest.
//
// A value is opaque bytes and nothing here interprets them. At rest they are
// base64 text inside the encrypted state document, because the document is
// JSON; the codec is strict in both directions, so a damaged document fails
// its round trip rather than decoding leniently into different bytes (the
// same rule the backup container's decoder follows).
//
// An alias is metadata, never a place for a sensitive note (spec §6.2), and
// a dictionary key, never a filesystem path. The grammar is the spec's:
// a letter, then up to 63 more of letters, digits, dot, underscore or dash.

export const secretLimits = {
  maxAliasChars: 64,
  // The catalog's secret_value_too_large message states this limit as
  // 64 KiB; the two move together.
  maxValueBytes: 64 * 1024,
} as const;

// The spec's grammar, built from the limit so the two cannot drift.
const aliasPattern = new RegExp(
  `^[A-Za-z][A-Za-z0-9._-]{0,${secretLimits.maxAliasChars - 1}}$`,
);

export function isSecretAlias(value: unknown): value is string {
  return typeof value === "string" && aliasPattern.test(value);
}

export interface SecretRecord {
  readonly id: string;
  readonly projectId: string;
  readonly alias: string;
  // The canonical base64 encoding of the value bytes. Only a string that
  // decodes and re-encodes to itself is accepted when a document is parsed.
  readonly value: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly revision: number;
}

export function encodeSecretValue(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// Strict decoding, like the backup container's: Node's decoder ignores
// characters it does not recognize, so a string that is not the canonical
// encoding of its own bytes is refused rather than accepted as a different
// value. undefined means "not canonical base64"; the caller decides which
// error that is.
export function decodeSecretValue(value: string): Uint8Array | undefined {
  const buffer = Buffer.from(value, "base64");
  if (buffer.toString("base64") !== value) return undefined;
  return new Uint8Array(buffer);
}
