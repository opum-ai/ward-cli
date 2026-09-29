// The one header an approved operation carries its credential in (§9.2).
//
// This is a short module on purpose. Spec §9.2 says "Authentication values
// must never be interpolated into URLs or public headers", and the way that
// is kept true here is that there is exactly one function that puts a
// credential anywhere, it returns exactly one header, and the transport
// writes that header and no other field of that kind.
//
// The value is bytes from end to end. It is never decoded into a string, so
// no step of this path can put it into a template literal, a property name,
// an error message or a log line — and a byte array is something the caller
// can zero when it is finished with, which a string is not.
//
// What is refused, and why each is a real injection rather than a tidiness
// rule. An HTTP field value is one line of text. A value containing CR or LF
// ends the header early and lets whatever follows be read as more headers, or
// as a second request, at a destination the developer approved for something
// else entirely. NUL and the other control bytes are what a parser may treat
// as a terminator. So the rule is the same one the approved snapshot already
// applies to its declared headers (`hasUnwritableHeaderByte` in
// domain/profile.ts):
// no byte below 0x20 and no DEL. The two move together deliberately — a
// build that widened this one without widening that one would have a
// declaration grammar stricter than its credential path, which is the kind
// of asymmetry nobody reviews.
//
// Bytes at or above 0x80 are permitted, as obs-text in RFC 9110 §5.5. They
// are passed through unchanged rather than re-encoded, because a value Ward
// rewrites is a value the developer did not store.
import { WardError } from "../contract/errors.ts";
import type { ProfileAuth } from "./profile.ts";

export interface AuthorizationHeader {
  readonly name: string;
  readonly value: Uint8Array;
}

// The scheme's wire name. Bearer is the only scheme this build implements;
// WCLI-33 adds the others, and an auth type it does not know is refused
// when the declaration is normalized rather than here, so this function is
// never asked about one.
const bearerScheme = "Bearer ";

// Whether bytes can be written as one HTTP field value. Exported so the
// transport can assert the same rule on what it is handed, rather than
// trusting that its caller ran this.
export function isFieldValue(value: Uint8Array): boolean {
  if (value.length === 0) return false;
  for (const byte of value) if (byte < 0x20 || byte === 0x7f) return false;
  return true;
}

// The header for an approved operation, given the credential's stored bytes.
// The caller keeps ownership of `value` and is expected to zero it; the
// returned bytes are a separate buffer, because the scheme prefix is part of
// what goes on the wire and the stored value is not.
export function authorizationHeader(
  auth: ProfileAuth,
  value: Uint8Array,
): AuthorizationHeader {
  if (auth.type !== "bearer") throw new WardError("run_auth_unsupported");
  if (!isFieldValue(value)) throw new WardError("run_credential_invalid");
  const scheme = new TextEncoder().encode(bearerScheme);
  const header = new Uint8Array(scheme.length + value.length);
  header.set(scheme, 0);
  header.set(value, scheme.length);
  return { name: "Authorization", value: header };
}
