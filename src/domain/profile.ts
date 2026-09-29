// The HTTPS profile: the declaration a tracked manifest carries, and the
// normalized snapshot a developer approves (spec §9.1-9.2, §8,
// docs/adr/0003).
//
// A manifest is a request, not authority. What authorizes an operation is the
// normalized snapshot the developer approved, held in the encrypted vault
// and bound to a binding, so this module owns both halves of that rule: it
// turns a declaration into the snapshot, and it compares two snapshots field
// by field. Normalization is total and pure — a declaration either produces
// a snapshot or is refused — and nothing here reads a value, resolves an
// alias, or reaches the network.
//
// Bearer is the only authentication scheme this build implements. Spec §9.2
// puts it first and calls a custom API-key header and HTTP Basic bounded
// extensions that are "not reasons to delay the first valid consumption
// flow"; they are deferred (WCLI-33), so a declaration naming one is refused
// as unsupported rather than ignored or quietly treated as bearer.
//
// Comparison is literal, and that is deliberate. A URL differing only in a
// default port, or a header name differing only in case, is a different
// approved operation and needs the developer's approval again: reapproval is
// cheap, and a normalization that silently equated two spellings would be a
// rule nobody reviewed. What is normalized is ordering (headers are sorted)
// and completeness (an omitted optional field becomes its default), so those
// two changes cannot invalidate an approval on their own.
import { WardError } from "../contract/errors.ts";
import { isSecretAlias } from "./secret.ts";

export const profileLimits = {
  maxProfileNameChars: 64,
  maxProfilesPerManifest: 64,
  maxHeadersPerProfile: 32,
  maxUrlChars: 2048,
  maxHeaderNameChars: 128,
  maxHeaderValueChars: 2048,
} as const;

// A profile is addressed by name on a command line, so the grammar is the
// same shape as a secret alias: a letter, then up to 63 more of letters,
// digits, dot, underscore or dash.
const profileNamePattern = new RegExp(
  `^[A-Za-z][A-Za-z0-9._-]{0,${profileLimits.maxProfileNameChars - 1}}$`,
);

export function isProfileName(value: unknown): value is string {
  return typeof value === "string" && profileNamePattern.test(value);
}

// The methods P0 implements. Anything else — lowercase `get`, or a method
// like TRACE — is refused as unsupported rather than normalized into one of
// these: HTTP method tokens are case-sensitive, and Ward does not guess what
// a declaration meant.
export const profileMethods = [
  "DELETE",
  "GET",
  "HEAD",
  "PATCH",
  "POST",
  "PUT",
] as const;

export type ProfileMethod = (typeof profileMethods)[number];

export type ProfileRequestBodyPolicy = "none" | "json-stdin";
export type ProfileOutputPolicy = "status";

export interface ProfileHeader {
  readonly name: string;
  readonly value: string;
}

// Bearer only, in this build. The alias names a secret in the project; the
// snapshot never holds a value, and there is no field one could be written
// into.
export interface ProfileAuth {
  readonly type: "bearer";
  readonly secret: string;
}

// The normalized operation, exactly as the developer approved it. Every
// field is present, headers are sorted by name, and nothing here is derived
// from a secret.
export interface NormalizedProfile {
  readonly adapter: "http";
  readonly method: ProfileMethod;
  readonly url: string;
  readonly auth: ProfileAuth;
  readonly headers: readonly ProfileHeader[];
  readonly requestBody: ProfileRequestBodyPolicy;
  readonly output: ProfileOutputPolicy;
}

export const profileSnapshotFields = [
  "adapter",
  "method",
  "url",
  "auth",
  "headers",
  "requestBody",
  "output",
] as const;

export type ProfileSnapshotField = (typeof profileSnapshotFields)[number];

const declarationFields = new Set<string>(profileSnapshotFields);

function invalid(): never {
  throw new WardError("profile_invalid");
}

function unsupported(): never {
  throw new WardError("profile_unsupported");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// An HTTP field name is a token (RFC 9110 §5.6.2): letters, digits and the
// listed punctuation, and nothing that would split a header line — no space,
// no colon, no control byte.
const headerNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// The auth channel belongs to `auth`. A declaration cannot carry a second
// Authorization header beside it, and Ward will not send a public header
// whose name it has been told to treat as public while the value beside it
// is a credential.
const reservedHeaderNames = new Set(["authorization", "proxy-authorization"]);

function hasControlBytes(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function normalizedMethod(value: unknown): ProfileMethod {
  if (typeof value !== "string") invalid();
  if (!(profileMethods as readonly string[]).includes(value)) unsupported();
  return value as ProfileMethod;
}

// The URL is validated and then kept as declared — not rebuilt from URL's
// own normalization — so what the developer approved is exactly the string
// Ward would use.
function normalizedUrl(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > profileLimits.maxUrlChars
  )
    invalid();
  if (hasControlBytes(value)) invalid();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    invalid();
  }
  // HTTPS is P0's only transport (spec §9.3): plain HTTP is not implemented
  // here, and nothing in this build can enable it.
  if (url.protocol !== "https:") unsupported();
  // A user-info URL carries a credential outside the header path this
  // contract exists to keep credentials inside (spec §9.3).
  if (url.username !== "" || url.password !== "") invalid();
  if (url.hostname === "") invalid();
  return value;
}

function normalizedAuth(value: unknown): ProfileAuth {
  if (!isRecord(value)) invalid();
  for (const key of Object.keys(value))
    if (key !== "type" && key !== "secret") unsupported();
  if (typeof value.type !== "string") invalid();
  if (value.type !== "bearer") unsupported();
  if (!isSecretAlias(value.secret)) invalid();
  return { type: "bearer", secret: value.secret };
}

// Non-secret headers, as declared, in a canonical order. Two names that
// differ only in case are refused rather than sorted into an order: they are
// one header by the protocol's own rule, and a declaration that spells it
// twice is ambiguous about which value Ward would send.
function normalizedHeaders(value: unknown): readonly ProfileHeader[] {
  if (value === undefined) return [];
  if (!isRecord(value)) invalid();
  const names = Object.keys(value);
  if (names.length > profileLimits.maxHeadersPerProfile) invalid();
  const seen = new Set<string>();
  const headers: ProfileHeader[] = [];
  for (const name of names) {
    if (
      name.length === 0 ||
      name.length > profileLimits.maxHeaderNameChars ||
      !headerNamePattern.test(name)
    )
      invalid();
    const folded = name.toLowerCase();
    if (seen.has(folded)) invalid();
    seen.add(folded);
    if (reservedHeaderNames.has(folded)) invalid();
    const headerValue = value[name];
    if (typeof headerValue !== "string") invalid();
    if (headerValue.length > profileLimits.maxHeaderValueChars) invalid();
    // CR, LF, NUL and every other control byte: a header value is a single
    // line of text, and Ward refuses anything that could terminate it.
    if (hasControlBytes(headerValue)) invalid();
    headers.push({ name, value: headerValue });
  }
  return headers.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );
}

function normalizedRequestBody(value: unknown): ProfileRequestBodyPolicy {
  if (value === undefined) return "none";
  if (typeof value !== "string") invalid();
  if (value !== "none" && value !== "json-stdin") unsupported();
  return value;
}

function normalizedOutput(value: unknown): ProfileOutputPolicy {
  if (value === undefined) return "status";
  if (typeof value !== "string") invalid();
  if (value !== "status") unsupported();
  return value;
}

// A declaration becomes the snapshot a developer can be asked to approve.
// Unknown fields are refused, so a declaration written for a newer Ward
// cannot be read as if the fields this build knows were the whole of it.
export function normalizeProfile(value: unknown): NormalizedProfile {
  if (!isRecord(value)) invalid();
  for (const key of Object.keys(value))
    if (!declarationFields.has(key)) unsupported();
  if (value.adapter !== "http") {
    if (typeof value.adapter !== "string") invalid();
    unsupported();
  }
  return {
    adapter: "http",
    method: normalizedMethod(value.method),
    url: normalizedUrl(value.url),
    auth: normalizedAuth(value.auth),
    headers: normalizedHeaders(value.headers),
    requestBody: normalizedRequestBody(value.requestBody),
    output: normalizedOutput(value.output),
  };
}

function sameHeaders(
  left: readonly ProfileHeader[],
  right: readonly ProfileHeader[],
): boolean {
  if (left.length !== right.length) return false;
  return left.every((header, index) => {
    const other = right[index];
    return (
      other !== undefined &&
      header.name === other.name &&
      header.value === other.value
    );
  });
}

// Which fields of the snapshot the declaration no longer matches. Field
// names only: a caller reporting this never has to decide whether a URL or a
// header value is safe to echo, because neither is here.
export function differingProfileFields(
  declared: NormalizedProfile,
  approved: NormalizedProfile,
): readonly ProfileSnapshotField[] {
  const differing: ProfileSnapshotField[] = [];
  if (declared.adapter !== approved.adapter) differing.push("adapter");
  if (declared.method !== approved.method) differing.push("method");
  if (declared.url !== approved.url) differing.push("url");
  if (
    declared.auth.type !== approved.auth.type ||
    declared.auth.secret !== approved.auth.secret
  )
    differing.push("auth");
  if (!sameHeaders(declared.headers, approved.headers))
    differing.push("headers");
  if (declared.requestBody !== approved.requestBody)
    differing.push("requestBody");
  if (declared.output !== approved.output) differing.push("output");
  return differing;
}

// The execution-time rule, in one place for the same reason the comparison
// is: "the declared profile must match the approved snapshot" is asked once
// here and answered by callers that must not differ.
export function profilesMatch(
  declared: NormalizedProfile,
  approved: NormalizedProfile,
): boolean {
  return differingProfileFields(declared, approved).length === 0;
}
