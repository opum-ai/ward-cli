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
// What an approval pins is the normalized operation — spec §9.2: "the
// developer approves the normalized operation: adapter, exact method and
// URL, ..."; §9.3: "only connect to the approved destination" — and not the
// bytes the manifest happened to spell it with. So normalization also
// canonicalizes the URL, and what is stored, shown and later executed is the
// canonical form. A declaration the canonical form would have to *rewrite*
// rather than merely complete is refused instead (see `normalizedUrl`): a
// spelling two parsers can read two ways must not become an approval whose
// meaning depends on which parser reads it back.
//
// Comparison is then literal over normalized values, and that is deliberate.
// A different path, a different method, or a header name differing only in
// case is a different approved operation and needs the developer's approval
// again: reapproval is cheap, and a normalization that silently equated two
// spellings would be a rule nobody reviewed. What is normalized is ordering
// (headers are sorted), completeness (an omitted optional field becomes its
// default), and canonical spelling of a value that denotes one operation
// (URL, whose host and scheme case, default port and empty path vary without
// changing where a request goes) — so none of those can invalidate an
// approval on its own.
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

// The version of the approved-snapshot schema, written beside every stored
// approval (spec §6.2: "store versioned collections for ... approved profile
// snapshots"). The vault's own formatVersion says which build wrote the
// document; this says which *normalizer* produced the snapshot inside it, and
// the two are not the same question: a build that widened or tightened what
// `normalizeProfile` accepts would otherwise re-read every stored approval
// through its new rules and silently reinterpret what the developer
// approved. A record naming a version this build does not implement is
// refused as a document from another build, never re-normalized into one.
//
// It is deliberately per record rather than one version for the whole
// collection: records written under different versions can sit side by side
// — an approval made after a schema change does not have to wait for every
// older one to be rewritten — and a collection-level version would have to
// claim a uniformity it could not guarantee.
//
// Bump this in the same change that alters what `normalizeProfile` accepts.
// A build whose rules differ re-normalizes a stored snapshot it did not
// write, and if the record's version still matches it will read the result
// as an approval the developer gave — so the version must not match.
//
// The golden table in test/profile.test.ts is a prompt, not a proof: it
// fails whenever a verdict it records changes, and it cannot see a change
// that touches none of its rows — measured, by a mutation that newly
// accepted a percent-encoded host with every case still green. So the table
// carries one row per class the URL rules decide, and a change to those
// rules that the table does not catch is exactly what this paragraph is for.
//
// This stays 1 while the accepted set is still being settled, and the reason
// is a fact about the stored data rather than about the rules: no compiled
// snapshot predates this build, because WCLI-9 is the first build to write
// one and it is unreleased. The version exists for the records that will
// outlive the rules; there are none yet to protect.
//
// **Considered again at WCLI-10, which narrowed the set** — a declared header
// value may no longer carry a code point the wire encoding cannot represent —
// and it still does not bump, on a reason the paragraph above does not supply
// on its own. The rule at the top exists to stop a build reading a
// differently-interpreted record as an approval the developer gave; this
// change can only ever *refuse* more, never accept more, so a snapshot it
// newly rejects fails closed at parse and there is no interpretation to get
// wrong in either direction. The cost accepted here is the error a developer
// sees on such a vault: malformed rather than unsupported-by-another-build,
// which is a worse description of a correctly-refused record. The first bump
// belongs to the first release, which is when snapshots begin outliving the
// rules that wrote them (WCLI-10 review, F7).
//
// The operator decided that shape on 2026-09-29 (DEC-50, ADR 0018): the
// constant stays 1 while Ward is unreleased, and the commit that cuts the
// first release bumps it and updates this comment, so the released build
// refuses every dev-era snapshot - it does not migrate one. This comment is
// no longer the only place the obligation lives: it is a step in
// docs/runbooks/cutting-a-ward-release.md and on WCLI-15's record, so the
// person cutting the release meets it without reading this file.
export const profileSnapshotVersion = 1;

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

// Whether a declared header value cannot be written as the single line of
// text it was approved as.
//
// Two things can go wrong, and they are the same thing seen from the two ends
// of the wire. A code point below 0x20, or DEL, ends the line: CR and LF
// terminate the header, and whatever follows is read as further headers or as
// a second request carrying this operation's credential (spec §9.2). A code
// point above 0xff has no byte to be written as — the transport encodes each
// line as latin1, which maps every code point from 0x100 upward to its low
// byte, so U+010A reaches the socket as a bare LF while a scan of the string's
// code points sees only a letter (WCLI-10 review, F1). Refusing both is what
// makes the bytes approved the bytes sent: inside this range that encoding is
// lossless, so nothing is rewritten between the approval prompt and the
// socket. A value that mangles rather than injects — U+0141, written as `A` —
// is refused for the same reason, which is that the developer approved
// something else.
function hasUnwritableHeaderByte(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || code > 0xff) return true;
  }
  return false;
}

function normalizedMethod(value: unknown): ProfileMethod {
  if (typeof value !== "string") invalid();
  if (!(profileMethods as readonly string[]).includes(value)) unsupported();
  return value as ProfileMethod;
}

// The characters RFC 3986 allows unencoded in a URI: unreserved, the
// gen-delims and sub-delims, and `%` for a percent escape (checked for
// well-formedness separately). Ward refuses a declaration carrying anything
// else rather than letting its parser encode it, because a character this
// parser rewrites is one another parser may read as structure.
const urlCharactersPattern = /^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$/;

// Every percent sign must introduce two hex digits, so no parser has to
// decide what a malformed escape means.
const percentEscapePattern = /%[0-9A-Fa-f]{2}/g;

// The authority, introduced by exactly `https://`. A special-scheme URL in
// any other spelling — `https:/host/x`, `https:host/x` — is given an
// authority by this parser and read as a path by parsers that require the
// two slashes, so the two would name different destinations. This build has
// no HTTP client yet (WCLI-10 adds one), so what the divergence costs is
// determined there; what it means here is that the declaration does not say
// which destination it names, and Ward refuses what it cannot state.
const httpsAuthorityPattern = /^https:\/\//i;

// The URL, as the canonical form of the operation Ward would perform.
//
// Two spellings this refuses are the reason the rule is stated over
// characters and structure rather than over remembered bad inputs. A
// backslash in the authority — `https://api.example.invalid\@evil.example/`
// — is a path separator to this parser, which judges the host
// `api.example.invalid`, and part of the user-info to others, which dial
// `evil.example`: the host the developer was shown is not the host another
// client would reach. And the single-slash form above is invented into an
// authority here and read as a path elsewhere. A backslash is outside the
// character set below and the single-slash form fails the authority pattern,
// so both are refused before anything is stored.
//
// What passes is stored as `URL`'s canonical href — host and scheme case
// folded, an empty path made `/`, a default port dropped — which is exactly
// what the approval prompt displays and what a later build executes, so the
// string the developer approved and the string Ward would send are one
// string rather than two the validator hoped were equal.
//
// Everything the developer wrote must then survive parsing, and only the
// documented folds may differ — case, and a default port. The authority is
// checked against the one the parser read, and the path, query and fragment
// must come through unchanged. Both halves exist because the parser rewrites
// more than it looks like it does, and each rewrite makes the record say
// something the declaration does not: `0x7f000001` and `2130706433` are read
// as `127.0.0.1`, an empty `@` is dropped, `:080` becomes `:80`, and
// `/%2e%2e/x` and `/a/../b` both become `/x` and `/b`. A declaration whose
// bytes name a destination only this parser agrees on is refused, and what
// is stored is a URL the developer could have written.
function normalizedUrl(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > profileLimits.maxUrlChars
  )
    invalid();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    invalid();
  }
  // HTTPS is P0's only transport (spec §9.3): plain HTTP is not implemented
  // here, and nothing in this build can enable it.
  if (url.protocol !== "https:") unsupported();
  if (!urlCharactersPattern.test(value)) invalid();
  if (value.replace(percentEscapePattern, "").includes("%")) invalid();
  if (!httpsAuthorityPattern.test(value)) invalid();
  // What the developer wrote, split where the authority ends: `https://` is
  // 8 characters, and an authority cannot contain `/`, `?` or `#`, so the
  // first of those three after the scheme is the boundary. A trailing `?` or
  // `#` with nothing after it is part of the suffix, which is why the suffix
  // below is taken from the parser's own href rather than rebuilt from
  // `pathname`, `search` and `hash`: those drop an empty query and fragment.
  const afterScheme = value.slice("https://".length);
  const suffixAt = afterScheme.search(/[/?#]/);
  const declaredAuthority =
    suffixAt === -1 ? afterScheme : afterScheme.slice(0, suffixAt);
  const declaredSuffix = suffixAt === -1 ? "" : afterScheme.slice(suffixAt);
  if (url.hostname === "") invalid();
  // The authority the parser read, against the authority the developer
  // wrote, case-folded, with a declared `:443` the one fold allowed. The
  // comparison is also what refuses user-info — `user:pass@host` and the
  // empty `@host` alike — which spec §9.3 keeps out of the operation
  // entirely, because a credential written into a URL sits outside the
  // header path this contract exists to keep credentials inside.
  const declaredOrigin = declaredAuthority.replace(/:443$/i, "").toLowerCase();
  if (declaredOrigin !== url.host.toLowerCase()) invalid();
  const parsedSuffix = url.href.slice(`https://${url.host}`.length);
  if (parsedSuffix !== declaredSuffix && parsedSuffix !== `/${declaredSuffix}`)
    invalid();
  return url.href;
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
    // line of text, and Ward refuses anything that could terminate it. Also
    // refused: a code point the wire encoding cannot carry, which is the same
    // defect arriving by truncation rather than by spelling.
    if (hasUnwritableHeaderByte(headerValue)) invalid();
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
