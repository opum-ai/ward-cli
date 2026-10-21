// The decrypted vault's own document (spec §6.2): versioned collections for
// projects, local bindings, secret records and approved profile snapshots.
// It reaches storage only through VaultStore.mutate, which seals each change
// as the next revision.
//
// The document is Ward's own encrypted state, so this module is defense in
// depth rather than a trust boundary: a snapshot that opens has already
// authenticated. It still validates every field, because the parse result
// feeds authority decisions — a binding decides whether a checkout may use a
// project's secrets — and a malformed value must fail before it is used.
//
// Collections are arrays of records rather than objects keyed by id or path,
// so no field can reach an object's prototype, and a record's identity is
// stated rather than implied by where it sits.
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "./identifiers.ts";
import {
  isProfileName,
  type NormalizedProfile,
  normalizeProfile,
  profileSnapshotVersion,
} from "./profile.ts";
import {
  decodeSecretValue,
  isSecretAlias,
  type SecretRecord,
  secretLimits,
} from "./secret.ts";

// The document's format, and its number (DEC-38, option A).
//
// Ward has one format and this is it. Before the first release the on-disk
// format is not a compatibility contract: every vault in existence was
// written by a build of this same line of work, so a document from a
// *different* build is not a state this reader needs to distinguish. DEC-19 B
// once bumped this to 2 for the audit field set §9.4 requires; DEC-38 returns
// it to 1, because that bump answered a compatibility question that had no
// one on the other side of it.
//
// What refuses a document whose shape is not this build's is the reader
// below, not this number. Every record's key set is compared exactly, so a
// record written to a different vocabulary is refused as
// `vault_state_malformed` — the answer every other invalid field in this
// document already gets. The version is validated the same way: a missing,
// non-numeric or unrecognized value is malformed, and this module never
// raises `vault_format_unsupported`. That code survives at the two sites
// which are not this format — the sealed envelope's header, which is bound as
// authenticated data, and a stored profile approval's snapshot version, which
// guards an authority question rather than a compatibility one.
export const vaultStateFormatVersion = 1;

export interface ProjectRecord {
  readonly id: string;
  readonly createdAt: string;
}

// A binding is authority: it says this vault, on this machine, approved this
// checkout for this project (spec §7.1).
//
// `root` is the canonical worktree root, and `device`/`inode` are that
// directory's own identity from a bigint stat, kept as decimal strings so no
// identifier loses precision on the way through JSON. Path alone cannot tell
// a fresh clone from the checkout it replaced: a directory removed and
// re-created at the same path is a new directory, and §7.1 requires a new
// clone to be handled explicitly rather than silently added to an existing
// binding.
export interface BindingRecord {
  readonly projectId: string;
  readonly root: string;
  readonly device: string;
  readonly inode: string;
  readonly registeredAt: string;
}

// The developer's approval of one HTTPS profile, for one binding (spec
// §9.2, docs/adr/0003). It carries the binding's whole identity — project,
// root, device and inode — because an approval is authority for a checkout
// and not for a repository: a clone at the same path, or the same project
// opened somewhere else, is a different binding and needs its own approval.
//
// The snapshot is the normalized operation and never a value. It is
// re-normalized when a document is parsed, so a stored snapshot that this
// build's normalizer would not produce is a damaged document rather than an
// approval with unknown meaning — and `snapshotVersion` names the schema the
// stored snapshot was written under, so a record from a build whose
// normalizer differs is refused rather than re-read through these rules
// (spec §6.2).
export interface ProfileApprovalRecord {
  readonly profile: string;
  readonly projectId: string;
  readonly root: string;
  readonly device: string;
  readonly inode: string;
  readonly approvedAt: string;
  readonly snapshotVersion: number;
  readonly snapshot: NormalizedProfile;
}

// A use-only grant of one owner secret to one alias in one other project
// (spec §7.2, DEC-217 Q1). It names the owner's secret by id and not by alias,
// so deleting the secret and creating another under the same alias does not
// revive it, while an owner update — which keeps the id — shows on the next
// use. `revokedAt` is a timestamp or null and never absent: this document's
// reader compares key sets exactly, and JSON drops a key whose value is
// undefined. A revoked record stays as a tombstone, so a refusal can say
// "revoked" rather than "missing", and a re-grant is a new record.
export interface SharingGrantRecord {
  readonly id: string;
  readonly ownerProjectId: string;
  readonly ownerSecretId: string;
  readonly targetProjectId: string;
  readonly targetAlias: string;
  readonly createdAt: string;
  readonly revokedAt: string | null;
}

// One operational event from a `ward run` (spec §9.4). Two are written per
// run and they are two records rather than one with two timestamps, because
// the point of the pair is that the first exists *before* a credential is
// delivered: if admission cannot be persisted, the run does not happen, and a
// single record written afterwards could not express that.
//
// What is here is the whole of what a record may hold, and the reason is the
// shape rather than a redaction step: there is no field a credential, a
// request body, a response body or an upstream message could be written
// into, so gate T14's "absent from ... audit" is a property of this
// interface rather than a rule the writer has to follow. `secretId` is the
// opaque identifier the vault assigns a stored secret, never an alias and
// never a value.
//
// `outcome` is null on an admission record, which is written before there is
// an outcome to record, and carries a safe code on the completion record.
// It is nullable rather than optional so that a serialized record always
// carries the key: this document's reader compares key sets exactly, and
// JSON drops a key whose value is undefined.
export type AuditPhase = "admission" | "completion";

// The outcomes a completed run can record. These are the run's own public
// outcome values as well as the audit record's, deliberately: one vocabulary
// means `ward run`'s result and the audit trail that describes it cannot
// drift into naming the same event two ways. The cases that are refused
// rather than performed — no approval, a stale declaration, a destination
// Ward will not connect to — are errors and are not recorded here, because
// nothing was admitted.
export const auditOutcomes = ["succeeded", "failed", "indeterminate"] as const;

export type AuditOutcome = (typeof auditOutcomes)[number];

// What the OS said about who ran this event and on what machine, recorded as
// what Ward observed rather than as anything a caller claimed (spec §9.4's
// "observed OS identity"). Ward reads this itself, from the platform, and no
// argument reaches it: a run's `--actor-label` is a different field below,
// because an assertion and an observation must not be able to occupy the same
// place in a record a reader will trust.
//
// It is nullable, and only one thing makes it null: the OS gave no answer this
// build can record. `os.userInfo()` throws for a uid with no passwd entry,
// which is ordinary in a container, and Ward will not refuse to run in order
// to insist on a field a machine may not have. A null here is the record
// saying Ward observed nothing, and `ward audit` prints it that way rather
// than leaving a blank a reader would take for an identity.
export interface ObservedMachine {
  readonly user: string;
  readonly host: string;
}

export interface AuditRecord {
  readonly id: string;
  readonly runId: string;
  readonly projectId: string;
  readonly profile: string;
  readonly secretId: string;
  readonly phase: AuditPhase;
  readonly outcome: AuditOutcome | null;
  readonly at: string;
  readonly machine: ObservedMachine | null;
  // What the caller said about who it was and what it was doing, carried
  // through `ward run`'s `--actor-label` and `--task-label`, and recorded as
  // self-asserted fact (spec §4.2, §12). These are correlation metadata and
  // never authorization: nothing in Ward reads them back to decide anything,
  // and `null` means the caller asserted nothing rather than that Ward failed
  // to observe it — the machine field is the observed one.
  readonly actorLabel: string | null;
  readonly taskLabel: string | null;
}

// How many events this vault keeps, across every project. Spec §9.4 permits a
// bounded history for the local MVP and requires the limit to be exposed
// rather than hidden: `ward audit` states this bound, and this constant is
// the one source of that number. The oldest records are dropped first,
// across projects rather than per project.
//
// The bound is deliberately vault-wide rather than per project. What bounds
// the audit at all is the size of the state document, and a per-project
// number cannot do that: a vault-wide cap would have to exist beside it for
// any number of projects. A per-project limit on its own would also be a
// second eviction rule to enforce at every write, where the collection is
// one array and the risk is its size. The cost is real and is stated rather
// than hidden: a project's retained history can be shorter than this limit,
// and another project's activity can shorten it — which is why `ward audit`
// reports the bound and the project's own retained count together, with the
// eviction rule said in words.
export const auditHistoryLimit = 500;

export interface VaultState {
  readonly formatVersion: number;
  readonly projects: readonly ProjectRecord[];
  readonly localBindings: readonly BindingRecord[];
  readonly secrets: readonly SecretRecord[];
  readonly profileApprovals: readonly ProfileApprovalRecord[];
  readonly sharingGrants: readonly SharingGrantRecord[];
  readonly auditRecords: readonly AuditRecord[];
}

// The directory a binding is being matched against.
export interface CheckoutIdentity {
  readonly root: string;
  readonly device: string;
  readonly inode: string;
}

export function emptyVaultState(): VaultState {
  return {
    formatVersion: vaultStateFormatVersion,
    projects: [],
    localBindings: [],
    secrets: [],
    profileApprovals: [],
    sharingGrants: [],
    auditRecords: [],
  };
}

function malformed(): never {
  throw new WardError("vault_state_malformed");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// `new Date(...).toISOString()` output. A stored timestamp is only ever read
// back or shown, so a fixed grammar is enough to catch a damaged document.
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && timestampPattern.test(value);
}

// A canonical absolute path as node:path.posix would produce it after
// resolve() and realpath(): one leading slash, no trailing slash, no empty,
// "." or ".." segment, no NUL. The root of a filesystem is its own case.
// This is a grammar check; whether the path exists, and whether it is
// contained where it should be, is checked where the path is used.
export function isCanonicalAbsolutePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  if (value.includes("\0") || !value.startsWith("/")) return false;
  if (value === "/") return true;
  if (value.endsWith("/")) return false;
  return value
    .split("/")
    .slice(1)
    .every(
      (segment) => segment.length > 0 && segment !== "." && segment !== "..",
    );
}

// Device and inode numbers from `stat(path, { bigint: true })`. Bounded in
// length so a damaged document cannot carry an unbounded digit string.
const counterPattern = /^(0|[1-9]\d{0,19})$/;

function isCounter(value: unknown): value is string {
  return typeof value === "string" && counterPattern.test(value);
}

function ownProject(value: unknown): ProjectRecord {
  if (!isRecord(value)) malformed();
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== "createdAt" || keys[1] !== "id")
    malformed();
  if (!isOpaqueId(value.id) || !isTimestamp(value.createdAt)) malformed();
  return { id: value.id, createdAt: value.createdAt };
}

function ownBinding(value: unknown): BindingRecord {
  if (!isRecord(value)) malformed();
  const expected = ["device", "inode", "projectId", "registeredAt", "root"];
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length) malformed();
  for (const [index, key] of expected.entries())
    if (keys[index] !== key) malformed();
  if (!isOpaqueId(value.projectId)) malformed();
  if (!isCanonicalAbsolutePath(value.root)) malformed();
  if (!isCounter(value.device) || !isCounter(value.inode)) malformed();
  if (!isTimestamp(value.registeredAt)) malformed();
  return {
    projectId: value.projectId,
    root: value.root,
    device: value.device,
    inode: value.inode,
    registeredAt: value.registeredAt,
  };
}

function ownCollection<T>(
  value: unknown,
  own: (entry: unknown) => T,
): readonly T[] {
  if (!Array.isArray(value)) malformed();
  return value.map(own);
}

// A stored secret record. The value is validated by decoding it: a string
// that is not canonical base64, or whose bytes are empty or over the limit,
// is a damaged document rather than a secret. Nothing here decodes a value
// for use; the parse result only ever reports that the record is intact.
function ownSecret(value: unknown): SecretRecord {
  if (!isRecord(value)) malformed();
  const expected = [
    "alias",
    "createdAt",
    "id",
    "projectId",
    "revision",
    "updatedAt",
    "value",
  ];
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length) malformed();
  for (const [index, key] of expected.entries())
    if (keys[index] !== key) malformed();
  if (!isOpaqueId(value.id) || !isOpaqueId(value.projectId)) malformed();
  if (!isSecretAlias(value.alias)) malformed();
  if (typeof value.value !== "string") malformed();
  const bytes = decodeSecretValue(value.value);
  if (
    bytes === undefined ||
    bytes.length === 0 ||
    bytes.length > secretLimits.maxValueBytes
  )
    malformed();
  if (!isTimestamp(value.createdAt) || !isTimestamp(value.updatedAt))
    malformed();
  if (
    typeof value.revision !== "number" ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 1
  )
    malformed();
  return {
    id: value.id,
    projectId: value.projectId,
    alias: value.alias,
    value: value.value,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    revision: value.revision,
  };
}

// A stored approval. The snapshot is validated by running the normalizer
// over it: a shape this build's normalizer would refuse is a damaged
// document, and a valid one is rebuilt in canonical form, so a caller
// comparing snapshots compares the same normalization on both sides.
function ownProfileApproval(value: unknown): ProfileApprovalRecord {
  if (!isRecord(value)) malformed();
  const expected = [
    "approvedAt",
    "device",
    "inode",
    "profile",
    "projectId",
    "root",
    "snapshot",
    "snapshotVersion",
  ];
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length) malformed();
  for (const [index, key] of expected.entries())
    if (keys[index] !== key) malformed();
  if (!isProfileName(value.profile)) malformed();
  if (!isOpaqueId(value.projectId)) malformed();
  if (!isCanonicalAbsolutePath(value.root)) malformed();
  if (!isCounter(value.device) || !isCounter(value.inode)) malformed();
  if (!isTimestamp(value.approvedAt)) malformed();
  // A version that is missing or is not a number is a damaged record; a
  // version this build does not implement is a record from another build.
  // The second is answered rather than re-normalized, because running this
  // build's rules over a snapshot written under different ones is how an
  // approval comes to mean something the developer never approved.
  if (typeof value.snapshotVersion !== "number") malformed();
  if (value.snapshotVersion !== profileSnapshotVersion)
    throw new WardError("vault_format_unsupported");
  let snapshot: NormalizedProfile;
  try {
    snapshot = normalizeProfile(value.snapshot);
  } catch {
    malformed();
  }
  return {
    profile: value.profile,
    projectId: value.projectId,
    root: value.root,
    device: value.device,
    inode: value.inode,
    approvedAt: value.approvedAt,
    snapshotVersion: value.snapshotVersion,
    snapshot,
  };
}

function ownSharingGrant(value: unknown): SharingGrantRecord {
  if (!isRecord(value)) malformed();
  const expected = [
    "createdAt",
    "id",
    "ownerProjectId",
    "ownerSecretId",
    "revokedAt",
    "targetAlias",
    "targetProjectId",
  ];
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length) malformed();
  for (const [index, key] of expected.entries())
    if (keys[index] !== key) malformed();
  if (!isOpaqueId(value.id)) malformed();
  if (!isOpaqueId(value.ownerProjectId)) malformed();
  if (!isOpaqueId(value.ownerSecretId)) malformed();
  if (!isOpaqueId(value.targetProjectId)) malformed();
  // A grant to the owner's own project is not a grant: it would be a second
  // name for a record the project already owns.
  if (value.ownerProjectId === value.targetProjectId) malformed();
  if (!isSecretAlias(value.targetAlias)) malformed();
  if (!isTimestamp(value.createdAt)) malformed();
  if (value.revokedAt !== null && !isTimestamp(value.revokedAt)) malformed();
  return {
    id: value.id,
    ownerProjectId: value.ownerProjectId,
    ownerSecretId: value.ownerSecretId,
    targetProjectId: value.targetProjectId,
    targetAlias: value.targetAlias,
    createdAt: value.createdAt,
    revokedAt: value.revokedAt,
  };
}

// The relations between records that no single record can state. An active
// grant must name a secret that exists and is owned by the grant's owner
// project, and no two active grants may give one target the same alias, and
// no active grant may share an alias with a secret its target owns. A
// document that breaks one of these was not written by this build, and
// resolving an alias through it would be an authority decision about
// something nobody approved, so it is refused rather than repaired.
function requireGrantRelations(state: VaultState): void {
  const seen = new Set<string>();
  for (const grant of state.sharingGrants) {
    if (grant.revokedAt !== null) continue;
    const key = `${grant.targetProjectId}\0${grant.targetAlias}`;
    if (seen.has(key)) malformed();
    seen.add(key);
    const secret = state.secrets.find(
      (entry) => entry.id === grant.ownerSecretId,
    );
    if (secret === undefined || secret.projectId !== grant.ownerProjectId)
      malformed();
    if (
      findSecret(state, grant.targetProjectId, grant.targetAlias) !== undefined
    )
      malformed();
  }
}

// How long one observed OS value may be. Real user and host names are far
// shorter than this on every platform Ward targets; the bound is here so a
// damaged document cannot carry an unbounded string, and it is wide enough
// that a name observed from the OS is one this build will always read back.
const maxObservedChars = 256;

// Everything a name Ward prints may not contain. Empty and over-long values
// cannot be what a platform reported; the rest is the set of characters that
// are not text a line can carry, named by Unicode general category so the
// code and this sentence cannot drift: Cc is the controls, C0 and DEL and the
// C1 block together; Cf is the format characters, whose bidi overrides are
// the ones that could make `ward audit`'s line read as the reverse of what it
// says; and Zl and Zp are the two line separators, which a line cannot carry
// for the plainer reason that they end it. Tested as one class over the whole
// value because the claim is about the whole value. The first version of this
// grammar refused only C0 and DEL, and a reviewer measured U+0085, U+2028 and
// U+202E passing it (WCLI-11 review, F4).
const unprintable = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

function isObservedString(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > maxObservedChars) return false;
  return !unprintable.test(value);
}

function isObservedMachine(value: unknown): value is ObservedMachine {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== "host" || keys[1] !== "user")
    return false;
  return isObservedString(value.user) && isObservedString(value.host);
}

// The observed identity as a record may carry it, or null when the OS said
// nothing this build can record. The caller observes — reading the platform is
// an adapter's job, not this module's — and passes what it read through here.
//
// This is the one grammar for the value, and the serializer runs the value
// through it again rather than trusting what it is handed (see the audit
// branch of serializeVaultState). That second funnel is load-bearing: the run
// path takes an identity from an injected port, and a value outside the
// grammar that reached the document would be refused by this module's own
// reader on the way back in, with no repair command for a vault in that state
// (WCLI-11 review, F3).
export function observedMachine(
  user: unknown,
  host: unknown,
): ObservedMachine | null {
  if (!isObservedString(user) || !isObservedString(host)) return null;
  return { user, host };
}

// A self-asserted label, bounded by the alias grammar (WCLI-11). The grammar
// is deliberately the secret alias's: a label is correlation metadata with the
// same job an alias has — being a name a person types and a record can carry —
// and one grammar for both means a value that could not be an alias is not a
// label either.
function isLabelOrNull(value: unknown): value is string | null {
  return value === null || isSecretAlias(value);
}

// A stored audit event. Every field is a Ward-owned identifier, a closed
// code, a timestamp, or a value this module's own grammar bounds — which is
// what makes this collection safe to read back and display, and what makes an
// event written by a build whose vocabulary differed a damaged record rather
// than a displayable one.
function ownAuditRecord(value: unknown): AuditRecord {
  if (!isRecord(value)) malformed();
  const expected = [
    "actorLabel",
    "at",
    "id",
    "machine",
    "outcome",
    "phase",
    "profile",
    "projectId",
    "runId",
    "secretId",
    "taskLabel",
  ];
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length) malformed();
  for (const [index, key] of expected.entries())
    if (keys[index] !== key) malformed();
  if (!isOpaqueId(value.id)) malformed();
  if (!isOpaqueId(value.runId)) malformed();
  if (!isOpaqueId(value.projectId)) malformed();
  if (!isOpaqueId(value.secretId)) malformed();
  if (!isProfileName(value.profile)) malformed();
  if (value.phase !== "admission" && value.phase !== "completion") malformed();
  if (value.outcome !== null) {
    if (typeof value.outcome !== "string") malformed();
    if (!(auditOutcomes as readonly string[]).includes(value.outcome))
      malformed();
    // An admission record is written before there is an outcome, so one
    // carrying an outcome is not a record this build wrote.
    if (value.phase === "admission") malformed();
  }
  if (!isTimestamp(value.at)) malformed();
  if (value.machine !== null && !isObservedMachine(value.machine)) malformed();
  if (!isLabelOrNull(value.actorLabel)) malformed();
  if (!isLabelOrNull(value.taskLabel)) malformed();
  return {
    id: value.id,
    runId: value.runId,
    projectId: value.projectId,
    profile: value.profile,
    secretId: value.secretId,
    phase: value.phase,
    outcome: value.outcome as AuditOutcome | null,
    at: value.at,
    machine: value.machine as ObservedMachine | null,
    actorLabel: value.actorLabel,
    taskLabel: value.taskLabel,
  };
}

// A missing collection key is an empty collection, so a document carrying
// only `formatVersion` parses as an empty vault rather than being refused.
// That tolerance is about a missing key inside this format, and not about
// another format: the version below is read without it and refuses first, so
// no document from a different build reaches these defaults.
export function parseVaultState(plaintext: Uint8Array): VaultState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
    );
  } catch {
    malformed();
  }
  if (!isRecord(parsed)) malformed();
  for (const key of Object.keys(parsed))
    if (
      key !== "formatVersion" &&
      key !== "projects" &&
      key !== "localBindings" &&
      key !== "secrets" &&
      key !== "profileApprovals" &&
      key !== "sharingGrants" &&
      key !== "auditRecords"
    )
      malformed();
  // The version is an ordinary field, not a format gate (DEC-38). A missing
  // or non-numeric value and a number this build did not write are one
  // answer rather than two, because with one format there is no other build
  // for the second to be about — a `typeof` check would only split off a case
  // that reaches the same refusal one line later.
  if (parsed.formatVersion !== vaultStateFormatVersion) malformed();
  const state: VaultState = {
    formatVersion: parsed.formatVersion,
    projects: ownCollection(parsed.projects ?? [], ownProject),
    localBindings: ownCollection(parsed.localBindings ?? [], ownBinding),
    secrets: ownCollection(parsed.secrets ?? [], ownSecret),
    profileApprovals: ownCollection(
      parsed.profileApprovals ?? [],
      ownProfileApproval,
    ),
    sharingGrants: ownCollection(parsed.sharingGrants ?? [], ownSharingGrant),
    auditRecords: ownCollection(parsed.auditRecords ?? [], ownAuditRecord),
  };
  requireGrantRelations(state);
  return state;
}

export function serializeVaultState(state: VaultState): Uint8Array {
  // The reader refuses a document whose grants break the relations above, and
  // there is no repair command, so a writer that would produce one fails here
  // instead of leaving a vault nothing can open.
  requireGrantRelations(state);
  const document = {
    formatVersion: vaultStateFormatVersion,
    projects: state.projects.map(({ id, createdAt }) => ({ id, createdAt })),
    localBindings: state.localBindings.map(
      ({ projectId, root, device, inode, registeredAt }) => ({
        projectId,
        root,
        device,
        inode,
        registeredAt,
      }),
    ),
    secrets: state.secrets.map(
      ({ id, projectId, alias, value, createdAt, updatedAt, revision }) => ({
        id,
        projectId,
        alias,
        value,
        createdAt,
        updatedAt,
        revision,
      }),
    ),
    profileApprovals: state.profileApprovals.map(
      ({
        profile,
        projectId,
        root,
        device,
        inode,
        approvedAt,
        snapshotVersion,
        snapshot,
      }) => ({
        profile,
        projectId,
        root,
        device,
        inode,
        approvedAt,
        snapshotVersion,
        // Written in the same shape a manifest declares it, so one
        // normalizer reads both and a stored snapshot cannot drift into a
        // form only the serializer produces. The canonical order is the
        // normalizer's sorted one, and an object preserves it.
        snapshot: {
          adapter: snapshot.adapter,
          method: snapshot.method,
          url: snapshot.url,
          auth: { type: snapshot.auth.type, secret: snapshot.auth.secret },
          headers: Object.fromEntries(
            snapshot.headers.map(({ name, value }) => [name, value]),
          ),
          requestBody: snapshot.requestBody,
          output: snapshot.output,
        },
      }),
    ),
    sharingGrants: state.sharingGrants.map(
      ({
        id,
        ownerProjectId,
        ownerSecretId,
        targetProjectId,
        targetAlias,
        createdAt,
        revokedAt,
      }) => ({
        id,
        ownerProjectId,
        ownerSecretId,
        targetProjectId,
        targetAlias,
        createdAt,
        revokedAt,
      }),
    ),
    auditRecords: state.auditRecords.map(
      ({
        id,
        runId,
        projectId,
        profile,
        secretId,
        phase,
        outcome,
        at,
        machine,
        actorLabel,
        taskLabel,
      }) => ({
        id,
        runId,
        projectId,
        profile,
        secretId,
        phase,
        outcome,
        at,
        // Written as an object or as null, never omitted: this document's
        // reader compares key sets exactly, and JSON drops a key whose value
        // is undefined. The value goes back through the grammar rather than
        // being trusted — a caller can hand this one in from an injected port
        // — so this path cannot serialize a record the reader would refuse.
        // A value that fails becomes null, which is what the record says when
        // the OS gave no answer, and is true of this value too: Ward has no
        // identity here that it can record.
        machine:
          machine === null ? null : observedMachine(machine.user, machine.host),
        actorLabel,
        taskLabel,
      }),
    ),
  };
  return new TextEncoder().encode(JSON.stringify(document));
}

// The binding for a specific directory, whatever project it names. A miss
// means this checkout is not registered, and a hit for another project means
// the path was registered under a different manifest: both are answered by
// the caller, and neither falls back to another path or project.
export function findBinding(
  state: VaultState,
  checkout: CheckoutIdentity,
): BindingRecord | undefined {
  return state.localBindings.find(
    (binding) =>
      binding.root === checkout.root &&
      binding.device === checkout.device &&
      binding.inode === checkout.inode,
  );
}

// Registers a checkout for a project and records the project itself if this
// vault has not seen it. The caller is responsible for the authority
// decision; this only writes what it is given.
export function registerCheckout(options: {
  state: VaultState;
  projectId: string;
  checkout: CheckoutIdentity;
  registeredAt: string;
}): VaultState {
  const { state, projectId, checkout, registeredAt } = options;
  return {
    formatVersion: vaultStateFormatVersion,
    // Registering a checkout is not an event in a run's history and does not
    // add one; the collection is carried through untouched.
    auditRecords: state.auditRecords,
    projects: state.projects.some((project) => project.id === projectId)
      ? state.projects
      : [...state.projects, { id: projectId, createdAt: registeredAt }],
    localBindings: [
      ...state.localBindings,
      {
        projectId,
        root: checkout.root,
        device: checkout.device,
        inode: checkout.inode,
        registeredAt,
      },
    ],
    // Carried through unchanged: registering a checkout must never drop
    // records a project already holds.
    secrets: state.secrets,
    profileApprovals: state.profileApprovals,
    sharingGrants: state.sharingGrants,
  };
}

// The single secret one project stores under one alias. A miss stays a miss:
// no other project's records are consulted (spec §7.1, T11).
export function findSecret(
  state: VaultState,
  projectId: string,
  alias: string,
): SecretRecord | undefined {
  return state.secrets.find(
    (secret) => secret.projectId === projectId && secret.alias === alias,
  );
}

// Every secret one project owns, in storage order. Another project's records
// are not filtered in or counted: this never crosses the project boundary.
export function secretsFor(
  state: VaultState,
  projectId: string,
): readonly SecretRecord[] {
  return state.secrets.filter((secret) => secret.projectId === projectId);
}

// Replaces the record under the same (project, alias) or appends it. The
// caller builds the record; this only places it.
export function withSecret(
  state: VaultState,
  record: SecretRecord,
): VaultState {
  return {
    ...state,
    secrets: [
      ...state.secrets.filter(
        (secret) =>
          secret.projectId !== record.projectId ||
          secret.alias !== record.alias,
      ),
      record,
    ],
  };
}

// Removes a secret and, in the same state, revokes every active grant of it
// (spec §7.2: deleting an owner record invalidates its aliases and grants
// atomically). It is one function so no caller can delete a record and leave
// a grant naming it; the document reader would refuse that state.
export function withoutSecret(
  state: VaultState,
  projectId: string,
  alias: string,
  revokedAt: string,
): VaultState {
  const removed = findSecret(state, projectId, alias);
  return {
    ...state,
    secrets: state.secrets.filter(
      (secret) => secret.projectId !== projectId || secret.alias !== alias,
    ),
    sharingGrants:
      removed === undefined
        ? state.sharingGrants
        : state.sharingGrants.map((grant) =>
            grant.ownerSecretId === removed.id && grant.revokedAt === null
              ? { ...grant, revokedAt }
              : grant,
          ),
  };
}

// The active grant that gives `projectId` the alias, if any.
export function findActiveGrant(
  state: VaultState,
  projectId: string,
  alias: string,
): SharingGrantRecord | undefined {
  return state.sharingGrants.find(
    (grant) =>
      grant.targetProjectId === projectId &&
      grant.targetAlias === alias &&
      grant.revokedAt === null,
  );
}

// The active grant of one owner secret to one target project, if any.
export function findActiveGrantOf(
  state: VaultState,
  ownerSecretId: string,
  targetProjectId: string,
): SharingGrantRecord | undefined {
  return state.sharingGrants.find(
    (grant) =>
      grant.ownerSecretId === ownerSecretId &&
      grant.targetProjectId === targetProjectId &&
      grant.revokedAt === null,
  );
}

// What an alias means inside one project. This is the single place a read
// turns an alias into a secret, so `ward run`, its admission transaction,
// `ward check` and `profile approve` cannot disagree about it. A project's own
// secret answers first; the relations the reader enforces mean an own secret
// and an active grant never share an alias, so the order is not a precedence
// that could hide one behind the other. "revoked" is an alias whose only grant
// has been revoked, kept distinct from "missing" so a refusal can say why.
export type ResolvedSecret =
  | { readonly kind: "owned"; readonly secret: SecretRecord }
  | {
      readonly kind: "granted";
      readonly secret: SecretRecord;
      readonly grant: SharingGrantRecord;
    }
  | { readonly kind: "revoked" }
  | { readonly kind: "missing" };

export function resolveSecret(
  state: VaultState,
  projectId: string,
  alias: string,
): ResolvedSecret {
  const owned = findSecret(state, projectId, alias);
  if (owned !== undefined) return { kind: "owned", secret: owned };
  const grant = findActiveGrant(state, projectId, alias);
  if (grant !== undefined) {
    // The relation the reader enforces, checked again where the authority is
    // used: the grant names a secret by id, and it must still be the
    // owner project's.
    const secret = state.secrets.find(
      (entry) =>
        entry.id === grant.ownerSecretId &&
        entry.projectId === grant.ownerProjectId,
    );
    return secret === undefined
      ? { kind: "revoked" }
      : { kind: "granted", secret, grant };
  }
  return state.sharingGrants.some(
    (entry) =>
      entry.targetProjectId === projectId && entry.targetAlias === alias,
  )
    ? { kind: "revoked" }
    : { kind: "missing" };
}

export function withGrant(
  state: VaultState,
  record: SharingGrantRecord,
): VaultState {
  return { ...state, sharingGrants: [...state.sharingGrants, record] };
}

export function withRevokedGrant(
  state: VaultState,
  grantId: string,
  revokedAt: string,
): VaultState {
  return {
    ...state,
    sharingGrants: state.sharingGrants.map((grant) =>
      grant.id === grantId && grant.revokedAt === null
        ? { ...grant, revokedAt }
        : grant,
    ),
  };
}

// The approval for one profile in one binding. All four parts of the
// identity are matched — project, root, device, inode — so an approval can
// never be reached from another project, another checkout, or a directory
// that replaced the one it was made in.
function isApprovalFor(
  approval: ProfileApprovalRecord,
  checkout: CheckoutIdentity,
  projectId: string,
  profile: string,
): boolean {
  return (
    approval.profile === profile &&
    approval.projectId === projectId &&
    approval.root === checkout.root &&
    approval.device === checkout.device &&
    approval.inode === checkout.inode
  );
}

export function findProfileApproval(
  state: VaultState,
  checkout: CheckoutIdentity,
  projectId: string,
  profile: string,
): ProfileApprovalRecord | undefined {
  return state.profileApprovals.find((approval) =>
    isApprovalFor(approval, checkout, projectId, profile),
  );
}

// Replaces the approval for the same (binding, project, profile) or appends
// it. Reapproving replaces the snapshot rather than adding a second one, so
// a profile has at most one approval per binding.
export function withProfileApproval(
  state: VaultState,
  record: ProfileApprovalRecord,
): VaultState {
  return {
    ...state,
    profileApprovals: [
      ...state.profileApprovals.filter(
        (approval) =>
          !isApprovalFor(
            approval,
            {
              root: record.root,
              device: record.device,
              inode: record.inode,
            },
            record.projectId,
            record.profile,
          ),
      ),
      record,
    ],
  };
}

export function withoutProfileApproval(
  state: VaultState,
  checkout: CheckoutIdentity,
  projectId: string,
  profile: string,
): VaultState {
  return {
    ...state,
    profileApprovals: state.profileApprovals.filter(
      (approval) => !isApprovalFor(approval, checkout, projectId, profile),
    ),
  };
}

// Appends an audit event and drops the oldest if the history is at its
// bound. Appending rather than replacing is the point: two runs of the same
// profile are two events, and a history that collapsed them would not be one.
export function withAuditRecord(
  state: VaultState,
  record: AuditRecord,
): VaultState {
  const appended = [...state.auditRecords, record];
  return {
    ...state,
    auditRecords:
      appended.length > auditHistoryLimit
        ? appended.slice(appended.length - auditHistoryLimit)
        : appended,
  };
}
