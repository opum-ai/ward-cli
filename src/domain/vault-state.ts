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

export interface VaultState {
  readonly formatVersion: number;
  readonly projects: readonly ProjectRecord[];
  readonly localBindings: readonly BindingRecord[];
  readonly secrets: readonly SecretRecord[];
  readonly profileApprovals: readonly ProfileApprovalRecord[];
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

// A document with no collection key is an empty collection: the skeleton
// `ward setup` seals holds only `formatVersion`, and an older vault gains
// the collections with its first binding rather than being refused.
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
      key !== "profileApprovals"
    )
      malformed();
  // A version that is missing or is not a number is a damaged document; a
  // version this build does not implement is a document from another build.
  // They are different answers because they call for different actions.
  if (typeof parsed.formatVersion !== "number") malformed();
  if (parsed.formatVersion !== vaultStateFormatVersion)
    throw new WardError("vault_format_unsupported");
  return {
    formatVersion: parsed.formatVersion,
    projects: ownCollection(parsed.projects ?? [], ownProject),
    localBindings: ownCollection(parsed.localBindings ?? [], ownBinding),
    secrets: ownCollection(parsed.secrets ?? [], ownSecret),
    profileApprovals: ownCollection(
      parsed.profileApprovals ?? [],
      ownProfileApproval,
    ),
  };
}

export function serializeVaultState(state: VaultState): Uint8Array {
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

export function withoutSecret(
  state: VaultState,
  projectId: string,
  alias: string,
): VaultState {
  return {
    ...state,
    secrets: state.secrets.filter(
      (secret) => secret.projectId !== projectId || secret.alias !== alias,
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
