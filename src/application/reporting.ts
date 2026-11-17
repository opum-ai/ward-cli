// `ward status` and `ward doctor` (spec §8): the two read-only reports over
// the state every other command acts on. Status answers what this checkout
// and its backend look like right now; doctor runs the same observation as
// its named checks (DEC-262 a25 fixes their order) and exits 6 when one of
// them is wrong. They share this
// module because they must never disagree: a status run and a doctor run
// read the same facts through the same ports, in the same order.
//
// Three rules shape both reports:
//
// - Only this checkout. Neither report enumerates the vault: no other
//   project, no other binding, no alias. A checkout bound to another project
//   is reported as a conflict, never by naming that project (spec §8's "no
//   global inventory").
// - Nothing secret. The only vault value either report touches is the vault
//   key, which is used and zeroed and never rendered. No transport exists in
//   this build (WCLI-10 owns `ward run`), so there are no request headers to
//   print; when that lands, this file's non-disclosure claim has to be
//   re-measured against it rather than assumed.
// - Read-only. Every fact comes from `store.header`, `keyProvider.load`,
//   `store.read` and a project file read. Nothing here can write: there is no
//   call to `mutate`, `create`, or a file write in this module.
//
// A doctor check is one of three things, and the middle one is the point:
//
//   - pass    — its subject is present and healthy;
//   - fail    — its subject is present and wrong, or present and cannot be
//               evaluated: a blocked check must never read as a healthy one;
//   - skipped — its subject does not exist here (no vault, no manifest, no
//               installed instruction block), so there is nothing to judge.
//
// Absence is never a failure. A machine or checkout that was never set up
// has nothing wrong with it, and readiness for a specific profile is
// `ward check` (WCLI-9), not this command. Doctor exits 0 when no check
// failed and 6 when any did, with every check reported either way.
import { type ExitCode, exitCodes } from "../contract/envelope.ts";
import { type ErrorCode, errorCatalog, WardError } from "../contract/errors.ts";
import type { AgentTarget } from "../contract/manifest.ts";
import { escapeForDisplay } from "../domain/display.ts";
import { managedBlockStatus } from "../domain/managed-block.ts";
import { normalizeProfile } from "../domain/profile.ts";
import { parseProjectManifest } from "../domain/project-manifest.ts";
import {
  type CheckoutIdentity,
  findBinding,
  parseVaultState,
  type VaultState,
} from "../domain/vault-state.ts";
import { agentTargetDocuments, wardBlockBody } from "./bridges.ts";
import type {
  KeyBackendId,
  KeyProvider,
  KeyRefusalClassifier,
  KeyRefusalState,
  KeyRefusalStateName,
  TpmDiagnoser,
} from "./key-provider.ts";
import type { ProjectFiles } from "./project-files.ts";
import type { VaultStore } from "./vault-store.ts";

export interface ReportingOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
  readonly checkouts: StaleCheckoutProbe;
  // Reads a TPM2 refusal into its doctor state. Supplied by the composition
  // root, since the application layer cannot reach the adapter. Absent means
  // no backend detail is kept, and a TPM2 refusal is still `unavailable`.
  readonly classifyKeyRefusal?: KeyRefusalClassifier;
  // The platform the report is about (the selection's own, else the host's).
  // Linux alone reports the Secret Service gap (DEC-262 a24 Q3).
  readonly platform?: string;
  // Doctor's TPM probe (DEC-262 a26), supplied on Linux by the composition root.
  readonly diagnoseTpm?: TpmDiagnoser;
}

function onLinux(options: ReportingOptions): boolean {
  return (options.platform ?? process.platform) === "linux";
}

// The store a report names (DEC-262 a24 Q1). Unsupported and ambiguous have
// none to name. A provider that cannot say reads as the platform's own store.
function backendIn(
  options: ReportingOptions,
  key: KeyObservation | undefined,
): KeyBackendId | null {
  if (key?.status === "unsupported" || key?.status === "ambiguous") return null;
  const reported = options.keyProvider.backend?.();
  if (reported !== undefined) return reported;
  return (options.platform ?? process.platform) === "darwin"
    ? "macos-keychain"
    : null;
}

const backendDisplay: Record<KeyBackendId, string> = {
  "macos-keychain": "macOS Keychain",
  tpm2: "TPM2",
};

// A checkout a stored record names, seen from here. Most stale approvals were
// written by a different directory than the one being reported — a deleted
// worktree, a re-cloned tree, a sibling — so the port answers about an
// absolute root rather than about the checkout in hand.
export interface ProbedCheckout {
  // The root the record's path resolves to, which is what `ward profile
  // approve` would itself resolve. It is compared against the record's root,
  // not assumed equal: a directory that survived without its `.git` resolves
  // to an ancestor, and re-approving there would write a different root.
  readonly root: string;
  readonly device: string;
  readonly inode: string;
  // The nonce in that checkout's git directory, when it has one.
  readonly checkoutId?: string;
  // Whether `ward init` could plausibly give that checkout an identity, judged
  // without writing. False when its git directory does not resolve or is not
  // writable by this account, its nonce file is invalid, or a link or file
  // stands where the `ward` directory belongs: init throws
  // checkout_identity_unavailable there. Absent means it could.
  readonly registrable?: boolean;
  // The project manifest's text, or undefined when there is none to read.
  readonly manifest: string | undefined;
}

export interface StaleCheckoutProbe {
  probe(root: string): ProbedCheckout | undefined;
}

// The error code of a WardError, or undefined for anything else. An
// unrecognized error is rethrown by every caller below: a report that
// silently absorbs a fault it does not understand would be the same shape as
// one that reports clean without reading anything.
function wardCode(error: unknown): string | undefined {
  return error instanceof WardError ? error.code : undefined;
}

// --- what the ports answered -------------------------------------------------

type ManifestObservation =
  | { status: "present"; projectId: string; schemaVersion: number }
  | { status: "absent" }
  | { status: "malformed" }
  | { status: "unsupported" }
  | { status: "unreadable" }
  | { status: "unsafe" };

type VaultStatus =
  | "present"
  | "absent"
  | "insecure"
  | "unrecognized"
  | "unsupported"
  | "malformed"
  | "unreadable"
  | "busy";

type VaultObservation =
  | {
      status: "present";
      vaultId: string;
      revision: number;
      formatVersion: number;
    }
  | { status: Exclude<VaultStatus, "present"> };

type KeyObservation =
  | { status: "present"; key: Uint8Array }
  | { status: "missing" }
  // `refusal` is the backend's own reading of why (DEC-262 a15 to a20); doctor
  // reports its state as the check's code or reason (DEC-262 a24, a25).
  | { status: "unavailable"; refusal?: KeyRefusalState }
  // Two stores hold a key for this vault (a16 rule 2). The names are carried
  // from WardError.stores, never a path. Doctor reports it as its own code;
  // status keeps its existing `unavailable` value (see reportedKeyStatus).
  | { status: "ambiguous"; stores: readonly string[] }
  | { status: "invalid" }
  | { status: "unsupported" };

type ReportedKeyStatus = Exclude<KeyObservation["status"], "ambiguous">;

// What the existing report contract can say about a key observation. Ambiguous
// reads as unavailable until opum-doc rules on its own value, so the contract
// does not move in this slice and the report answers instead of throwing.
function reportedKeyStatus(key: KeyObservation): ReportedKeyStatus {
  return key.status === "ambiguous" ? "unavailable" : key.status;
}

// `unsupported` is not about the document's own version, which now has a
// single format and answers `malformed` when it is not this build's (DEC-38).
// It is the sealed envelope reaching this read with a header this build does
// not implement, which is the only remaining raiser of
// `vault_format_unsupported`: since DEC-246 a2 a stored approval's snapshot
// version is an inert record reported as stale, not an error. Because that
// envelope case is reachable, this status is what keeps the two reports
// answering rather than throwing.
type StateObservation =
  | { status: "present"; state: VaultState }
  | { status: "unreadable" }
  | { status: "unauthenticated" }
  | { status: "malformed" }
  | { status: "unsupported" }
  | { status: "busy" };

// undefined means the read was never attempted because a prerequisite is
// absent: a state document without a vault, or a key without a vault header.
type Observation = {
  manifest: ManifestObservation;
  vault: VaultObservation;
  key: KeyObservation | undefined;
  state: StateObservation | undefined;
};

function observeManifest(files: ProjectFiles): ManifestObservation {
  let text: string | undefined;
  try {
    text = files.read("manifest");
  } catch (error) {
    switch (wardCode(error)) {
      case "project_path_unsafe":
        return { status: "unsafe" };
      case "project_file_unwritable":
        return { status: "unreadable" };
      default:
        throw error;
    }
  }
  if (text === undefined) return { status: "absent" };
  try {
    const manifest = parseProjectManifest(text);
    return {
      status: "present",
      projectId: manifest.projectId,
      schemaVersion: manifest.schemaVersion,
    };
  } catch (error) {
    switch (wardCode(error)) {
      case "project_manifest_malformed":
        return { status: "malformed" };
      case "project_manifest_unsupported":
        return { status: "unsupported" };
      default:
        throw error;
    }
  }
}

// The header is read without the key, so "a vault exists" and "the vault
// location is private" are answered even when the key is missing.
function observeVault(store: VaultStore): VaultObservation {
  try {
    const header = store.header();
    if (header === undefined) return { status: "absent" };
    return {
      status: "present",
      vaultId: header.vaultId,
      revision: header.revision,
      formatVersion: header.formatVersion,
    };
  } catch (error) {
    switch (wardCode(error)) {
      case "vault_store_insecure":
        return { status: "insecure" };
      case "vault_store_unrecognized":
        return { status: "unrecognized" };
      case "vault_format_unsupported":
        return { status: "unsupported" };
      case "vault_record_malformed":
        return { status: "malformed" };
      case "vault_busy":
        return { status: "busy" };
      case "vault_store_failed":
        return { status: "unreadable" };
      default:
        throw error;
    }
  }
}

export async function observeKey(
  keyProvider: KeyProvider,
  vaultId: string,
  classify?: KeyRefusalClassifier,
): Promise<KeyObservation> {
  try {
    return { status: "present", key: await keyProvider.load(vaultId) };
  } catch (error) {
    switch (wardCode(error)) {
      case "vault_key_missing":
        return { status: "missing" };
      case "vault_key_unavailable":
        return { status: "unavailable" };
      case "vault_key_ambiguous":
        return {
          status: "ambiguous",
          stores: error instanceof WardError ? error.stores : [],
        };
      case "vault_key_invalid":
        return { status: "invalid" };
      case "vault_key_store_unsupported":
        return { status: "unsupported" };
      default:
        // Every TPM2 code (DEC-262 a15) means the TPM did not give the key:
        // fail closed as unavailable. A lone private blob (tpm_key_incomplete)
        // is a recovery condition and is NEVER read as a missing key, which is
        // what lets setup run (WCLI-21 N3 a). The refusal's state rides along
        // for the renderers of slice 3d-2.
        if (wardCode(error)?.startsWith("tpm_") === true) {
          // A classifier that throws must not take the report down: fail
          // closed to a plain unavailable key.
          let refusal: KeyRefusalState | undefined;
          try {
            refusal = classify?.(error);
          } catch {
            refusal = undefined;
          }
          return refusal === undefined
            ? { status: "unavailable" }
            : { status: "unavailable", refusal };
        }
        throw error;
    }
  }
}

// The decrypted state document. The caller owns `key` and zeroes it; the
// plaintext is zeroed here as soon as it has been parsed, and the parsed
// state holds identifiers and timestamps only, never key material.
function observeState(store: VaultStore, key: Uint8Array): StateObservation {
  try {
    const snapshot = store.read(key);
    try {
      return { status: "present", state: parseVaultState(snapshot.plaintext) };
    } finally {
      snapshot.plaintext.fill(0);
    }
  } catch (error) {
    switch (wardCode(error)) {
      case "vault_state_malformed":
        return { status: "malformed" };
      // Still reachable after DEC-38 and DEC-246 a2, and this case is the
      // whole reason the status survives: the sealed envelope's header raises
      // this code for a format this build does not implement. The state
      // document's own version no longer raises it, and neither does a
      // stored approval, which is held inert and reported as stale instead.
      // Dropping this case makes both reports throw out of their read
      // instead of answering.
      case "vault_format_unsupported":
        return { status: "unsupported" };
      case "vault_authentication_failed":
        return { status: "unauthenticated" };
      case "vault_busy":
        return { status: "busy" };
      case "vault_not_found":
      case "vault_store_insecure":
      case "vault_store_unrecognized":
      case "vault_record_malformed":
      case "vault_record_too_large":
      case "vault_store_failed":
        return { status: "unreadable" };
      default:
        throw error;
    }
  }
}

async function observe(options: ReportingOptions): Promise<Observation> {
  const manifest = observeManifest(options.files);
  const vault = observeVault(options.store);
  if (vault.status !== "present")
    return { manifest, vault, key: undefined, state: undefined };
  const key = await observeKey(
    options.keyProvider,
    vault.vaultId,
    options.classifyKeyRefusal,
  );
  let state: StateObservation | undefined;
  try {
    if (key.status === "present") state = observeState(options.store, key.key);
  } finally {
    // The key is not needed past this point, and nothing below can render it.
    if (key.status === "present") key.key.fill(0);
  }
  return { manifest, vault, key, state };
}

// --- ward status -------------------------------------------------------------

// One stored approval this build cannot read: its snapshot version names
// another build's normalizer (DEC-246 a2). It authorises nothing, and both
// reports name it so the developer can re-approve it rather than discovering
// the loss at a refusal.
//
// Two things decide whether it appears here at all, and both are DEC-246 (a3):
// it belongs to the project being reported (Q1), and it can still be cleared
// (Q2). A record of another project is counted, never named; a record of this
// project that nothing can reach is named as inert without failing the doctor.
export interface StaleApprovalReport {
  readonly profile: string;
  readonly projectId: string;
  readonly checkout: string;
  readonly snapshotVersion: number;
  // Whether re-approving this profile from that checkout would replace this
  // record. False means inert: it authorises nothing. Usually nothing this
  // build offers can reach it (DEC-246 a3 Q2); the one exception is a legacy
  // record at an unregistered checkout `ward init` can register, which
  // registerHint below words.
  readonly clearable: boolean;
  // The step that clears this record, or why there is none. Written out
  // rather than left for the caller to compose from the fields above: the
  // clearing step only works from the checkout the record names, and a reader
  // assembling its own command has no way to know that from the fields alone.
  readonly remedy: string;
  // Present and true only on a record written before checkouts had an identity,
  // left inert because its checkout is not registered, at a checkout `ward init`
  // can register: the report then adds the register-and-approve-again hint. It
  // is absent everywhere else, including a legacy record at a checkout init
  // cannot register, which reads as inert and unreachable. The report words the
  // hint from this field, not from the remedy text.
  readonly registerHint?: boolean;
}

export interface StatusReport {
  readonly checkout: string;
  readonly manifest: {
    readonly status: ManifestObservation["status"];
    readonly projectId?: string;
    readonly schemaVersion?: number;
  };
  readonly binding: {
    readonly status: "registered" | "unregistered" | "conflict" | "unknown";
  };
  readonly vault: {
    readonly status: VaultStatus;
    readonly revision?: number;
    readonly formatVersion?: number;
  };
  readonly keyProvider: {
    readonly status:
      | "present"
      | "missing"
      | "unavailable"
      | "invalid"
      | "unsupported"
      | "unchecked";
    // Always present (DEC-262 a24 Q1): the store holding the key, or where a
    // new one would go; null when no backend is usable on this host, which
    // `status` above says why.
    readonly backend: KeyBackendId | null;
    // Present on Linux only (a24 Q3): what Ward does not implement, by name.
    readonly notImplemented?: readonly ["secret-service"];
  };
  // Empty rather than absent when there are none, so a caller can tell "none"
  // from "this report does not say".
  readonly staleApprovals: readonly StaleApprovalReport[];
  // How many stale approvals belong to projects other than this one. A bare
  // count by design (DEC-246 a3 Q1): their ids, profile names and paths are
  // never part of a report for a checkout that cannot act on them. Zero
  // rather than absent when there are none, matching the field above.
  readonly otherProjectStaleApprovals: number;
}

// The project a report is about: the one this checkout's tracked manifest
// claims. Undefined when the manifest is absent or cannot be judged, and then
// nothing is named — a report that cannot say which project it is for cannot
// say whose records are whose.
function currentProject(manifest: ManifestObservation): string | undefined {
  return manifest.status === "present" ? manifest.projectId : undefined;
}

// Both halves of DEC-246 (a3), answered in one pass because they are one read.
//
// Q1: a record is named only when it belongs to the project being reported.
// Records of other projects are counted and nothing else — no id, no profile
// name, no path — which is what keeps status, an admin:false report an agent
// runs, from becoming a vault-wide inventory (spec §8, ADR 0007).
//
// Q2: a named record is clearable only when running `ward profile approve` in
// its own checkout would actually replace it: that directory still resolves to
// the same root, device and inode; that checkout is still registered under its
// current nonce (for a legacy record, which has none, the nonce the checkout
// holds now); and its manifest still declares the profile under this project.
// Everything else is inert, and inert records are named without failing the
// doctor. A legacy record at a checkout that is not registered is inert too,
// with a hint: registering would grant that checkout the project's secrets, so
// the doctor never asks for it (DEC-255 a6: records nobody touches stay inert).
function staleApprovals(
  state: StateObservation | undefined,
  project: string | undefined,
  checkouts: StaleCheckoutProbe,
): { named: readonly StaleApprovalReport[]; otherProjects: number } {
  if (state === undefined || state.status !== "present")
    return { named: [], otherProjects: 0 };
  const named: StaleApprovalReport[] = [];
  let otherProjects = 0;
  for (const record of state.state.staleProfileApprovals) {
    if (project === undefined || record.projectId !== project) {
      otherProjects += 1;
      continue;
    }
    named.push(describeStaleApproval(record, state.state, checkouts));
  }
  return { named, otherProjects };
}

function describeStaleApproval(
  record: VaultState["staleProfileApprovals"][number],
  state: VaultState,
  checkouts: StaleCheckoutProbe,
): StaleApprovalReport {
  const fields = {
    profile: record.profile,
    projectId: record.projectId,
    checkout: record.root,
    snapshotVersion: record.snapshotVersion,
  };
  const inert = (why: string): StaleApprovalReport => ({
    ...fields,
    clearable: false,
    remedy: `inert and unreachable: ${why}`,
  });

  const probed = checkouts.probe(record.root);
  if (probed === undefined) return inert("that directory no longer exists");
  if (
    probed.root !== record.root ||
    probed.device !== record.device ||
    probed.inode !== record.inode
  )
    return inert("a different directory now stands at that path");
  const legacy = record.checkoutId === undefined;
  if (!legacy && probed.checkoutId !== record.checkoutId)
    return inert("a different directory now stands at that path");
  // An approval with no nonce was written before checkouts had an identity and
  // authorises nothing. It is judged like any other stale record against the
  // checkout as it stands: the binding is looked up under the checkout's CURRENT
  // nonce, since the record has none. A checkout that holds no nonce, or holds
  // one whose binding is gone, is not registered, and a legacy record there is
  // inert (below), never a request to register.
  const identity = {
    root: record.root,
    device: record.device,
    inode: record.inode,
    ...(legacy
      ? probed.checkoutId === undefined
        ? {}
        : { checkoutId: probed.checkoutId }
      : { checkoutId: record.checkoutId }),
  };
  const binding =
    legacy && probed.checkoutId === undefined
      ? undefined
      : findBinding(state, identity);
  if (binding === undefined && !legacy)
    return inert("that checkout is no longer registered");
  if (binding !== undefined && binding.projectId !== record.projectId)
    return inert("that checkout is registered to another project");
  if (probed.manifest === undefined)
    return inert("that checkout has no project manifest");
  let manifest: ReturnType<typeof parseProjectManifest>;
  try {
    manifest = parseProjectManifest(probed.manifest);
  } catch {
    return inert("that checkout's project manifest cannot be read");
  }
  if (manifest.projectId !== record.projectId)
    return inert("that checkout now declares another project");
  if (!Object.hasOwn(manifest.profiles, record.profile))
    return inert("that checkout no longer declares this profile");
  try {
    normalizeProfile(manifest.profiles[record.profile]);
  } catch {
    return inert("that checkout's declaration of this profile cannot be read");
  }
  if (legacy && binding === undefined) {
    // Registering is offered only where `ward init` can run: at a checkout
    // whose identity cannot be bound it throws, and no step would work.
    if (probed.registrable === false)
      return inert(
        "a legacy approval, written before checkouts had an identity, at a checkout Ward cannot register because its git directory or identity file is unusable",
      );
    return {
      ...fields,
      clearable: false,
      registerHint: true,
      remedy: `a legacy approval, written before checkouts had an identity; it authorises nothing and stays inert. To replace it, register and approve again from ${record.root} (ward init, then ward profile approve ${record.profile}); registering gives that checkout access to the project's secrets`,
    };
  }
  return {
    ...fields,
    clearable: true,
    remedy: `from ${record.root}, run ward profile approve ${record.profile}`,
  };
}

function staleApprovalLines(
  approvals: readonly StaleApprovalReport[],
  otherProjects: number,
): readonly string[] {
  const lines: string[] = [];
  if (approvals.length > 0) {
    lines.push(
      `  stale approvals: ${approvals.length} (written by another build; they authorise nothing)`,
    );
    lines.push(
      ...approvals.map(
        (entry) =>
          `    - ${escapeForDisplay(entry.profile)} at ${escapeForDisplay(entry.checkout)}, snapshot version ${entry.snapshotVersion}: ${
            entry.clearable
              ? `re-approve in a trusted terminal with ward profile approve ${escapeForDisplay(entry.profile)}, run from that checkout`
              : entry.registerHint === true
                ? `inert, a legacy approval that authorises nothing; to replace it, register and approve again from that checkout (ward init, then ward profile approve ${escapeForDisplay(entry.profile)}), which gives it access to the project's secrets`
                : `inert and unreachable — ${escapeForDisplay(entry.remedy.replace(/^inert and unreachable: /, ""))}`
          }`,
      ),
    );
  }
  if (otherProjects > 0) {
    lines.push(
      `  stale approvals in other projects: ${otherProjects} (counted, never named; run Ward in that project to see them)`,
    );
  }
  return lines;
}

// The binding for this root, whatever project it names. A miss means this
// checkout is unregistered; a hit for another project than the manifest
// claims is a conflict, and the other project is not named (spec §8).
function bindingStatus(
  manifest: ManifestObservation,
  state: StateObservation | undefined,
  checkout: CheckoutIdentity,
): StatusReport["binding"]["status"] {
  if (state === undefined || state.status !== "present") return "unknown";
  const binding = findBinding(state.state, checkout);
  if (binding === undefined) return "unregistered";
  if (manifest.status === "present" && binding.projectId !== manifest.projectId)
    return "conflict";
  return "registered";
}

function statusText(report: StatusReport): string {
  const project =
    report.manifest.status === "present"
      ? `${report.manifest.projectId} (manifest present)`
      : `none (manifest ${report.manifest.status})`;
  const vault =
    report.vault.status === "present"
      ? `present (revision ${report.vault.revision}, format version ${report.vault.formatVersion})`
      : report.vault.status;
  return [
    "Ward status",
    "",
    `  checkout:      ${report.checkout}`,
    `  project:       ${project}`,
    `  binding:       ${report.binding.status}`,
    `  vault:         ${vault}`,
    `  key provider:  ${report.keyProvider.status}`,
    `  key backend:   ${report.keyProvider.backend === null ? "none" : backendDisplay[report.keyProvider.backend]}`,
    ...(report.keyProvider.notImplemented === undefined
      ? []
      : ["  Secret Service: not implemented"]),
    ...staleApprovalLines(
      report.staleApprovals,
      report.otherProjectStaleApprovals,
    ),
    "",
    "Ward read this state; it did not change anything.",
  ].join("\n");
}

export interface StatusResult {
  readonly data: StatusReport;
  readonly text: string;
}

export async function runStatus(
  options: ReportingOptions,
): Promise<StatusResult> {
  const observation = await observe(options);
  const { manifest, vault, key } = observation;
  const stale = staleApprovals(
    observation.state,
    currentProject(manifest),
    options.checkouts,
  );
  const data: StatusReport = {
    checkout: options.checkout.root,
    manifest:
      manifest.status === "present"
        ? {
            status: "present",
            projectId: manifest.projectId,
            schemaVersion: manifest.schemaVersion,
          }
        : { status: manifest.status },
    binding: {
      status: bindingStatus(manifest, observation.state, options.checkout),
    },
    vault:
      vault.status === "present"
        ? {
            status: "present",
            revision: vault.revision,
            formatVersion: vault.formatVersion,
          }
        : { status: vault.status },
    keyProvider: {
      status: key === undefined ? "unchecked" : reportedKeyStatus(key),
      backend: backendIn(options, key),
      ...(onLinux(options)
        ? { notImplemented: ["secret-service"] as const }
        : {}),
    },
    staleApprovals: stale.named,
    otherProjectStaleApprovals: stale.otherProjects,
  };
  return { data, text: statusText(data) };
}

// --- ward doctor -------------------------------------------------------------

export type DoctorCheckName =
  | "permissions"
  | "key_provider"
  | "schema"
  | "binding"
  | "stale_approvals"
  | "instructions"
  | "tpm2"
  | "secret_service";

export type InstructionState =
  | "current"
  | "absent"
  | "stale"
  | "malformed"
  | "unreadable"
  | "unsafe";

export interface DoctorCheck {
  readonly check: DoctorCheckName;
  readonly status: "pass" | "fail" | "skipped";
  readonly code: string;
  readonly documents?: Readonly<Record<AgentTarget, InstructionState>>;
  // key_provider only (DEC-262 a24 Q2, a25): why the key could not be had, when
  // the backend said. `reason` is always prose: the state's fixed wording
  // (key_unloadable's doctor string is carried unchanged), the catalog's
  // message for its code, or the fixed unknownRefusalReason; `path`
  // is a tool that failed the trust walk; `stores` names the stores that both
  // hold a key; `version` is tool_incompatible's tpm2-tools version, data a
  // script compares. Prose beyond `reason` (the hint) is human output only and
  // is never a field.
  readonly reason?: string;
  readonly path?: string;
  readonly stores?: readonly string[];
  readonly version?: string;
  // Named individually rather than counted, because the re-approve step is
  // per profile and per checkout (DEC-246 a2 clause 2), and only for this
  // project's records: other projects are a bare count (DEC-246 a3 Q1).
  readonly staleApprovals?: readonly StaleApprovalReport[];
  readonly otherProjectStaleApprovals?: number;
}

export interface DoctorReport {
  readonly ok: boolean;
  readonly checks: readonly DoctorCheck[];
}

// The vault location's own permissions, which the store enforces before
// anything else it does: `insecure` is refused first, and unrecognized,
// unsupported and malformed are thrown only after the location has passed
// the privacy inspection. The first three therefore say the location is
// private; the content problems belong to the schema check.
function permissionsCheck(vault: VaultObservation): DoctorCheck {
  const check = "permissions" as const;
  switch (vault.status) {
    case "absent":
      return { check, status: "skipped", code: "absent" };
    case "present":
    case "unrecognized":
    case "unsupported":
    case "malformed":
      return { check, status: "pass", code: "private" };
    case "insecure":
      return { check, status: "fail", code: "insecure" };
    case "busy":
      return { check, status: "fail", code: "busy" };
    case "unreadable":
      return { check, status: "fail", code: "unreadable" };
  }
}

function keyCheck(
  vault: VaultObservation,
  key: KeyObservation | undefined,
): DoctorCheck {
  const check = "key_provider" as const;
  if (vault.status === "absent")
    return { check, status: "skipped", code: "vault_absent" };
  if (key === undefined)
    return { check, status: "fail", code: `vault_${vault.status}` };
  if (key.status === "ambiguous")
    return {
      check,
      status: "fail",
      code: "vault_key_ambiguous",
      reason: errorCatalog.vault_key_ambiguous.message,
      stores: key.stores,
    };
  switch (reportedKeyStatus(key)) {
    case "present":
      return { check, status: "pass", code: "present" };
    case "missing":
      return { check, status: "fail", code: "missing" };
    case "unavailable":
      return key.status === "unavailable" && key.refusal !== undefined
        ? refusedKeyCheck(key.refusal)
        : { check, status: "fail", code: "unavailable" };
    case "invalid":
      return { check, status: "fail", code: "invalid" };
    case "unsupported":
      return { check, status: "fail", code: "unsupported" };
  }
}

// The states a TPM refusal reports under their own code (DEC-262 a24 Q2);
// every other refusal stays `unavailable` and names its state in `reason`. The
// Record is exhaustive: a new state is a compile error until it is placed.
const keyStateCode: Record<KeyRefusalStateName, string> = {
  key_incomplete: "key_incomplete",
  key_unloadable: "key_unloadable",
  tool_untrusted: "tool_untrusted",
  tool_incompatible: "tool_incompatible",
  ready: "unavailable",
  unsupported: "unavailable",
  access_refused: "unavailable",
  tools_absent: "unavailable",
  tpm_unusable: "unavailable",
  session_not_encrypted: "unavailable",
  blob_not_user_private: "unavailable",
  key_not_sealed: "unavailable",
  key_exists: "unavailable",
  directory_unusable: "unavailable",
  tool_timeout: "unavailable",
  tool_output_too_large: "unavailable",
  tool_failed: "unavailable",
};

// The catalog's fixed wording for a refusal's contract code, so `reason` is
// always prose, never a bare state token (DEC-262 a25 pick 3).
// What `reason` says when the catalog has no wording for a refusal's code (or
// the refusal carries none): fixed prose, never the state token.
export const unknownRefusalReason =
  "The credential store did not give the vault key, and Ward has no more specific wording for why.";

function catalogEntry(code: ErrorCode | undefined): {
  message?: string;
  hint?: string;
} {
  // `?? {}`: a code the catalog does not know fails closed to no wording, and
  // the caller then says unknownRefusalReason, rather than throwing out of
  // doctor.
  return code === undefined
    ? {}
    : ((errorCatalog[code] as object | undefined) ?? {});
}

function refusedKeyCheck(refusal: KeyRefusalState): DoctorCheck {
  const code = keyStateCode[refusal.state];
  return {
    check: "key_provider",
    status: "fail",
    code,
    reason:
      refusal.summary ??
      catalogEntry(refusal.code).message ??
      unknownRefusalReason,
    ...(refusal.path === undefined ? {} : { path: refusal.path }),
    ...(code === "tool_incompatible" && refusal.version !== undefined
      ? { version: refusal.version }
      : {}),
  };
}

// The host states under which no TPM is usable at all (DEC-262 a26 Q3): the
// check is skipped and names which. Every other state is about the KEY and is
// reported once, in key_provider, never repeated here.
const tpmHostStates: ReadonlySet<KeyRefusalStateName> = new Set([
  "unsupported",
  "access_refused",
  "tools_absent",
  "tpm_unusable",
  "tool_untrusted",
  "tool_incompatible",
]);

// DEC-262 (a25, a26): `tpm2` is `pass` with code `ok`, or `skipped` with
// `tpm2_absent` (no TPM is usable here) or `not_applicable` (not Linux, or this
// report has no TPM probe). It is attention at most, and never a failure.
async function tpm2Check(
  options: ReportingOptions,
  vault: VaultObservation,
): Promise<DoctorCheck> {
  const check = "tpm2" as const;
  if (!onLinux(options) || options.diagnoseTpm === undefined)
    return { check, status: "skipped", code: "not_applicable" };
  let state: KeyRefusalState;
  try {
    state = (
      await options.diagnoseTpm(
        vault.status === "present" ? vault.vaultId : undefined,
      )
    ).state;
  } catch {
    // A probe that failed is not a TPM fault and not a doctor failure: it fails
    // closed to "no TPM usable" with fixed prose.
    return {
      check,
      status: "skipped",
      code: "tpm2_absent",
      reason: unknownRefusalReason,
    };
  }
  if (!tpmHostStates.has(state.state))
    return { check, status: "pass", code: "ok" };
  return {
    check,
    status: "skipped",
    code: "tpm2_absent",
    reason:
      state.summary ?? catalogEntry(state.code).message ?? unknownRefusalReason,
    ...(state.path === undefined ? {} : { path: state.path }),
  };
}

// DEC-262 (a24) Q3, (a25): Secret Service is a named gap on Linux, and the check
// is reported on every platform in its fixed place. It is `skipped`, ADR 0007's
// "reported, not failed" value for something absent here: `not_implemented` on
// Linux, `not_applicable` elsewhere.
function secretServiceCheck(linux: boolean): DoctorCheck {
  return {
    check: "secret_service",
    status: "skipped",
    code: linux ? "not_implemented" : "not_applicable",
  };
}

// Every versioned document this build reads: the project manifest, the vault
// record's header, and the decrypted state document. A definite violation is
// reported by name; a document that could not be read at all is a failure
// too, with the blocking reason as its code, because "not checked" must not
// look like "checked and fine".
function schemaCheck(
  manifest: ManifestObservation,
  vault: VaultObservation,
  key: KeyObservation | undefined,
  state: StateObservation | undefined,
): DoctorCheck {
  const check = "schema" as const;
  switch (manifest.status) {
    case "malformed":
      return { check, status: "fail", code: "manifest_malformed" };
    case "unsupported":
      return { check, status: "fail", code: "manifest_unsupported" };
    case "unreadable":
    case "unsafe":
      return { check, status: "fail", code: "manifest_unreadable" };
    case "present":
    case "absent":
      break;
  }
  switch (vault.status) {
    case "unrecognized":
      return { check, status: "fail", code: "vault_unrecognized" };
    case "unsupported":
      return { check, status: "fail", code: "vault_unsupported" };
    case "malformed":
      return { check, status: "fail", code: "vault_malformed" };
    case "insecure":
    case "busy":
    case "unreadable":
      return { check, status: "fail", code: `vault_${vault.status}` };
    case "present":
    case "absent":
      break;
  }
  if (vault.status === "present") {
    if (state === undefined) {
      const reason =
        key === undefined
          ? "state_unreadable"
          : `key_${reportedKeyStatus(key)}`;
      return { check, status: "fail", code: reason };
    }
    switch (state.status) {
      case "malformed":
        return { check, status: "fail", code: "state_malformed" };
      // The sealed envelope's header names a format this build cannot read.
      // Keyed to the vault rather than to the state document, which is why it
      // is not `state_malformed`: there was no document to parse.
      case "unsupported":
        return { check, status: "fail", code: "state_unsupported" };
      case "unauthenticated":
        return { check, status: "fail", code: "vault_unauthenticated" };
      case "unreadable":
        return { check, status: "fail", code: "state_unreadable" };
      case "busy":
        return { check, status: "fail", code: "state_busy" };
      case "present":
        break;
    }
  }
  if (manifest.status === "absent" && vault.status === "absent")
    return { check, status: "skipped", code: "absent" };
  return { check, status: "pass", code: "current" };
}

// Whether this checkout's claim (the manifest) and its authority (the vault
// binding for this root) agree. A registered checkout whose manifest was
// replaced is a conflict, decided without naming the bound project; an
// unregistered one is the state a fresh clone is in until a developer runs
// `ward init`, which is what this check exists to surface.
function bindingCheck(
  manifest: ManifestObservation,
  vault: VaultObservation,
  key: KeyObservation | undefined,
  state: StateObservation | undefined,
  checkout: CheckoutIdentity,
): DoctorCheck {
  const check = "binding" as const;
  switch (manifest.status) {
    case "absent":
      return { check, status: "skipped", code: "manifest_absent" };
    case "malformed":
    case "unsupported":
    case "unreadable":
    case "unsafe":
      // A manifest that exists but cannot be judged is a failure, not an
      // absence: the checkout claims integration and the claim is wrong or
      // unreadable. Only the manifest's actual absence is a skip.
      return { check, status: "fail", code: `manifest_${manifest.status}` };
    case "present":
      break;
  }
  if (vault.status === "absent")
    return { check, status: "skipped", code: "vault_absent" };
  if (vault.status !== "present")
    return { check, status: "fail", code: `vault_${vault.status}` };
  if (state === undefined) {
    const reason =
      key === undefined ? "state_unreadable" : `key_${reportedKeyStatus(key)}`;
    return { check, status: "fail", code: reason };
  }
  if (state.status !== "present")
    return { check, status: "fail", code: `state_${state.status}` };
  const binding = findBinding(state.state, checkout);
  if (binding === undefined)
    return { check, status: "fail", code: "unregistered" };
  if (binding.projectId !== manifest.projectId)
    return { check, status: "fail", code: "conflict" };
  return { check, status: "pass", code: "registered" };
}

// A stored approval this build cannot read is a finding rather than a fault
// in the vault: the document parsed, the record authorises nothing, and the
// developer clears it by re-approving the profile (DEC-246 a2). It fails the
// doctor only when that is actually possible — a record nothing can reach is
// named as inert and does not fail (DEC-246 a3 Q2), because a permanent exit 6
// naming a step that cannot be carried out is not a finding a developer can
// act on.
//
// A check that could not be evaluated fails with the blocking reason as its
// code, exactly as `binding` does. `skipped` is reserved for the subject not
// existing here, and this report being unable to look is not that: reading it
// as healthy would tell a developer their approvals are current when Ward
// never got to count them.
function staleApprovalsCheck(
  vault: VaultObservation,
  key: KeyObservation | undefined,
  state: StateObservation | undefined,
  manifest: ManifestObservation,
  checkouts: StaleCheckoutProbe,
): DoctorCheck {
  const check = "stale_approvals" as const;
  if (vault.status === "absent")
    return { check, status: "skipped", code: "vault_absent" };
  if (vault.status !== "present")
    return { check, status: "fail", code: `vault_${vault.status}` };
  if (state === undefined) {
    const reason =
      key === undefined ? "state_unreadable" : `key_${reportedKeyStatus(key)}`;
    return { check, status: "fail", code: reason };
  }
  if (state.status !== "present")
    return { check, status: "fail", code: `state_${state.status}` };
  const stale = staleApprovals(state, currentProject(manifest), checkouts);
  const named = stale.named;
  if (named.length === 0 && stale.otherProjects === 0)
    return { check, status: "pass", code: "current" };
  const reported = {
    check,
    staleApprovals: named,
    otherProjectStaleApprovals: stale.otherProjects,
  };
  if (named.some((entry) => entry.clearable))
    return { ...reported, status: "fail", code: "reapprove_required" };
  // Nothing here can be cleared. A count of other projects' records alone is
  // not a finding about this one, so it gets its own code rather than reading
  // as records this checkout is merely declining to act on.
  return {
    ...reported,
    status: "pass",
    code: named.length === 0 ? "other_projects" : "inert",
  };
}

const instructionTargets: readonly AgentTarget[] = ["claude", "codex"];

function instructionState(
  files: ProjectFiles,
  target: AgentTarget,
): InstructionState {
  let text: string | undefined;
  try {
    text = files.read(agentTargetDocuments[target]);
  } catch (error) {
    switch (wardCode(error)) {
      case "project_path_unsafe":
        return "unsafe";
      case "project_file_unwritable":
        return "unreadable";
      default:
        throw error;
    }
  }
  if (text === undefined) return "absent";
  try {
    return managedBlockStatus(text, wardBlockBody);
  } catch (error) {
    if (wardCode(error) === "instructions_markers_conflict") return "malformed";
    throw error;
  }
}

function unhealthy(state: InstructionState): boolean {
  return (
    state === "stale" ||
    state === "malformed" ||
    state === "unreadable" ||
    state === "unsafe"
  );
}

// The blocks Ward installed, per host, judged by the same marker grammar the
// writer uses. A block this build did not write — an older body, or markers
// it would refuse — is a failure; a host with no block at all is reported
// and skipped, because bridge selection is optional (init may run without
// `--claude`/`--codex`) and judging absence for a named target is
// `ward agents --check` (WCLI-14), not this check.
function instructionsCheck(files: ProjectFiles): DoctorCheck {
  const check = "instructions" as const;
  const documents: Record<AgentTarget, InstructionState> = {
    claude: instructionState(files, "claude"),
    codex: instructionState(files, "codex"),
  };
  const failing = instructionTargets.filter((target) =>
    unhealthy(documents[target]),
  );
  const first = failing[0];
  if (first !== undefined)
    return { check, status: "fail", code: documents[first], documents };
  if (documents.claude === "current" || documents.codex === "current")
    return { check, status: "pass", code: "current", documents };
  return { check, status: "skipped", code: "absent", documents };
}

// What a key_provider failure adds beneath its line, in the same fields the
// JSON carries, so the reason, the path and the stores are as visible in
// human output as in JSON (DEC-262 a19, a24).
// The recovery step a failed key check adds in human output only. Ambiguity
// carries the catalog's recovery wording; a TPM state carries its own hint.
function keyRecoveryHint(key: KeyObservation | undefined): string | undefined {
  if (key?.status === "ambiguous") return errorCatalog.vault_key_ambiguous.hint;
  if (key?.status !== "unavailable" || key.refusal === undefined)
    return undefined;
  // key_unloadable carries its own hint; every other state falls back to the
  // catalog's recovery wording for its code (key_incomplete's "do not run
  // setup" is written there).
  return key.refusal.hint ?? catalogEntry(key.refusal.code).hint;
}

function keyDetailLines(check: DoctorCheck, hint?: string): string[] {
  const lines: string[] = [];
  if (check.reason !== undefined) lines.push(`    reason: ${check.reason}`);
  if (check.path !== undefined)
    lines.push(`    path: ${escapeForDisplay(check.path)}`);
  if (check.version !== undefined)
    lines.push(`    version: ${escapeForDisplay(check.version)}`);
  if (check.stores !== undefined && check.stores.length > 0)
    lines.push(`    stores: ${check.stores.join(", ")}`);
  if (hint !== undefined) lines.push(`    ${hint}`);
  return lines;
}

function doctorText(report: DoctorReport, keyHint: string | undefined): string {
  const lines = report.checks.flatMap((check) => {
    const documents =
      check.documents === undefined
        ? ""
        : ` (claude: ${check.documents.claude}, codex: ${check.documents.codex})`;
    return [
      `  ${check.check.padEnd(16)}${check.status.padEnd(8)}${check.code}${documents}`,
      ...keyDetailLines(
        check,
        check.check === "key_provider" ? keyHint : undefined,
      ),
      ...staleApprovalLines(
        check.staleApprovals ?? [],
        check.otherProjectStaleApprovals ?? 0,
      ),
    ];
  });
  const failed = report.checks
    .filter((check) => check.status === "fail")
    .map((check) => check.check);
  const verdict =
    failed.length === 0
      ? "Every check passed."
      : `Failed: ${failed.join(", ")}.`;
  return [
    "Ward doctor",
    "",
    ...lines,
    "",
    verdict,
    "Ward read this state; it did not change anything.",
  ].join("\n");
}

export interface DoctorResult {
  readonly data: DoctorReport;
  readonly text: string;
  // 6 when a check failed (spec §8's validation exit), 0 otherwise.
  readonly exitCode: ExitCode;
}

export async function runDoctor(
  options: ReportingOptions,
): Promise<DoctorResult> {
  const observation = await observe(options);
  const checks: DoctorCheck[] = [
    permissionsCheck(observation.vault),
    keyCheck(observation.vault, observation.key),
    schemaCheck(
      observation.manifest,
      observation.vault,
      observation.key,
      observation.state,
    ),
    bindingCheck(
      observation.manifest,
      observation.vault,
      observation.key,
      observation.state,
      options.checkout,
    ),
    staleApprovalsCheck(
      observation.vault,
      observation.key,
      observation.state,
      observation.manifest,
      options.checkouts,
    ),
    instructionsCheck(options.files),
    // DEC-262 (a25, a26): fixed order, every platform: the six, tpm2, then
    // secret_service.
    await tpm2Check(options, observation.vault),
    secretServiceCheck(onLinux(options)),
  ];
  const ok = checks.every((check) => check.status !== "fail");
  const data: DoctorReport = { ok, checks };
  return {
    data,
    text: doctorText(data, keyRecoveryHint(observation.key)),
    exitCode: ok ? exitCodes.success : exitCodes.validation,
  };
}
