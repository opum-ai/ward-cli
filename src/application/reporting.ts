// `ward status` and `ward doctor` (spec §8): the two read-only reports over
// the state every other command acts on. Status answers what this checkout
// and its backend look like right now; doctor runs the same observation as
// five named checks and exits 6 when one of them is wrong. They share this
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
import { WardError } from "../contract/errors.ts";
import type { AgentTarget } from "../contract/manifest.ts";
import { managedBlockStatus } from "../domain/managed-block.ts";
import { parseProjectManifest } from "../domain/project-manifest.ts";
import {
  type CheckoutIdentity,
  findBinding,
  parseVaultState,
  type VaultState,
} from "../domain/vault-state.ts";
import { agentTargetDocuments, wardBlockBody } from "./bridges.ts";
import type { KeyProvider } from "./key-provider.ts";
import type { ProjectFiles } from "./project-files.ts";
import type { VaultStore } from "./vault-store.ts";

export interface ReportingOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
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
  | { status: "unavailable" }
  | { status: "invalid" }
  | { status: "unsupported" };

// `unsupported` is not about the document's own version, which now has a
// single format and answers `malformed` when it is not this build's (DEC-38).
// It is the *other* raiser of `vault_format_unsupported` reaching this read: a
// stored profile approval whose `snapshotVersion` this build does not
// implement. That record sits inside an otherwise-readable document, so the
// document is not malformed — and because it is reachable, this status is what
// keeps the two reports answering rather than throwing (WCLI-51 review, F1).
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

async function observeKey(
  keyProvider: KeyProvider,
  vaultId: string,
): Promise<KeyObservation> {
  try {
    return { status: "present", key: await keyProvider.load(vaultId) };
  } catch (error) {
    switch (wardCode(error)) {
      case "vault_key_missing":
        return { status: "missing" };
      case "vault_key_unavailable":
        return { status: "unavailable" };
      case "vault_key_invalid":
        return { status: "invalid" };
      case "vault_key_store_unsupported":
        return { status: "unsupported" };
      default:
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
      // Still reachable after DEC-38, and this case is the whole reason the
      // status survives: parseVaultState raises this code for a stored
      // approval's snapshotVersion even though it no longer raises it for the
      // document's own version. Dropping this case makes both reports throw
      // out of their read instead of answering.
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
  const key = await observeKey(options.keyProvider, vault.vaultId);
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
export interface StaleApprovalReport {
  readonly profile: string;
  readonly projectId: string;
  readonly checkout: string;
  readonly snapshotVersion: number;
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
  };
  // Empty rather than absent when there are none, so a caller can tell "none"
  // from "this report does not say".
  readonly staleApprovals: readonly StaleApprovalReport[];
}

function staleApprovalReports(
  state: StateObservation | undefined,
): readonly StaleApprovalReport[] {
  if (state === undefined || state.status !== "present") return [];
  return state.state.staleProfileApprovals.map(
    ({ profile, projectId, root, snapshotVersion }) => ({
      profile,
      projectId,
      checkout: root,
      snapshotVersion,
    }),
  );
}

function staleApprovalLines(
  approvals: readonly StaleApprovalReport[],
): readonly string[] {
  if (approvals.length === 0) return [];
  return [
    `  stale approvals: ${approvals.length} (written by another build; they authorise nothing)`,
    ...approvals.map(
      (entry) =>
        `    - ${entry.profile} at ${entry.checkout}, snapshot version ${entry.snapshotVersion}: re-approve in a trusted terminal with ward profile approve ${entry.profile}`,
    ),
  ];
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
    ...staleApprovalLines(report.staleApprovals),
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
    keyProvider: { status: key === undefined ? "unchecked" : key.status },
    staleApprovals: staleApprovalReports(observation.state),
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
  | "instructions";

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
  // Named individually rather than counted, because the re-approve step is
  // per profile and per checkout (DEC-246 a2 clause 2).
  readonly staleApprovals?: readonly StaleApprovalReport[];
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
  switch (key.status) {
    case "present":
      return { check, status: "pass", code: "present" };
    case "missing":
      return { check, status: "fail", code: "missing" };
    case "unavailable":
      return { check, status: "fail", code: "unavailable" };
    case "invalid":
      return { check, status: "fail", code: "invalid" };
    case "unsupported":
      return { check, status: "fail", code: "unsupported" };
  }
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
        key === undefined ? "state_unreadable" : `key_${key.status}`;
      return { check, status: "fail", code: reason };
    }
    switch (state.status) {
      case "malformed":
        return { check, status: "fail", code: "state_malformed" };
      // A stored approval this build cannot read. Keyed to the record rather
      // than to the document, which is why it is not `state_malformed`: the
      // document parsed, and one record in it did not (WCLI-51 review, F1).
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
    const reason = key === undefined ? "state_unreadable" : `key_${key.status}`;
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
// developer clears it by re-approving the profile (DEC-246 a2). It is a
// failure rather than a pass because "approved" is exactly what the operator
// would otherwise assume, and the exit code is how that assumption gets
// corrected without reading prose.
function staleApprovalsCheck(
  vault: VaultObservation,
  key: KeyObservation | undefined,
  state: StateObservation | undefined,
): DoctorCheck {
  const check = "stale_approvals" as const;
  if (vault.status === "absent")
    return { check, status: "skipped", code: "vault_absent" };
  if (vault.status !== "present")
    return { check, status: "skipped", code: `vault_${vault.status}` };
  if (state === undefined)
    return {
      check,
      status: "skipped",
      code: key === undefined ? "state_unreadable" : `key_${key.status}`,
    };
  if (state.status !== "present")
    return { check, status: "skipped", code: `state_${state.status}` };
  const stale = staleApprovalReports(state);
  if (stale.length === 0) return { check, status: "pass", code: "current" };
  return {
    check,
    status: "fail",
    code: "reapprove_required",
    staleApprovals: stale,
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

function doctorText(report: DoctorReport): string {
  const lines = report.checks.flatMap((check) => {
    const documents =
      check.documents === undefined
        ? ""
        : ` (claude: ${check.documents.claude}, codex: ${check.documents.codex})`;
    return [
      `  ${check.check.padEnd(16)}${check.status.padEnd(8)}${check.code}${documents}`,
      ...staleApprovalLines(check.staleApprovals ?? []),
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
    staleApprovalsCheck(observation.vault, observation.key, observation.state),
    instructionsCheck(options.files),
  ];
  const ok = checks.every((check) => check.status !== "fail");
  const data: DoctorReport = { ok, checks };
  return {
    data,
    text: doctorText(data),
    exitCode: ok ? exitCodes.success : exitCodes.validation,
  };
}
