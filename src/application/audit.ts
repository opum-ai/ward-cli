// `ward audit` (spec §8, §9.4): this project's retained operational events,
// and the retention bound stated rather than left for a reader to discover.
//
// Three properties, and each is a decision rather than a consequence:
//
// - Only this project. The binding decides which project this checkout is,
//   exactly as it does for `ward run` and `ward secret`, and the records are
//   filtered to it. Another project's events are not shown, not counted and
//   not summarised (spec §8's "no global inventory").
// - Nothing outside the record. An audit record's fields are Ward-owned
//   identifiers, a closed phase and outcome, a profile name and a timestamp
//   (domain/vault-state.ts), and this report renders them as stored. There
//   are no free-text fields and no value fields, so there is nothing here a
//   caller could smuggle a secret through, and this module reads no secret
//   and no key material beyond the vault key.
// - Read-only. Every fact comes from a project file read, `store.header`,
//   `keyProvider.load` and `store.read`; nothing here can write.
//
// This command refuses rather than reporting a status the way `ward status`
// and `ward doctor` do (application/reporting.ts): an absence of a vault or
// a binding here would make "no events" and "no way to read events" print
// the same answer, and an agent reading it could not tell which it had. The
// refusal path is application/run.ts's, so the same condition produces the
// same error code in both commands.
import { WardError } from "../contract/errors.ts";
import {
  type AuditRecord,
  auditHistoryLimit,
  type CheckoutIdentity,
  findBinding,
  parseVaultState,
  type VaultState,
} from "../domain/vault-state.ts";
import type { KeyProvider } from "./key-provider.ts";
import { type Checkout, readCheckout } from "./project.ts";
import type { ProjectFiles } from "./project-files.ts";
import type { VaultStore } from "./vault-store.ts";

export interface AuditOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
}

// What the vault's retention actually is, carried into the report instead of
// left for a reader to find in the source (spec §9.4).
//
// The bound is a vault-wide number, not a per-project one: auditHistoryLimit
// counts every project's events together and drops the oldest first, so the
// number of events a project can still read depends on how much other
// projects have run. Stating the bound alone would let a reader take 500 as
// a guarantee about this project, and stating a per-project number alone
// would be a quantity rather than a bound — so the report states both, and
// the pairing is the honest answer rather than a choice between them.
export interface RetentionStatement {
  readonly bound: number;
  readonly scope: "vault";
  readonly eviction: "oldest-first";
  readonly retainedForProject: number;
}

export interface AuditReport {
  readonly projectId: string;
  readonly events: readonly AuditRecord[];
  readonly retention: RetentionStatement;
}

export interface AuditResult {
  readonly data: AuditReport;
  readonly text: string;
}

// The manifest's project and the vault's binding must agree, and the binding
// is what decides which project's events this checkout may read. A missing
// manifest and a missing binding are the same answer: this checkout is not
// registered. A binding for a project the manifest does not name is a
// conflict, and the other project is not named.
function boundProject(checkout: Checkout, state: VaultState): string {
  const manifest = checkout.manifest;
  if (manifest === undefined) throw new WardError("project_not_registered");
  const binding = findBinding(state, checkout.identity);
  if (binding === undefined) throw new WardError("project_not_registered");
  if (binding.projectId !== manifest.projectId)
    throw new WardError("binding_conflict");
  return binding.projectId;
}

// One event, as stored. Every field is printed; nothing is truncated and
// nothing is summarised, because a summarised audit line is a claim about
// what was dropped.
function eventLine(event: AuditRecord): string {
  const outcome = event.outcome ?? "-";
  return `${event.at}  ${event.phase}  ${outcome}  ${event.profile}  run ${event.runId}  secret ${event.secretId}`;
}

function auditText(report: AuditReport): string {
  const lines = [
    "Ward audit",
    "",
    `  project:        ${report.projectId}`,
    `  retained here:  ${report.retention.retainedForProject}`,
  ];
  if (report.events.length === 0) {
    lines.push("", "  No events are retained for this project.");
  } else {
    // Oldest first, which is the order the vault stores them in.
    lines.push("", ...report.events.map((event) => `  ${eventLine(event)}`));
  }
  lines.push(
    "",
    `  This vault keeps at most ${report.retention.bound} events in total, across all`,
    "  projects, and drops the oldest first, so another project's activity can",
    "  shorten this project's retained history.",
    "",
    "Ward read this state; it did not change anything.",
  );
  return lines.join("\n");
}

export async function runAudit(options: AuditOptions): Promise<AuditResult> {
  const checkout = readCheckout(options.checkout, options.files);
  const header = options.store.header();
  if (header === undefined) throw new WardError("vault_not_found");
  const key = await options.keyProvider.load(header.vaultId);
  let state: VaultState;
  try {
    const snapshot = options.store.read(key);
    try {
      state = parseVaultState(snapshot.plaintext);
    } finally {
      // The plaintext holds identifiers and timestamps, and nothing below
      // can render it once it has been parsed into the state.
      snapshot.plaintext.fill(0);
    }
  } finally {
    // The key is not needed past this point, on any path out.
    key.fill(0);
  }
  const projectId = boundProject(checkout, state);
  const events = state.auditRecords.filter(
    (record) => record.projectId === projectId,
  );
  const data: AuditReport = {
    projectId,
    events,
    retention: {
      bound: auditHistoryLimit,
      scope: "vault",
      eviction: "oldest-first",
      retainedForProject: events.length,
    },
  };
  return { data, text: auditText(data) };
}
