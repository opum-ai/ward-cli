// `ward run`: execute the operation this checkout approved (spec §9.2-§9.4,
// docs/adr/0003).
//
// The rule this file implements, and the one thing to read it for: **the
// approved snapshot is what runs, and the declaration is only what has to
// agree with it.** A manifest is a tracked file anyone who can edit the
// repository can change, so it is a request; the snapshot in the encrypted
// vault is the authority. The declared profile is normalized and compared
// against the snapshot first — spec §9.2's "at execution, the declared
// profile must match the approved snapshot" — and then every part of the
// request is built from `approval.snapshot`: its URL, its method, its
// headers, its alias. That the two are equal at that point is a consequence
// of the comparison, not the reason for building from the snapshot: a later
// change that weakened the comparison would otherwise silently widen what
// runs, and building from the authority means it could not.
//
// The run is two transactions with a gap between them, and the gap is the
// point (spec §9.4): admission is persisted *before* a credential is
// delivered, so a run whose admission cannot be written does not happen at
// all, and completion is persisted after, in its own transaction, because
// holding the vault's write lock across network I/O is exactly what spec
// §9.4 forbids. Admission re-reads the approval and the secret inside its own
// transaction, which is where revocation's admission-time semantics live: a
// revocation that lands before this run is admitted blocks it, and one that
// lands afterwards cannot recall what has already been sent (docs/adr/0003).
//
// The credential is bytes from the vault to the socket and is never a string
// on the way (domain/authorization.ts, application/transport.ts). It is
// decoded once, assembled into one header, handed to the transport, and
// zeroed in a `finally` on every path out — including the paths that throw,
// which is when it would otherwise be easiest to leave behind.

import type { ExitCode, ResultKind } from "../contract/envelope.ts";
import { exitCodes } from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import { authorizationHeader } from "../domain/authorization.ts";
import {
  isProfileName,
  normalizeProfile,
  type NormalizedProfile,
  profilesMatch,
} from "../domain/profile.ts";
import {
  decodeSecretValue,
  isSecretAlias,
  type SecretRecord,
} from "../domain/secret.ts";
import {
  type AuditOutcome,
  type AuditRecord,
  type CheckoutIdentity,
  findProfileApproval,
  type ObservedMachine,
  parseVaultState,
  resolveSecret,
  serializeVaultState,
  type VaultState,
  withAuditRecord,
} from "../domain/vault-state.ts";
import { boundProject, requireBinding, requireManifest } from "./binding.ts";
import type { KeyProvider } from "./key-provider.ts";
import { type Checkout, readCheckout } from "./project.ts";
import type { ProjectFiles } from "./project-files.ts";
import type { Transport, TransportRequest } from "./transport.ts";
import type { VaultStore } from "./vault-store.ts";

export interface RunCommandInput {
  readonly profile: string | undefined;
  // `--actor-label` and `--task-label`: what the caller says about who it is
  // and what it is doing, recorded on the run's events as self-asserted
  // (spec §4.2, §12). They are correlation metadata and never authorization —
  // nothing in Ward reads them back — and `undefined` means the caller
  // asserted nothing, which is recorded as absence rather than as a value.
  readonly actorLabel: string | undefined;
  readonly taskLabel: string | undefined;
}

export interface OperationOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
  readonly transport: Transport;
  readonly now: () => Date;
  // `crypto.randomUUID`, supplied by the caller rather than imported here, so
  // this layer keeps no dependency a caller cannot replace and a test can
  // predict the identifiers it asserts on.
  readonly newId: () => string;
  // What the OS says about this process's user and host, supplied for the same
  // reason and read once per run so both of a run's events carry one identity.
  readonly observeMachine: () => ObservedMachine | null;
}

export interface OperationResult {
  readonly kind: ResultKind;
  readonly data: Record<string, unknown>;
  readonly text: string;
  readonly exitCode?: ExitCode;
}

interface OpenedVault {
  readonly checkout: Checkout;
  readonly key: Uint8Array;
  readonly state: VaultState;
}

async function withOpenVault<T>(
  options: OperationOptions,
  run: (opened: OpenedVault) => Promise<T>,
): Promise<T> {
  const checkout = readCheckout(options.checkout, options.files);
  requireManifest(checkout);
  const header = options.store.header();
  if (header === undefined) throw new WardError("vault_not_found");
  const key = await options.keyProvider.load(header.vaultId);
  try {
    const snapshot = options.store.read(key);
    let state: VaultState;
    try {
      state = parseVaultState(snapshot.plaintext);
    } finally {
      snapshot.plaintext.fill(0);
    }
    return await run({ checkout, key, state });
  } finally {
    key.fill(0);
  }
}

// Every reason the transport gives for not having sent anything, as the code
// the caller sees. A fixed name rather than a message: spec §9.4 keeps a
// run's output to Ward-owned values, and an upstream message is not one.
const notSentCodes = {
  "destination-not-public": "run_destination_refused",
  "destination-unresolved": "run_destination_unresolved",
  "connection-failed": "run_connection_failed",
  "tls-failed": "run_tls_failed",
  "request-invalid": "run_request_invalid",
} as const;

// The approved operation, or the reason there is not one to run. The
// declaration is normalized and compared here and is not returned: what the
// caller goes on to execute is the snapshot.
function approvedSnapshot(options: {
  state: VaultState;
  identity: CheckoutIdentity;
  projectId: string;
  name: string;
  declared: unknown;
}): NormalizedProfile {
  const declared = normalizeProfile(options.declared);
  const approval = findProfileApproval(
    options.state,
    options.identity,
    options.projectId,
    options.name,
  );
  if (approval === undefined) throw new WardError("profile_not_approved");
  if (!profilesMatch(declared, approval.snapshot))
    throw new WardError("profile_approval_stale");
  return approval.snapshot;
}

// The secret an alias resolves to inside this project, or the fixed refusal.
// One function for the pre-read and the admission transaction, so the two
// cannot disagree about what a granted, revoked or missing alias is. A revoked
// grant and a deleted owner secret are the same refusal: either way the alias
// no longer reaches a secret this project may use (spec §7.2).
function usableSecret(
  state: VaultState,
  projectId: string,
  alias: string,
): SecretRecord {
  const resolved = resolveSecret(state, projectId, alias);
  if (resolved.kind === "owned" || resolved.kind === "granted")
    return resolved.secret;
  throw new WardError(
    resolved.kind === "revoked" ? "grant_revoked" : "secret_not_found",
  );
}

// Writes one audit event, re-reading the state inside the transaction. What
// is re-checked there is re-checked because it is the authority this run is
// about to act on and another Ward process may have changed it since the
// read above: the binding still names this project, the profile is still
// approved for this binding, and — at admission — that approval still *is*
// the snapshot about to be executed. The last of those is passed in rather
// than re-read, because the snapshot and the credential were both read before
// this transaction opened: without the comparison, a re-approval landing in
// that window would send the superseded operation while the vault's
// authoritative record described a different one, and both audit records
// would describe the newer state (WCLI-10 review, F2). Spec §9.4's
// "pre-delivery audit failure blocks execution" is this call throwing —
// admission has not delivered anything yet, so blocking is still possible
// there, and is not afterwards.
function writeAudit(options: {
  store: VaultStore;
  key: Uint8Array;
  identity: CheckoutIdentity;
  projectId: string;
  profile: string;
  alias: string;
  phase: AuditRecord["phase"];
  outcome: AuditOutcome | null;
  runId: string;
  at: string;
  machine: ObservedMachine | null;
  actorLabel: string | null;
  taskLabel: string | null;
  newId: () => string;
  // Present at admission only: what this run is about to execute, and the
  // credential it is about to deliver.
  executing?: NormalizedProfile;
  executingSecret?: { readonly id: string; readonly revision: number };
  // Present at completion only: the secret the admission recorded. A run that
  // was admitted may finish (spec §7.2), so completion is not a second
  // admission and does not resolve the alias again — a grant revoked or an
  // owner secret deleted while the request was in flight must not turn a
  // request that was sent into a run Ward cannot account for.
  completingSecretId?: string;
}): void {
  options.store.mutate(options.key, (plaintext) => {
    const state = parseVaultState(plaintext);
    requireBinding(state, options.identity, options.projectId);
    // The approval must still be there, and must still be this declaration's,
    // at the moment the run is admitted.
    const approval = findProfileApproval(
      state,
      options.identity,
      options.projectId,
      options.profile,
    );
    if (approval === undefined) throw new WardError("profile_not_approved");
    if (
      options.executing !== undefined &&
      !profilesMatch(options.executing, approval.snapshot)
    )
      throw new WardError("profile_approval_stale");
    // The grant (if the alias is granted) and the owner record are read here,
    // in this one transaction, and both must still hold: the alias resolves
    // through an active grant to an existing owner secret, or to this
    // project's own. A revocation or owner deletion that landed first blocks
    // the run before anything is sent.
    const secret =
      options.completingSecretId === undefined
        ? usableSecret(state, options.projectId, options.alias)
        : undefined;
    const secretId = secret?.id ?? options.completingSecretId;
    if (secretId === undefined) throw new WardError("uncaught");
    // The credential's bytes were decoded before this transaction opened, so
    // its revision is what says the value about to be delivered is still the
    // value the vault holds. Without this, a rotation landing in that window
    // sends the superseded credential to the approved endpoint while the
    // vault holds the replacement — and the two audit records cannot show it,
    // because a rotation keeps the record's id (WCLI-10 review, F2).
    if (
      options.executingSecret !== undefined &&
      secret !== undefined &&
      (secret.id !== options.executingSecret.id ||
        secret.revision !== options.executingSecret.revision)
    )
      throw new WardError("secret_changed");
    const record: AuditRecord = {
      id: options.newId(),
      runId: options.runId,
      projectId: options.projectId,
      profile: options.profile,
      secretId,
      phase: options.phase,
      outcome: options.outcome,
      at: options.at,
      machine: options.machine,
      actorLabel: options.actorLabel,
      taskLabel: options.taskLabel,
    };
    return serializeVaultState(withAuditRecord(state, record));
  });
}

// A response is a completed operation; whether the operation *succeeded* is
// what its status says. Ward's own enum, and only Ward's: no status text, no
// header and no body byte reaches this.
function outcomeForResponse(httpStatus: number): AuditOutcome {
  return httpStatus >= 200 && httpStatus < 300 ? "succeeded" : "failed";
}

function resultText(options: {
  profile: string;
  projectId: string;
  outcome: AuditOutcome;
  httpStatus: number | null;
  auditRecorded: boolean;
}): string {
  const lines = [
    `Run ${options.outcome}.`,
    "",
    `  profile:   ${options.profile}`,
    `  project:   ${options.projectId}`,
    `  outcome:   ${options.outcome}`,
  ];
  if (options.httpStatus !== null)
    lines.push(`  status:    ${options.httpStatus}`);
  if (options.outcome === "indeterminate")
    lines.push(
      "",
      "Ward sent the request and did not receive an answer it could read. It",
      "cannot say whether the server applied the operation, and it did not",
      "send it again.",
    );
  if (!options.auditRecorded)
    lines.push(
      "",
      "Ward could not record this run's completion in the vault. The record of",
      "the admission is there; this one is not.",
    );
  return lines.join("\n");
}

// A self-asserted label as an audit record carries it: the caller's value, or
// null when it asserted none. The grammar is the alias grammar (WCLI-11), and
// a value outside it is refused rather than recorded — a label is a name Ward
// carries into a record and prints, and one this build will not write is not
// one it should accept and then quietly drop.
function assertedLabel(value: string | undefined): string | null {
  if (value === undefined) return null;
  if (!isSecretAlias(value)) throw new WardError("run_label_invalid");
  return value;
}

export async function runOperation(
  input: RunCommandInput,
  options: OperationOptions,
): Promise<OperationResult> {
  const name = input.profile;
  if (name === undefined) throw new WardError("missing_argument");
  if (!isProfileName(name)) throw new WardError("profile_name_invalid");
  // A label this build would not record is a usage fault, and answering it
  // must not cost a credential-store read or a key prompt, so it is refused
  // here rather than inside the vault.
  const actorLabel = assertedLabel(input.actorLabel);
  const taskLabel = assertedLabel(input.taskLabel);
  // Observed once, before either event is written, so the admission and the
  // completion describe the same run on the same machine.
  const machine = options.observeMachine();

  return withOpenVault(options, async ({ checkout, key, state }) => {
    const manifest = requireManifest(checkout);
    if (!Object.hasOwn(manifest.profiles, name))
      throw new WardError("profile_not_found");
    const projectId = boundProject(checkout, state);
    const snapshot = approvedSnapshot({
      state,
      identity: options.checkout,
      projectId,
      name,
      declared: manifest.profiles[name],
    });

    // Declared above and refused here rather than at approval time, because
    // the approval is of the operation and the body policy is part of it.
    // This build sends no body at all; a profile approved to send one is
    // refused rather than run without it, since an endpoint expecting a body
    // and given none is a different operation from the approved one.
    if (snapshot.requestBody !== "none")
      throw new WardError("run_body_unsupported");

    const secret = usableSecret(state, projectId, snapshot.auth.secret);
    const value = decodeSecretValue(secret.value);
    if (value === undefined) throw new WardError("vault_state_malformed");

    const runId = options.newId();
    try {
      const authorization = authorizationHeader(snapshot.auth, value);
      try {
        const request: TransportRequest = {
          // Every field here is the approved snapshot's. The declaration was
          // compared against it, never substituted for it.
          url: snapshot.url,
          method: snapshot.method,
          headers: snapshot.headers,
          authorization,
          body: undefined,
        };

        // Admission, before anything is sent.
        writeAudit({
          store: options.store,
          key,
          identity: options.checkout,
          projectId,
          profile: name,
          alias: snapshot.auth.secret,
          phase: "admission",
          outcome: null,
          runId,
          at: options.now().toISOString(),
          machine,
          actorLabel,
          taskLabel,
          newId: options.newId,
          executing: snapshot,
          executingSecret: { id: secret.id, revision: secret.revision },
        });

        const sent = await options.transport.send(request);
        const outcome: AuditOutcome =
          sent.kind === "response"
            ? outcomeForResponse(sent.httpStatus)
            : sent.kind === "indeterminate"
              ? "indeterminate"
              : "failed";
        const httpStatus = sent.kind === "response" ? sent.httpStatus : null;

        // Completion, in its own transaction, with the outcome. A failure
        // here is reported rather than thrown: the operation has already
        // happened, and spec §9.4 requires this to be said honestly instead
        // of being allowed to look like the operation failed.
        let auditRecorded = true;
        try {
          writeAudit({
            store: options.store,
            key,
            identity: options.checkout,
            projectId,
            profile: name,
            alias: snapshot.auth.secret,
            phase: "completion",
            outcome,
            runId,
            at: options.now().toISOString(),
            machine,
            actorLabel,
            taskLabel,
            newId: options.newId,
            completingSecretId: secret.id,
          });
        } catch {
          auditRecorded = false;
        }

        // The transport's refusal to send is an error and not an outcome: no
        // operation was attempted, so there is no status to report and
        // nothing for the caller to read as one.
        if (sent.kind === "not-sent")
          throw new WardError(notSentCodes[sent.reason]);

        return {
          kind: "run.result" as const,
          data: {
            projectId,
            profile: name,
            runId,
            outcome,
            auditRecorded,
            ...(httpStatus === null ? {} : { httpStatus }),
          },
          text: resultText({
            profile: name,
            projectId,
            outcome,
            httpStatus,
            auditRecorded,
          }),
          exitCode:
            outcome === "indeterminate"
              ? exitCodes.indeterminate
              : outcome === "failed" || !auditRecorded
                ? exitCodes.validation
                : exitCodes.success,
        };
      } finally {
        authorization.value.fill(0);
      }
    } finally {
      value.fill(0);
    }
  });
}
