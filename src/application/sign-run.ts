// `ward sign <profile>`: sign the bytes on standard input with the key an
// approved sign profile names (DEC-262 (2), a3 (iii), a4; docs/adr/0027).
//
// The authority is the approved snapshot, never the manifest: the declaration
// is a request, and what authorises a signature is the stored approval that
// still matches it, is unexpired, and names a signing key this project owns.
// The bytes are signed exactly as given, and only if they begin with one of
// the approved domain prefixes. The private key is read inside this process,
// used once and zeroed, and appears in no result, error or audit record.
//
// A sign is audited like a run (spec §9.4): an admission event is written
// before anything is signed, and a completion event after, in their own
// transactions. The existing audit record fits as it is: `profile` is the sign
// profile, `secretId` is the key record's id, and the outcome is Ward's own
// enum. Nothing about the bytes or the signature is recorded.
import { type ExitCode, exitCodes } from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import {
  isProfileName,
  isSignSnapshot,
  type NormalizedSignProfile,
  normalizeSignProfile,
  approvedSnapshotsMatch,
  withSignKeyId,
} from "../domain/profile.ts";
import {
  decodeSecretValue,
  isSignKey,
  secretLimits,
} from "../domain/secret.ts";
import { startsWithAllowedPrefix } from "../domain/signing.ts";
import {
  type AuditOutcome,
  type AuditPhase,
  type AuditRecord,
  approvalExpired,
  type CheckoutIdentity,
  findProfileApproval,
  findSecret,
  type ObservedMachine,
  parseVaultState,
  serializeVaultState,
  type VaultState,
  withAuditRecord,
} from "../domain/vault-state.ts";
import { boundProject, requireBinding, requireManifest } from "./binding.ts";
import type { KeyProvider } from "./key-provider.ts";
import { readCheckout } from "./project.ts";
import type { ProjectFiles } from "./project-files.ts";
import { assertedLabel } from "./run.ts";
import { signWithKey } from "./sign.ts";
import type { VaultStore } from "./vault-store.ts";

// The most bytes one sign reads. A signature covers the bytes in one piece,
// so this bounds memory rather than limiting what a caller may sign; the same
// 64 KiB bound as a secret value.
export const signInputLimitBytes = secretLimits.maxValueBytes;

export interface SignCommandInput {
  readonly profile: string | undefined;
  readonly actorLabel: string | undefined;
  readonly taskLabel: string | undefined;
}

export interface SignOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
  readonly now: () => Date;
  readonly newId: () => string;
  readonly observeMachine: () => ObservedMachine | null;
  // Standard input to EOF as exact bytes, refusing a terminal and more than
  // the limit. The caller owns nothing: the buffer is zeroed here.
  readonly readInput: (maxBytes: number) => Uint8Array;
}

export interface SignResult {
  readonly kind: "sign.result";
  readonly data: Record<string, unknown>;
  // The 64-byte signature. The composition root decides how it is printed.
  readonly signature: Uint8Array;
  readonly text: string;
  readonly exitCode?: ExitCode;
  // Written to standard error. Set only when a signature exists but its
  // completion audit event could not be written (DEC-262 a7): the exit is
  // nonzero then, and this says why, so a caller cannot read the exit as an
  // unspecific failure or the raw signature on stdout as a clean success.
  readonly warning?: string;
}

// The approved sign snapshot, or the reason there is not one to act on. The
// declaration is normalized and compared and is not returned: what the caller
// goes on to use is the approval.
function approvedSignSnapshot(options: {
  now: Date;
  state: VaultState;
  identity: CheckoutIdentity;
  projectId: string;
  name: string;
  declared: unknown;
}): NormalizedSignProfile {
  const named = normalizeSignProfile(options.declared);
  // Compared against the key the alias resolves to now (DEC-262 a8).
  const current = findSecret(options.state, options.projectId, named.key);
  const declared = withSignKeyId(
    named,
    current !== undefined && isSignKey(current) ? current.id : undefined,
  ) as NormalizedSignProfile;
  const approval = findProfileApproval(
    options.state,
    options.identity,
    options.projectId,
    options.name,
  );
  if (approval === undefined) throw new WardError("profile_not_approved");
  const approved = approval.snapshot;
  if (!isSignSnapshot(approved) || !approvedSnapshotsMatch(declared, approved))
    throw new WardError("profile_approval_stale");
  if (approvalExpired(approval, options.now))
    throw new WardError("profile_approval_expired");
  return approved;
}

function writeSignAudit(options: {
  store: VaultStore;
  key: Uint8Array;
  identity: CheckoutIdentity;
  projectId: string;
  profile: string;
  phase: AuditPhase;
  outcome: AuditOutcome | null;
  runId: string;
  at: string;
  machine: ObservedMachine | null;
  actorLabel: string | null;
  taskLabel: string | null;
  newId: () => string;
  // At admission: what this sign is about to use. The approval and the key
  // are re-read inside the transaction, and an approval that changed, expired
  // or was revoked, or a key that was replaced, since the read blocks the sign.
  admitting?: {
    readonly snapshot: NormalizedSignProfile;
    readonly keyId: string;
    readonly keyRevision: number;
  };
  // At completion: the key the admission recorded.
  completingKeyId?: string;
}): void {
  options.store.mutate(options.key, (plaintext) => {
    const state = parseVaultState(plaintext);
    requireBinding(state, options.identity, options.projectId);
    let keyId = options.completingKeyId;
    if (options.admitting !== undefined) {
      const approval = findProfileApproval(
        state,
        options.identity,
        options.projectId,
        options.profile,
      );
      if (approval === undefined) throw new WardError("profile_not_approved");
      if (
        !isSignSnapshot(approval.snapshot) ||
        !approvedSnapshotsMatch(options.admitting.snapshot, approval.snapshot)
      )
        throw new WardError("profile_approval_stale");
      if (approvalExpired(approval, new Date(options.at)))
        throw new WardError("profile_approval_expired");
      const record = findSecret(
        state,
        options.projectId,
        options.admitting.snapshot.key,
      );
      if (record === undefined || !isSignKey(record))
        throw new WardError("sign_key_not_found");
      // The approval binds the key's id (DEC-262 a8): compared against the
      // pinned id, not against whatever the alias resolves to at this moment.
      if (record.id !== options.admitting.snapshot.keyId)
        throw new WardError("profile_approval_stale");
      // A key replaced between the read and here keeps the alias, so id and
      // revision are what say the key about to be used is the one read.
      if (
        record.id !== options.admitting.keyId ||
        record.revision !== options.admitting.keyRevision
      )
        throw new WardError("secret_changed");
      keyId = record.id;
    }
    if (keyId === undefined) throw new WardError("uncaught");
    const record: AuditRecord = {
      id: options.newId(),
      runId: options.runId,
      projectId: options.projectId,
      profile: options.profile,
      secretId: keyId,
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

export const auditIncompleteWarning =
  "ward sign: the signature was produced, but its completion audit event could not be written, so the audit trail for this sign is incomplete.";

export async function runSign(
  input: SignCommandInput,
  options: SignOptions,
): Promise<SignResult> {
  const name = input.profile;
  if (name === undefined) throw new WardError("missing_argument");
  if (!isProfileName(name)) throw new WardError("profile_name_invalid");
  // Judged before the vault or the input is touched, as `ward run` does.
  const actorLabel = assertedLabel(input.actorLabel);
  const taskLabel = assertedLabel(input.taskLabel);
  const machine = options.observeMachine();

  let message: Uint8Array;
  try {
    message = options.readInput(signInputLimitBytes);
  } catch (error) {
    if (error instanceof WardError && error.code === "secret_value_too_large")
      throw new WardError("sign_input_too_large");
    if (error instanceof WardError && error.code === "secret_stdin_terminal")
      throw new WardError("sign_input_terminal");
    throw error;
  }
  try {
    const checkout = readCheckout(options.checkout, options.files);
    const manifest = requireManifest(checkout);
    if (!Object.hasOwn(manifest.profiles, name))
      throw new WardError("profile_not_found");
    const header = options.store.header();
    if (header === undefined) throw new WardError("vault_not_found");
    const key = await options.keyProvider.load(header.vaultId);
    try {
      const read = options.store.read(key);
      let state: VaultState;
      try {
        state = parseVaultState(read.plaintext);
      } finally {
        read.plaintext.fill(0);
      }
      const projectId = boundProject(checkout, state);
      const snapshot = approvedSignSnapshot({
        now: options.now(),
        state,
        identity: options.checkout,
        projectId,
        name,
        declared: manifest.profiles[name],
      });
      const record = findSecret(state, projectId, snapshot.key);
      if (record === undefined || !isSignKey(record))
        throw new WardError("sign_key_not_found");
      const prefixes = snapshot.prefixes.map(
        (prefix) => new Uint8Array(Buffer.from(prefix, "base64")),
      );
      // Refused rather than performed, so nothing was admitted and no audit
      // event is written (the same rule as a run refused before it is sent).
      if (!startsWithAllowedPrefix(message, prefixes))
        throw new WardError("sign_input_refused");

      const runId = options.newId();
      const audit = {
        store: options.store,
        key,
        identity: options.checkout,
        projectId,
        profile: name,
        runId,
        machine,
        actorLabel,
        taskLabel,
        newId: options.newId,
      };
      // Admission, before anything is signed.
      writeSignAudit({
        ...audit,
        phase: "admission",
        outcome: null,
        at: options.now().toISOString(),
        admitting: {
          snapshot,
          keyId: record.id,
          keyRevision: record.revision,
        },
      });

      let signature: Uint8Array | undefined;
      let publicKey: Uint8Array | undefined;
      let outcome: AuditOutcome = "failed";
      let failure: unknown;
      try {
        const signed = signWithKey(
          state,
          projectId,
          snapshot.key,
          message,
          prefixes,
        );
        signature = signed.signature;
        publicKey = signed.publicKey;
        outcome = "succeeded";
      } catch (error) {
        failure = error;
      }
      // Completion in its own transaction. A failure to write it is reported
      // rather than thrown once a signature exists: the signing has happened
      // (spec §9.4 asks for that to be said honestly).
      let recorded = true;
      try {
        writeSignAudit({
          ...audit,
          phase: "completion",
          outcome,
          at: options.now().toISOString(),
          completingKeyId: record.id,
        });
      } catch {
        recorded = false;
      }
      if (failure !== undefined) throw failure;
      if (signature === undefined || publicKey === undefined)
        throw new WardError("uncaught");
      return {
        kind: "sign.result",
        data: {
          projectId,
          profile: name,
          runId,
          outcome,
          auditRecorded: recorded,
          algorithm: "ed25519",
          publicKey: Buffer.from(publicKey).toString("base64"),
          signature: Buffer.from(signature).toString("base64"),
        },
        signature,
        text: Buffer.from(signature).toString("base64"),
        ...(recorded
          ? {}
          : {
              exitCode: exitCodes.validation,
              warning: auditIncompleteWarning,
            }),
      };
    } finally {
      key.fill(0);
    }
  } finally {
    message.fill(0);
  }
}
