// `ward secret`: set, list, inspect and delete this project's secrets
// (spec §6.2, §8, §7.1).
//
// A value is the developer's data: entered hidden on a terminal, or piped
// with --stdin as exact bytes. It is never an argument, never part of a
// result, and never readable back out: every result object below is built
// from fields that do not include a value, a length or a hash of one, so
// disclosure is excluded by construction rather than by filtering.
//
// Authority is the checkout binding (spec §7.1). The manifest names the
// project; the vault's binding for this exact directory decides whether the
// checkout may touch that project's records, and the decision is repeated
// inside the write transaction so a concurrent change cannot reopen it. A
// lookup that misses stays a miss: no other project's records are consulted,
// filtered in or counted.
import type { ResultKind } from "../contract/envelope.ts";
import type { GrantApprover } from "./approvals.ts";
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "../domain/identifiers.ts";
import {
  encodeSecretValue,
  isSecretAlias,
  isSignKey,
  type SecretRecord,
  secretLimits,
} from "../domain/secret.ts";
import {
  type CheckoutIdentity,
  findActiveGrant,
  findActiveGrantOf,
  findSecret,
  parseVaultState,
  resolveSecret,
  secretsFor,
  serializeVaultState,
  type VaultState,
  withGrant,
  withRevokedGrant,
  withoutSecret,
  withSecret,
} from "../domain/vault-state.ts";
import { boundProject, requireBinding } from "./binding.ts";
import type { KeyProvider } from "./key-provider.ts";
import type { ProjectFiles } from "./project-files.ts";
import { readCheckout } from "./project.ts";
import type { VaultStore } from "./vault-store.ts";

// Where a secret value comes from. The hidden path is a person on a
// terminal; the stdin path is explicit automation; the confirmation is the
// replacement question, which is only ever asked on the hidden path.
export interface SecretValueSource {
  // True when a hidden read and a confirmation question can be asked on a
  // terminal.
  available(): boolean;
  // Echo-suppressed entry. The caller owns the buffer and zeroes it.
  // undefined when there is no terminal to ask on (available() is false) or
  // the terminal cannot be read once raw mode is on. A terminal that cannot be
  // put into raw mode throws instead, before the read starts. Ctrl-C abandons
  // the read and returns an empty buffer, as does nothing typed; the caller
  // treats an empty buffer and undefined as the same answer. A value past the
  // limit is refused as too large rather than truncated.
  readHidden(): Uint8Array | undefined;
  // Standard input to EOF as exact bytes, terminator included: --stdin does
  // nothing to the bytes it is given. The caller owns the buffer and zeroes
  // it. Refuses an interactive terminal as the source, and refuses more than
  // maxBytes rather than truncating.
  readStdin(maxBytes: number): Uint8Array;
  // The replacement question, answered y/yes to consent. False when it
  // cannot be asked or it was declined.
  confirmReplace(alias: string): boolean;
}

export interface SecretOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
  readonly values: SecretValueSource;
  // The question a grant is asked on. A grant extends authority to another
  // project, so it is a developer's act in a terminal, like a profile approval.
  readonly grants: GrantApprover;
  readonly now: () => Date;
  readonly newSecretId: () => string;
  // Identifies a grant record. Supplied like `newSecretId`, so a test can
  // predict the identifiers it asserts on.
  readonly newGrantId: () => string;
}

export interface SecretCommandInput {
  readonly action: string;
  readonly alias: string | undefined;
  readonly viaStdin: boolean;
  // `--to` and `--as` (grant) and `--from` (revoke): a target project id and
  // the alias the target will see it under.
  readonly to?: string | undefined;
  readonly as?: string | undefined;
  readonly from?: string | undefined;
}

export interface SecretResult {
  readonly kind: ResultKind;
  readonly data: Record<string, unknown>;
  readonly text: string;
}

// The key, the state and the decision every action runs against. The caller
// of openBoundVault owns `key` and zeroes it; the plaintext buffer is zeroed
// as soon as the state has been parsed.
export interface BoundVault {
  readonly key: Uint8Array;
  readonly state: VaultState;
  readonly projectId: string;
}

export const secretActions = [
  "set",
  "list",
  "inspect",
  "delete",
  "grant",
  "revoke",
] as const;

function isSecretAction(
  value: string,
): value is (typeof secretActions)[number] {
  return (secretActions as readonly string[]).includes(value);
}

// A stored record, as every result reports it: identifiers, the alias and
// the times of the value. There is no field for a value or its length to
// leak through, because none is read.
function recordMetadata(record: SecretRecord): Record<string, unknown> {
  return {
    alias: record.alias,
    id: record.id,
    projectId: record.projectId,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    revision: record.revision,
    // Named only for a record that is not an ordinary secret.
    ...(record.kind === undefined ? {} : { kind: record.kind }),
  };
}

const storedValueNote =
  "Ward does not display stored values, and there is no command that prints one.";

function setText(record: SecretRecord, status: "created" | "replaced"): string {
  return [
    status === "created" ? "Secret stored." : "Secret replaced.",
    "",
    `  alias:     ${record.alias}`,
    `  project:   ${record.projectId}`,
    `  id:        ${record.id}`,
    `  created:   ${record.createdAt}`,
    `  updated:   ${record.updatedAt}`,
    `  revision:  ${record.revision}`,
    "",
    storedValueNote,
  ].join("\n");
}

function declinedText(alias: string): string {
  return [
    "Not replaced.",
    "",
    `  alias:     ${alias}`,
    "",
    "The existing secret was left as it is.",
  ].join("\n");
}

function inspectText(record: SecretRecord): string {
  return [
    "Secret metadata.",
    "",
    `  alias:     ${record.alias}`,
    `  project:   ${record.projectId}`,
    `  id:        ${record.id}`,
    "  ownership: this project",
    `  created:   ${record.createdAt}`,
    `  updated:   ${record.updatedAt}`,
    `  revision:  ${record.revision}`,
    ...(record.kind === undefined ? [] : [`  kind:      ${record.kind}`]),
    "",
    storedValueNote,
  ].join("\n");
}

function deleteText(alias: string, projectId: string): string {
  return [
    "Secret deleted.",
    "",
    `  alias:     ${alias}`,
    `  project:   ${projectId}`,
    "",
    "Deleting a Ward entry does not revoke the credential at its provider.",
  ].join("\n");
}

// Opens the vault for this checkout and hands the action the key, the parsed
// state and the project the binding authorises. The key is zeroed on every
// path out, and the read's plaintext is zeroed as soon as it has been parsed.
export async function withBoundVault<T>(
  options: Pick<SecretOptions, "checkout" | "files" | "store" | "keyProvider">,
  run: (bound: BoundVault) => T | Promise<T>,
): Promise<T> {
  const checkout = readCheckout(options.checkout, options.files);
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
    const projectId = boundProject(checkout, state);
    return await run({ key, state, projectId });
  } finally {
    key.fill(0);
  }
}

// The alias a non-list action needs, judged before anything is opened or
// read: a malformed request costs nothing, and a rejected alias is never
// looked up anywhere.
function requireAlias(input: SecretCommandInput): string {
  if (input.viaStdin && input.action !== "set")
    throw new WardError("secret_option_unexpected");
  if (input.alias === undefined) throw new WardError("missing_argument");
  if (!isSecretAlias(input.alias)) throw new WardError("secret_alias_invalid");
  return input.alias;
}

function listSecrets(bound: BoundVault): SecretResult {
  const owned = secretsFor(bound.state, bound.projectId).map(
    ({ alias, updatedAt, revision, kind }) => ({
      alias,
      ownership: "owner" as const,
      updatedAt: updatedAt as string | null,
      revision: revision as number | null,
      ...(kind === undefined ? {} : { kind }),
    }),
  );
  // A granted alias is listed so an agent can name it in a profile, and is
  // marked so it is never mistaken for one this project owns. The owner's
  // revision and update time are not reported here: the target needs the
  // name, not the owner's history.
  const granted = bound.state.sharingGrants
    .filter(
      (grant) =>
        grant.targetProjectId === bound.projectId && grant.revokedAt === null,
    )
    .map((grant) => ({
      alias: grant.targetAlias,
      ownership: "granted" as const,
      updatedAt: null as string | null,
      revision: null as number | null,
    }));
  const entries = [...owned, ...granted].sort((left, right) =>
    left.alias < right.alias ? -1 : left.alias > right.alias ? 1 : 0,
  );
  return {
    kind: "secret.list",
    data: { projectId: bound.projectId, secrets: entries },
    text:
      entries.length === 0
        ? "No secrets in this project."
        : [
            "Secrets in this project:",
            "",
            ...entries.map(
              (entry) =>
                `  ${entry.alias}${entry.ownership === "granted" ? "  (granted, use only)" : ""}${"kind" in entry ? `  (${entry.kind} signing key)` : ""}`,
            ),
          ].join("\n"),
  };
}

function inspectSecret(bound: BoundVault, alias: string): SecretResult {
  const resolved = resolveSecret(bound.state, bound.projectId, alias);
  if (resolved.kind === "granted")
    return {
      kind: "secret.inspect",
      data: {
        alias,
        projectId: bound.projectId,
        ownership: "granted",
        grantId: resolved.grant.id,
        ownerProjectId: resolved.grant.ownerProjectId,
        grantedAt: resolved.grant.createdAt,
      },
      text: [
        "Secret metadata.",
        "",
        `  alias:     ${alias}`,
        `  project:   ${bound.projectId}`,
        "  ownership: granted, use only",
        `  owner:     ${resolved.grant.ownerProjectId}`,
        `  granted:   ${resolved.grant.createdAt}`,
        "",
        storedValueNote,
      ].join("\n"),
    };
  if (resolved.kind !== "owned") throw new WardError("secret_not_found");
  const record = resolved.secret;
  return {
    kind: "secret.inspect",
    data: { ...recordMetadata(record), ownership: "owner" },
    text: inspectText(record),
  };
}

// A granted alias is use-only here: the target cannot write, delete, share or
// revoke it (spec §7.2). Named once so every target-side path refuses it the
// same way, and checked before the not-found answer so a target learns the
// alias is not its to change rather than that it does not exist.
function refuseGranted(
  state: VaultState,
  projectId: string,
  alias: string,
): void {
  if (findActiveGrant(state, projectId, alias) !== undefined)
    throw new WardError("secret_granted_readonly");
}

function deleteSecret(
  bound: BoundVault,
  alias: string,
  options: SecretOptions,
): SecretResult {
  refuseGranted(bound.state, bound.projectId, alias);
  const record = findSecret(bound.state, bound.projectId, alias);
  if (record === undefined) throw new WardError("secret_not_found");
  const at = options.now().toISOString();
  options.store.mutate(bound.key, (plaintext) => {
    // The authority decision, repeated inside the transaction so a change
    // that raced another writer cannot act on a state the earlier read no
    // longer describes.
    const current = parseVaultState(plaintext);
    requireBinding(current, options.checkout, bound.projectId);
    refuseGranted(current, bound.projectId, alias);
    if (findSecret(current, bound.projectId, alias) === undefined)
      throw new WardError("secret_not_found");
    // Deleting the record revokes its grants in the same document (spec
    // §7.2): there is no state in which the secret is gone and a target can
    // still be admitted through it.
    return serializeVaultState(
      withoutSecret(current, bound.projectId, alias, at),
    );
  });
  return {
    kind: "secret.delete",
    data: { alias: record.alias, id: record.id, projectId: record.projectId },
    text: deleteText(record.alias, record.projectId),
  };
}

async function setSecret(
  bound: BoundVault,
  alias: string,
  input: SecretCommandInput,
  options: SecretOptions,
): Promise<SecretResult> {
  refuseGranted(bound.state, bound.projectId, alias);
  const existing = findSecret(bound.state, bound.projectId, alias);
  // A signing key is not replaced as an ordinary secret (DEC-262 (2)).
  if (existing !== undefined && isSignKey(existing))
    throw new WardError("sign_key_refused");
  let value: Uint8Array | undefined;
  try {
    if (input.viaStdin) {
      value = options.values.readStdin(secretLimits.maxValueBytes);
    } else {
      if (!options.values.available())
        throw new WardError("secret_requires_terminal");
      // Asked before the value is read, so a declined replacement never
      // costs the developer their typing and never touches the vault.
      if (existing !== undefined && !options.values.confirmReplace(alias))
        return {
          kind: "secret.set",
          data: { alias, projectId: bound.projectId, status: "declined" },
          text: declinedText(alias),
        };
      value = options.values.readHidden();
      if (value === undefined) throw new WardError("secret_value_rejected");
    }
    // The bound is enforced here, against the port's contract, rather than
    // trusted to each source: a value over the limit must fail, not truncate.
    if (value.length === 0) throw new WardError("secret_value_rejected");
    if (value.length > secretLimits.maxValueBytes)
      throw new WardError("secret_value_too_large");
    const encoded = encodeSecretValue(value);
    const now = options.now().toISOString();
    // What the transaction actually wrote, captured for the result: the id
    // is minted inside the transaction, where the latest state decides
    // whether an existing record's identity is kept.
    let written: SecretRecord | undefined;
    options.store.mutate(bound.key, (plaintext) => {
      // The authority decision, repeated inside the transaction so a change
      // that raced another writer cannot act on a state the earlier read no
      // longer describes.
      const current = parseVaultState(plaintext);
      requireBinding(current, options.checkout, bound.projectId);
      // A grant that landed after the read would give this alias to the
      // project from outside; writing an own record over it is refused.
      refuseGranted(current, bound.projectId, alias);
      const previous = findSecret(current, bound.projectId, alias);
      if (previous !== undefined && isSignKey(previous))
        throw new WardError("sign_key_refused");
      // The confirmation belongs to the state the value was read against. An
      // alias that appeared in between was never covered by it, so the write
      // is refused rather than replacing a record unasked.
      if (!input.viaStdin && existing === undefined && previous !== undefined)
        throw new WardError("secret_changed");
      // The id survives a replacement: it is the record's identity, and a
      // rotation changes the value, not the identity.
      const id = previous?.id ?? options.newSecretId();
      if (!isOpaqueId(id)) throw new WardError("uncaught");
      const record: SecretRecord = {
        id,
        projectId: bound.projectId,
        alias,
        value: encoded,
        createdAt: previous?.createdAt ?? now,
        updatedAt: now,
        revision: (previous?.revision ?? 0) + 1,
      };
      written = record;
      return serializeVaultState(withSecret(current, record));
    });
    if (written === undefined) throw new WardError("uncaught");
    const record: SecretRecord = written;
    const status = record.revision === 1 ? "created" : "replaced";
    return {
      kind: "secret.set",
      data: { ...recordMetadata(record), status },
      text: setText(record, status),
    };
  } finally {
    value?.fill(0);
  }
}

// The flags each action takes. A flag that belongs to another action is a
// usage fault, judged before anything is opened, like `--stdin` on a non-set.
function requireActionFlags(input: SecretCommandInput): void {
  const { action } = input;
  const hasTo = input.to !== undefined;
  const hasAs = input.as !== undefined;
  const hasFrom = input.from !== undefined;
  if (action === "grant") {
    if (hasFrom) throw new WardError("secret_option_unexpected");
    if (!hasTo || !hasAs) throw new WardError("missing_required_option");
    return;
  }
  if (action === "revoke") {
    if (hasTo || hasAs) throw new WardError("secret_option_unexpected");
    if (!hasFrom) throw new WardError("missing_required_option");
    return;
  }
  if (hasTo || hasAs || hasFrom)
    throw new WardError("secret_option_unexpected");
}

// What a grant would do to this state, or the reason it cannot. It is the one
// function the pre-check and the transaction both run, so the decision made
// before the question is asked is the decision made when the record is
// written: the owner secret exists, the target is another project this vault
// knows, and neither the secret nor the target alias is already taken.
function grantInto(
  state: VaultState,
  options: {
    ownerProjectId: string;
    alias: string;
    targetProjectId: string;
    targetAlias: string;
    id: string;
    at: string;
  },
): VaultState {
  refuseGranted(state, options.ownerProjectId, options.alias);
  const secret = findSecret(state, options.ownerProjectId, options.alias);
  if (secret === undefined) throw new WardError("secret_not_found");
  // A grant gives the target the use of the value as a credential, which a
  // signing key never is (DEC-262 (2)).
  if (isSignKey(secret)) throw new WardError("sign_key_refused");
  if (options.targetProjectId === options.ownerProjectId)
    throw new WardError("grant_target_is_owner");
  if (!state.projects.some((project) => project.id === options.targetProjectId))
    throw new WardError("grant_target_unknown");
  if (
    findActiveGrantOf(state, secret.id, options.targetProjectId) !== undefined
  )
    throw new WardError("grant_exists");
  if (
    findSecret(state, options.targetProjectId, options.targetAlias) !==
      undefined ||
    findActiveGrant(state, options.targetProjectId, options.targetAlias) !==
      undefined
  )
    throw new WardError("grant_alias_conflict");
  return withGrant(state, {
    id: options.id,
    ownerProjectId: options.ownerProjectId,
    ownerSecretId: secret.id,
    targetProjectId: options.targetProjectId,
    targetAlias: options.targetAlias,
    createdAt: options.at,
    revokedAt: null,
  });
}

const admissionRule =
  "Revocation blocks runs admitted after it. A run admitted before it may finish, and Ward cannot recall a credential already sent.";

function grantSecret(
  bound: BoundVault,
  alias: string,
  targetProjectId: string,
  targetAlias: string,
  options: SecretOptions,
): SecretResult {
  const at = options.now().toISOString();
  const grantId = options.newGrantId();
  if (!isOpaqueId(grantId)) throw new WardError("uncaught");
  const attempt = {
    ownerProjectId: bound.projectId,
    alias,
    targetProjectId,
    targetAlias,
    id: grantId,
    at,
  };
  // Judged before the question, so a grant that cannot succeed costs the
  // developer no prompt and never reaches the vault.
  grantInto(bound.state, attempt);
  if (!options.grants.available())
    throw new WardError("grant_requires_terminal");
  const answer = options.grants.ask({
    ownerProjectId: bound.projectId,
    alias,
    targetProjectId,
    targetAlias,
  });
  if (answer === "unavailable") throw new WardError("grant_requires_terminal");
  if (answer === "declined") throw new WardError("grant_declined");
  options.store.mutate(bound.key, (plaintext) => {
    const current = parseVaultState(plaintext);
    requireBinding(current, options.checkout, bound.projectId);
    return serializeVaultState(grantInto(current, attempt));
  });
  return {
    kind: "secret.grant",
    data: {
      grantId,
      ownerProjectId: bound.projectId,
      alias,
      targetProjectId,
      targetAlias,
      createdAt: at,
    },
    text: [
      "Secret granted.",
      "",
      `  alias:          ${alias}`,
      `  owner project:  ${bound.projectId}`,
      `  target project: ${targetProjectId}`,
      `  target alias:   ${targetAlias}`,
      "",
      "The target can use this secret, and cannot read, change, delete or",
      "re-share it. The target's developer still has to approve a profile that",
      "names the target alias.",
      admissionRule,
    ].join("\n"),
  };
}

function revokeGrant(
  bound: BoundVault,
  alias: string,
  targetProjectId: string,
  options: SecretOptions,
): SecretResult {
  const at = options.now().toISOString();
  const revokedGrantId = (state: VaultState): string => {
    refuseGranted(state, bound.projectId, alias);
    const secret = findSecret(state, bound.projectId, alias);
    if (secret === undefined) throw new WardError("secret_not_found");
    const grant = findActiveGrantOf(state, secret.id, targetProjectId);
    if (grant === undefined) throw new WardError("grant_not_found");
    return grant.id;
  };
  revokedGrantId(bound.state);
  let grantId = "";
  options.store.mutate(bound.key, (plaintext) => {
    const current = parseVaultState(plaintext);
    requireBinding(current, options.checkout, bound.projectId);
    grantId = revokedGrantId(current);
    return serializeVaultState(withRevokedGrant(current, grantId, at));
  });
  return {
    kind: "secret.revoke",
    data: {
      grantId,
      ownerProjectId: bound.projectId,
      alias,
      targetProjectId,
      revokedAt: at,
    },
    text: [
      "Grant revoked.",
      "",
      `  alias:          ${alias}`,
      `  target project: ${targetProjectId}`,
      "",
      admissionRule,
      "Revoking a grant does not revoke the credential at its provider.",
    ].join("\n"),
  };
}

export async function runSecret(
  input: SecretCommandInput,
  options: SecretOptions,
): Promise<SecretResult> {
  const { action } = input;
  if (!isSecretAction(action)) throw new WardError("secret_action_unknown");
  requireActionFlags(input);
  if (action === "list") {
    if (input.alias !== undefined) throw new WardError("unexpected_argument");
    if (input.viaStdin) throw new WardError("secret_option_unexpected");
    return withBoundVault(options, (bound) => listSecrets(bound));
  }
  const alias = requireAlias(input);
  // Grammar judged before the vault is opened, like the alias.
  if (action === "grant") {
    const targetAlias = input.as as string;
    const target = input.to as string;
    if (!isSecretAlias(targetAlias))
      throw new WardError("secret_alias_invalid");
    if (!isOpaqueId(target)) throw new WardError("grant_project_invalid");
    return withBoundVault(options, (bound) =>
      grantSecret(bound, alias, target, targetAlias, options),
    );
  }
  if (action === "revoke") {
    const target = input.from as string;
    if (!isOpaqueId(target)) throw new WardError("grant_project_invalid");
    return withBoundVault(options, (bound) =>
      revokeGrant(bound, alias, target, options),
    );
  }
  return withBoundVault(options, (bound) => {
    if (action === "inspect") return inspectSecret(bound, alias);
    if (action === "delete") return deleteSecret(bound, alias, options);
    return setSecret(bound, alias, input, options);
  });
}
