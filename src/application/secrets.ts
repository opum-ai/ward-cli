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
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "../domain/identifiers.ts";
import {
  encodeSecretValue,
  isSecretAlias,
  type SecretRecord,
  secretLimits,
} from "../domain/secret.ts";
import {
  type CheckoutIdentity,
  findBinding,
  findSecret,
  parseVaultState,
  secretsFor,
  serializeVaultState,
  type VaultState,
  withoutSecret,
  withSecret,
} from "../domain/vault-state.ts";
import type { KeyProvider } from "./key-provider.ts";
import type { ProjectFiles } from "./project-files.ts";
import { type Checkout, readCheckout } from "./project.ts";
import type { VaultStore } from "./vault-store.ts";

// Where a secret value comes from. The hidden path is a person on a
// terminal; the stdin path is explicit automation; the confirmation is the
// replacement question, which is only ever asked on the hidden path.
export interface SecretValueSource {
  // True when a hidden read and a confirmation question can be asked on a
  // terminal.
  available(): boolean;
  // Echo-suppressed entry. The caller owns the buffer and zeroes it.
  // undefined when the read was cancelled; an empty buffer when nothing was
  // typed. The two are the same answer to the caller. A value past the
  // limit is refused as too large rather than truncated.
  readHidden(): Uint8Array | undefined;
  // Standard input to EOF as exact bytes, terminator included: --stdin does
  // nothing to the bytes it is given. Refuses an interactive terminal as the
  // source, and refuses more than maxBytes rather than truncating.
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
  readonly now: () => Date;
  readonly newSecretId: () => string;
}

export interface SecretCommandInput {
  readonly action: string;
  readonly alias: string | undefined;
  readonly viaStdin: boolean;
}

export interface SecretResult {
  readonly kind: ResultKind;
  readonly data: Record<string, unknown>;
  readonly text: string;
}

// The key, the state and the decision every action runs against. The caller
// of openBoundVault owns `key` and zeroes it; the plaintext buffer is zeroed
// as soon as the state has been parsed.
interface BoundVault {
  readonly key: Uint8Array;
  readonly state: VaultState;
  readonly projectId: string;
}

const secretActions = ["set", "list", "inspect", "delete"] as const;

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

// The manifest's project and the vault's binding must agree, and the binding
// is what decides access. A missing manifest and a missing binding are the
// same answer: this checkout is not registered. A binding for a project the
// manifest does not name is a conflict.
function boundProject(checkout: Checkout, state: VaultState): string {
  const manifest = checkout.manifest;
  if (manifest === undefined) throw new WardError("project_not_registered");
  const binding = findBinding(state, checkout.identity);
  if (binding === undefined) throw new WardError("project_not_registered");
  if (binding.projectId !== manifest.projectId)
    throw new WardError("binding_conflict");
  return binding.projectId;
}

// Opens the vault for this checkout and hands the action the key, the parsed
// state and the project the binding authorises. The key is zeroed on every
// path out, and the read's plaintext is zeroed as soon as it has been parsed.
async function withBoundVault<T>(
  options: SecretOptions,
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
  const records = secretsFor(bound.state, bound.projectId)
    .slice()
    .sort((left, right) =>
      left.alias < right.alias ? -1 : left.alias > right.alias ? 1 : 0,
    );
  return {
    kind: "secret.list",
    data: {
      projectId: bound.projectId,
      secrets: records.map(({ alias, updatedAt, revision }) => ({
        alias,
        updatedAt,
        revision,
      })),
    },
    text:
      records.length === 0
        ? "No secrets in this project."
        : [
            "Secrets in this project:",
            "",
            ...records.map((record) => `  ${record.alias}`),
          ].join("\n"),
  };
}

function inspectSecret(bound: BoundVault, alias: string): SecretResult {
  const record = findSecret(bound.state, bound.projectId, alias);
  if (record === undefined) throw new WardError("secret_not_found");
  return {
    kind: "secret.inspect",
    data: { ...recordMetadata(record), ownership: "owner" },
    text: inspectText(record),
  };
}

// The same authority decision, repeated inside a write transaction, so a
// change that raced another writer cannot act on a state the earlier read no
// longer describes.
function boundProjectOf(
  options: SecretOptions,
  plaintext: Uint8Array,
  expectedProjectId: string,
): VaultState {
  const state = parseVaultState(plaintext);
  const binding = findBinding(state, options.checkout);
  if (binding === undefined) throw new WardError("project_not_registered");
  if (binding.projectId !== expectedProjectId)
    throw new WardError("binding_conflict");
  return state;
}

function deleteSecret(
  bound: BoundVault,
  alias: string,
  options: SecretOptions,
): SecretResult {
  const record = findSecret(bound.state, bound.projectId, alias);
  if (record === undefined) throw new WardError("secret_not_found");
  options.store.mutate(bound.key, (plaintext) => {
    const current = boundProjectOf(options, plaintext, bound.projectId);
    if (findSecret(current, bound.projectId, alias) === undefined)
      throw new WardError("secret_not_found");
    return serializeVaultState(withoutSecret(current, bound.projectId, alias));
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
  const existing = findSecret(bound.state, bound.projectId, alias);
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
      const current = boundProjectOf(options, plaintext, bound.projectId);
      const previous = findSecret(current, bound.projectId, alias);
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

export async function runSecret(
  input: SecretCommandInput,
  options: SecretOptions,
): Promise<SecretResult> {
  const { action } = input;
  if (!isSecretAction(action)) throw new WardError("secret_action_unknown");
  if (action === "list") {
    if (input.alias !== undefined) throw new WardError("unexpected_argument");
    if (input.viaStdin) throw new WardError("secret_option_unexpected");
    return withBoundVault(options, (bound) => listSecrets(bound));
  }
  const alias = requireAlias(input);
  return withBoundVault(options, (bound) => {
    if (action === "inspect") return inspectSecret(bound, alias);
    if (action === "delete") return deleteSecret(bound, alias, options);
    return setSecret(bound, alias, input, options);
  });
}
