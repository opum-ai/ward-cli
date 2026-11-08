// `ward key`: generate an Ed25519 signing key inside the vault, and read its
// public key back (DEC-262 (2), docs/adr/0027).
//
// The seed is made here, stored as a SecretRecord of kind "ed25519" in the
// same custody as every other secret (no second key store), and never leaves
// this module: every result below is built from the alias, identifiers, times
// and the PUBLIC key. There is no field a seed could be written into, and the
// error paths name no alias and no byte of key material.
import type { ResultKind } from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "../domain/identifiers.ts";
import {
  decodeSecretValue,
  encodeSecretValue,
  isSecretAlias,
  isSignKey,
  type SecretRecord,
  signKeyKind,
} from "../domain/secret.ts";
import {
  generateSignKey,
  publicKeyOf,
  signBytes,
  startsWithAllowedPrefix,
} from "../domain/signing.ts";
import {
  findActiveGrant,
  findSecret,
  parseVaultState,
  serializeVaultState,
  type VaultState,
  withSecret,
} from "../domain/vault-state.ts";
import { requireBinding } from "./binding.ts";
import {
  type BoundVault,
  type SecretOptions,
  withBoundVault,
} from "./secrets.ts";

export type KeyOptions = Pick<
  SecretOptions,
  "checkout" | "files" | "store" | "keyProvider" | "now" | "newSecretId"
>;

export interface KeyCommandInput {
  readonly action: string;
  readonly alias: string | undefined;
}

export interface KeyResult {
  readonly kind: ResultKind;
  readonly data: Record<string, unknown>;
  readonly text: string;
}

export const keyActions = ["generate", "public"] as const;

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// The seed of the project's own sign key under an alias, or the fixed
// refusal. An ordinary secret under the alias is "not a signing key", the
// same answer as a miss, so an agent cannot use this to learn that an alias
// holds an ordinary secret.
function signKeySeed(
  state: VaultState,
  projectId: string,
  alias: string,
): { readonly record: SecretRecord; readonly seed: Uint8Array } {
  const record = findSecret(state, projectId, alias);
  if (record === undefined || !isSignKey(record))
    throw new WardError("sign_key_not_found");
  const seed = decodeSecretValue(record.value);
  if (seed === undefined) throw new WardError("vault_state_malformed");
  return { record, seed };
}

// Signs exactly the bytes given: Ward adds, strips and rewrites nothing, and
// domain prefixing is the caller's. The allowed prefixes come from an approved
// sign profile (held for its own change); an empty list allows no input.
export function signWithKey(
  state: VaultState,
  projectId: string,
  alias: string,
  message: Uint8Array,
  allowedPrefixes: readonly Uint8Array[],
): { readonly signature: Uint8Array; readonly publicKey: Uint8Array } {
  const { seed } = signKeySeed(state, projectId, alias);
  try {
    if (!startsWithAllowedPrefix(message, allowedPrefixes))
      throw new WardError("sign_input_refused");
    return {
      signature: signBytes(seed, message),
      publicKey: publicKeyOf(seed),
    };
  } finally {
    seed.fill(0);
  }
}

function requireAlias(input: KeyCommandInput): string {
  if (input.alias === undefined) throw new WardError("missing_argument");
  if (!isSecretAlias(input.alias)) throw new WardError("secret_alias_invalid");
  return input.alias;
}

function generate(
  bound: BoundVault,
  alias: string,
  options: KeyOptions,
): KeyResult {
  // An alias a grant gives this project is not this project's to take, and an
  // existing record, ordinary or not, is never replaced by a new key.
  if (findActiveGrant(bound.state, bound.projectId, alias) !== undefined)
    throw new WardError("secret_granted_readonly");
  if (findSecret(bound.state, bound.projectId, alias) !== undefined)
    throw new WardError("sign_key_exists");
  const generated = generateSignKey();
  const now = options.now().toISOString();
  let written: SecretRecord | undefined;
  try {
    options.store.mutate(bound.key, (plaintext) => {
      const current = parseVaultState(plaintext);
      requireBinding(current, options.checkout, bound.projectId);
      if (findActiveGrant(current, bound.projectId, alias) !== undefined)
        throw new WardError("secret_granted_readonly");
      if (findSecret(current, bound.projectId, alias) !== undefined)
        throw new WardError("sign_key_exists");
      const id = options.newSecretId();
      if (!isOpaqueId(id)) throw new WardError("uncaught");
      const record: SecretRecord = {
        id,
        projectId: bound.projectId,
        alias,
        value: encodeSecretValue(generated.seed),
        createdAt: now,
        updatedAt: now,
        revision: 1,
        kind: signKeyKind,
      };
      written = record;
      return serializeVaultState(withSecret(current, record));
    });
  } finally {
    generated.seed.fill(0);
  }
  if (written === undefined) throw new WardError("uncaught");
  const record: SecretRecord = written;
  const publicKey = base64(generated.publicKey);
  return {
    kind: "key.generate",
    data: {
      alias: record.alias,
      id: record.id,
      projectId: record.projectId,
      createdAt: record.createdAt,
      algorithm: signKeyKind,
      publicKey,
    },
    text: [
      `Generated signing key "${record.alias}".`,
      "",
      `  algorithm:  ${signKeyKind}`,
      `  public key: ${publicKey}`,
      "",
      "The private key stays in Ward's vault and is never shown. It is not part of a backup.",
    ].join("\n"),
  };
}

function publicKey(bound: BoundVault, alias: string): KeyResult {
  const { record, seed } = signKeySeed(bound.state, bound.projectId, alias);
  try {
    const encoded = base64(publicKeyOf(seed));
    return {
      kind: "key.public",
      data: {
        alias: record.alias,
        id: record.id,
        projectId: record.projectId,
        algorithm: signKeyKind,
        publicKey: encoded,
      },
      text: encoded,
    };
  } finally {
    seed.fill(0);
  }
}

export async function runKey(
  input: KeyCommandInput,
  options: KeyOptions,
): Promise<KeyResult> {
  if (!(keyActions as readonly string[]).includes(input.action))
    throw new WardError("key_action_unknown");
  const alias = requireAlias(input);
  return withBoundVault(options, (bound) =>
    input.action === "generate"
      ? generate(bound, alias, options)
      : publicKey(bound, alias),
  );
}
