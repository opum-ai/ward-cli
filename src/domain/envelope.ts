import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "./identifiers.ts";

// The vault encryption envelope (spec §6.3). One logical snapshot is sealed
// with AES-256-GCM under the 32-byte vault key, with a fresh random 12-byte
// nonce per seal. The header is bound as authenticated data, so a record
// moved to another vault, replayed under a different revision, or relabelled
// with another format version fails authentication.
//
// Authenticated encryption detects modification, not rollback: an older
// record that was valid under the same key still opens. Rollback resistance
// is not claimed.
//
// NIST SP 800-38D §8.3 caps random-nonce invocations per key at 2^32. Ward
// seals once per vault mutation.
//
// Not enforced here, and owned by the storage and secret layers: the 64 KiB
// per-value limit, the revision increment on each mutation, and persisting
// only these record fields.

export const envelopeDomain = "opum.ward.vault";
export const formatVersion = 1;

export const envelopeLimits = {
  keyBytes: 32,
  nonceBytes: 12,
  tagBytes: 16,
  // Proposed v0.1 product limit for the logical vault (spec §6.3).
  maxPlaintextBytes: 10 * 1024 * 1024,
} as const;

// A vault id is an opaque identifier, the same grammar as a project id
// (domain/identifiers.ts).
export const isVaultId = isOpaqueId;

export interface EnvelopeHeader {
  formatVersion: number;
  vaultId: string;
  revision: number;
}

export interface SealedRecord extends EnvelopeHeader {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export function generateVaultKey(): Uint8Array {
  return new Uint8Array(randomBytes(envelopeLimits.keyBytes));
}

// Every input is read once and copied before it is checked or used. The
// TypedArray constructor copies by the view's internal length, so a subclass
// overriding `length`, a getter returning different values on each read, or
// a SharedArrayBuffer another thread can write cannot make the bytes that
// were validated differ from the bytes that reach the cipher.
function ownBytes(
  value: unknown,
  code: "vault_key_invalid" | "vault_record_malformed",
): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new WardError(code);
  try {
    return new Uint8Array(value);
  } catch {
    throw new WardError(code);
  }
}

function ownKey(value: unknown): Uint8Array {
  const key = ownBytes(value, "vault_key_invalid");
  if (key.length !== envelopeLimits.keyBytes)
    throw new WardError("vault_key_invalid");
  return key;
}

function withinLimit(bytes: Uint8Array): Uint8Array {
  if (bytes.length > envelopeLimits.maxPlaintextBytes)
    throw new WardError("vault_record_too_large");
  return bytes;
}

function ownHeader(value: unknown): EnvelopeHeader {
  if (typeof value !== "object" || value === null)
    throw new WardError("vault_record_malformed");
  const source = value as Record<string, unknown>;
  const header = {
    formatVersion: source.formatVersion,
    vaultId: source.vaultId,
    revision: source.revision,
  };
  if (header.formatVersion !== formatVersion)
    throw new WardError("vault_format_unsupported");
  if (!isOpaqueId(header.vaultId))
    throw new WardError("vault_record_malformed");
  if (
    typeof header.revision !== "number" ||
    !Number.isSafeInteger(header.revision) ||
    header.revision < 1
  )
    throw new WardError("vault_record_malformed");
  return {
    formatVersion: header.formatVersion,
    vaultId: header.vaultId,
    revision: header.revision,
  };
}

// Validates a header read from storage without the key, with the same
// grammar and failure codes as open().
export function parseHeader(value: unknown): EnvelopeHeader {
  return ownHeader(value);
}

// Deterministic: a fixed-order JSON array of validated fields, so the same
// header always yields the same bytes.
function encodeHeader(header: EnvelopeHeader): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      envelopeDomain,
      header.formatVersion,
      header.vaultId,
      header.revision,
    ]),
  );
}

export function associatedData(header: EnvelopeHeader): Uint8Array {
  return encodeHeader(ownHeader(header));
}

export function seal(
  key: Uint8Array,
  header: Omit<EnvelopeHeader, "formatVersion">,
  plaintext: Uint8Array,
): SealedRecord {
  const ownedKey = ownKey(key);
  const fields =
    typeof header === "object" && header !== null
      ? { vaultId: header.vaultId, revision: header.revision }
      : header;
  const ownedHeader = ownHeader({ formatVersion, ...fields });
  const ownedPlaintext = withinLimit(
    ownBytes(plaintext, "vault_record_malformed"),
  );
  const nonce = new Uint8Array(randomBytes(envelopeLimits.nonceBytes));
  const cipher = createCipheriv("aes-256-gcm", ownedKey, nonce, {
    authTagLength: envelopeLimits.tagBytes,
  });
  cipher.setAAD(encodeHeader(ownedHeader));
  const ciphertext = Buffer.concat([
    cipher.update(ownedPlaintext),
    cipher.final(),
  ]);
  // Field by field, so nothing a caller attached to the header is carried
  // into a record the storage layer persists.
  return {
    formatVersion: ownedHeader.formatVersion,
    vaultId: ownedHeader.vaultId,
    revision: ownedHeader.revision,
    nonce,
    ciphertext: new Uint8Array(ciphertext),
    tag: new Uint8Array(cipher.getAuthTag()),
  };
}

// Every length, the format and the header are checked before the cipher
// runs, and no plaintext leaves this function until the tag has verified.
// Node's decipher.update() hands out bytes before final() authenticates
// them, so those bytes are held here and zeroed if authentication fails.
// The zeroing is best effort and is not asserted by a test; nothing is
// claimed about copies the runtime makes internally.
export function open(key: Uint8Array, record: SealedRecord): Uint8Array {
  const ownedKey = ownKey(key);
  const header = ownHeader(record);
  const nonce = ownBytes(record.nonce, "vault_record_malformed");
  const tag = ownBytes(record.tag, "vault_record_malformed");
  const ciphertext = withinLimit(
    ownBytes(record.ciphertext, "vault_record_malformed"),
  );
  if (nonce.length !== envelopeLimits.nonceBytes)
    throw new WardError("vault_record_malformed");
  if (tag.length !== envelopeLimits.tagBytes)
    throw new WardError("vault_record_malformed");

  const decipher = createDecipheriv("aes-256-gcm", ownedKey, nonce, {
    authTagLength: envelopeLimits.tagBytes,
  });
  decipher.setAAD(encodeHeader(header));
  decipher.setAuthTag(tag);
  const unverified = decipher.update(ciphertext);
  try {
    decipher.final();
  } catch {
    unverified.fill(0);
    throw new WardError("vault_authentication_failed");
  }
  const plaintext = new Uint8Array(unverified);
  unverified.fill(0);
  return plaintext;
}
