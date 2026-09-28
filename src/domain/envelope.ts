import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { WardError } from "../contract/errors.ts";

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
// A random 96-bit nonce is safe for well under 2^32 seals per key (NIST SP
// 800-38D §8.3). Ward seals once per vault mutation, which stays far below
// that on a single developer's machine.

export const envelopeDomain = "opum.ward.vault";
export const formatVersion = 1;

export const envelopeLimits = {
  keyBytes: 32,
  nonceBytes: 12,
  tagBytes: 16,
  // Proposed v0.1 product limit for the logical vault (spec §6.3).
  maxPlaintextBytes: 10 * 1024 * 1024,
} as const;

// crypto.randomUUID() output: lowercase, version 4, RFC 9562 variant. The
// grammar is strict so the authenticated data has exactly one encoding.
const vaultIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

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

function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== envelopeLimits.keyBytes)
    throw new WardError("vault_key_invalid");
}

function assertHeader(header: EnvelopeHeader): void {
  if (header.formatVersion !== formatVersion)
    throw new WardError("vault_format_unsupported");
  if (
    typeof header.vaultId !== "string" ||
    !vaultIdPattern.test(header.vaultId)
  )
    throw new WardError("vault_record_malformed");
  if (!Number.isSafeInteger(header.revision) || header.revision < 1)
    throw new WardError("vault_record_malformed");
}

function assertBytes(value: unknown, length?: number): void {
  if (!(value instanceof Uint8Array))
    throw new WardError("vault_record_malformed");
  if (length !== undefined && value.length !== length)
    throw new WardError("vault_record_malformed");
}

// Deterministic: a fixed-order JSON array of validated fields, so the same
// header always yields the same bytes.
export function associatedData(header: EnvelopeHeader): Uint8Array {
  assertHeader(header);
  return new TextEncoder().encode(
    JSON.stringify([
      envelopeDomain,
      header.formatVersion,
      header.vaultId,
      header.revision,
    ]),
  );
}

// The AES-256-GCM primitive with a caller-supplied nonce. Exported only so
// known-answer tests can drive it; everything else seals through seal(),
// which never takes a nonce from its caller.
export function encryptWithNonce(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const cipher = createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: envelopeLimits.tagBytes,
  });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: new Uint8Array(ciphertext),
    tag: new Uint8Array(cipher.getAuthTag()),
  };
}

export function seal(
  key: Uint8Array,
  header: Omit<EnvelopeHeader, "formatVersion">,
  plaintext: Uint8Array,
): SealedRecord {
  assertKey(key);
  const full: EnvelopeHeader = { formatVersion, ...header };
  const aad = associatedData(full);
  assertBytes(plaintext);
  if (plaintext.length > envelopeLimits.maxPlaintextBytes)
    throw new WardError("vault_record_too_large");
  const nonce = new Uint8Array(randomBytes(envelopeLimits.nonceBytes));
  return { ...full, nonce, ...encryptWithNonce(key, nonce, aad, plaintext) };
}

// Every length, the format and the header are checked before the cipher
// runs, and no plaintext leaves this function until the tag has verified.
// Node's decipher.update() hands out bytes before final() authenticates
// them, so those bytes are held here and zeroed if authentication fails.
export function open(key: Uint8Array, record: SealedRecord): Uint8Array {
  assertKey(key);
  const aad = associatedData(record);
  assertBytes(record.nonce, envelopeLimits.nonceBytes);
  assertBytes(record.tag, envelopeLimits.tagBytes);
  assertBytes(record.ciphertext);
  if (record.ciphertext.length > envelopeLimits.maxPlaintextBytes)
    throw new WardError("vault_record_too_large");

  const decipher = createDecipheriv("aes-256-gcm", key, record.nonce, {
    authTagLength: envelopeLimits.tagBytes,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(record.tag);
  const unverified = decipher.update(record.ciphertext);
  try {
    decipher.final();
  } catch {
    unverified.fill(0);
    throw new WardError("vault_authentication_failed");
  }
  // Copied out, then the source zeroed: a small Buffer can be a view into a
  // shared allocation pool, which a returned view would keep reachable.
  const plaintext = new Uint8Array(unverified);
  unverified.fill(0);
  return plaintext;
}
