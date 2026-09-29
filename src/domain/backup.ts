// The backup container (spec §10, docs/adr/0006). A backup is the vault's
// plaintext sealed a second time under a key derived from a passphrase, so
// it can be opened on a machine that has neither this vault's key nor the OS
// credential store item. Copying ward.db alone does not provide that
// property, which is why this is a container and not a database copy; and
// nothing here promises erasure of an old backup or revocation at a provider
// after a restore.
//
// v1 is one named parameter set: scrypt with N=131072, r=8, p=1, a fresh
// 32-byte salt, a 32-byte output key, and AES-256-GCM with a fresh 12-byte
// nonce. The parameters travel in the container and are authenticated as
// header data together with the domain, the format version, the origin vault
// id and its revision, so a container relabelled with another parameter set,
// another vault or another format fails to open rather than being read as
// something it is not.
//
// A file's parameters are attacker-controlled input: the set they name
// decides how much memory the derivation allocates. The set is therefore
// matched exactly and refused BEFORE the KDF runs — never clamped, never
// widened, and never weakened automatically to make a slow machine pass. The
// parameters are proposed format parameters, not a claim of a universal
// security standard, and passphrase entropy matters: length alone is not
// proof of strength (both are spec §10's own words, carried into the
// command's guidance).
//
// What this module does not do: read or write files, read the terminal, or
// decide whether a restore is allowed. Those belong to the application layer
// and its ports.
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { WardError } from "../contract/errors.ts";
import { isOpaqueId } from "./identifiers.ts";

export const backupDomain = "opum.ward.backup";
export const backupFormatVersion = 1;

export const backupLimits = {
  keyBytes: 32,
  saltBytes: 32,
  nonceBytes: 12,
  tagBytes: 16,
  // The vault's own plaintext cap, which a backup carries at most.
  maxPlaintextBytes: 10 * 1024 * 1024,
  // Base64 turns the ciphertext into 4/3 of its bytes; the rest is header.
  // A file larger than this is refused before it is decoded.
  maxContainerBytes: 14 * 1024 * 1024,
} as const;

export interface BackupKdf {
  readonly name: "scrypt";
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly salt: Uint8Array;
}

export interface BackupHeader {
  readonly formatVersion: number;
  readonly vaultId: string;
  readonly revision: number;
  readonly kdf: BackupKdf;
}

export interface SealedBackup extends BackupHeader {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

// The one parameter set this build writes and reads.
export const backupKdfParams = {
  name: "scrypt",
  N: 131072,
  r: 8,
  p: 1,
} as const;

// 128 * N * r for scrypt's own table plus Node's small constant. Node
// refuses the derivation without it, because its default bound (32 MiB) sits
// below the parameters spec §10 proposes.
export const backupKdfMemoryBytes =
  128 * backupKdfParams.N * backupKdfParams.r + 1024 * 1024;

export function newBackupKdf(): BackupKdf {
  return {
    ...backupKdfParams,
    salt: new Uint8Array(randomBytes(backupLimits.saltBytes)),
  };
}

function ownBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new WardError("backup_malformed");
  try {
    return new Uint8Array(value);
  } catch {
    throw new WardError("backup_malformed");
  }
}

// The parameter set is matched before any of its fields is used, so a file
// naming a set this build does not implement is refused without a byte of
// memory being allocated for it.
function ownKdf(value: unknown): BackupKdf {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new WardError("backup_malformed");
  const source = value as Record<string, unknown>;
  if (source.name !== backupKdfParams.name)
    throw new WardError("backup_unsupported");
  if (
    source.N !== backupKdfParams.N ||
    source.r !== backupKdfParams.r ||
    source.p !== backupKdfParams.p
  )
    throw new WardError("backup_unsupported");
  const salt = ownBytes(source.salt);
  if (salt.length !== backupLimits.saltBytes)
    throw new WardError("backup_malformed");
  return {
    name: backupKdfParams.name,
    N: backupKdfParams.N,
    r: backupKdfParams.r,
    p: backupKdfParams.p,
    salt,
  };
}

function ownHeader(value: unknown): BackupHeader {
  if (typeof value !== "object" || value === null)
    throw new WardError("backup_malformed");
  const source = value as Record<string, unknown>;
  if (source.formatVersion !== backupFormatVersion)
    throw new WardError("backup_unsupported");
  if (!isOpaqueId(source.vaultId)) throw new WardError("backup_malformed");
  if (
    typeof source.revision !== "number" ||
    !Number.isSafeInteger(source.revision) ||
    source.revision < 1
  )
    throw new WardError("backup_malformed");
  return {
    formatVersion: backupFormatVersion,
    vaultId: source.vaultId,
    revision: source.revision,
    kdf: ownKdf(source.kdf),
  };
}

function ownRecord(value: unknown): SealedBackup {
  const header = ownHeader(value);
  const source = value as Record<string, unknown>;
  const nonce = ownBytes(source.nonce);
  const tag = ownBytes(source.tag);
  const ciphertext = ownBytes(source.ciphertext);
  if (
    nonce.length !== backupLimits.nonceBytes ||
    tag.length !== backupLimits.tagBytes
  )
    throw new WardError("backup_malformed");
  if (ciphertext.length > backupLimits.maxPlaintextBytes)
    throw new WardError("backup_too_large");
  return { ...header, nonce, ciphertext, tag };
}

// Deterministic: a fixed-order JSON array of validated fields, so the same
// header always yields the same bytes, and every field a restore relies on
// is covered by the tag.
function encodeHeader(header: BackupHeader): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      backupDomain,
      header.formatVersion,
      header.vaultId,
      header.revision,
      header.kdf.name,
      header.kdf.N,
      header.kdf.r,
      header.kdf.p,
      Buffer.from(header.kdf.salt).toString("base64"),
    ]),
  );
}

export function backupAssociatedData(header: BackupHeader): Uint8Array {
  return encodeHeader(ownHeader(header));
}

// The passphrase never reaches argv or the environment (spec §8, §10); it
// arrives here as the bytes a terminal read, and both the caller's copy and
// the derived key are the caller's to zero.
export function deriveBackupKey(
  passphrase: Uint8Array,
  kdf: BackupKdf,
): Uint8Array {
  const ownedKdf = ownKdf(kdf);
  const owned = ownBytes(passphrase);
  return new Uint8Array(
    scryptSync(owned, ownedKdf.salt, backupLimits.keyBytes, {
      N: ownedKdf.N,
      r: ownedKdf.r,
      p: ownedKdf.p,
      maxmem: backupKdfMemoryBytes,
    }),
  );
}

export function sealBackup(
  key: Uint8Array,
  header: Omit<BackupHeader, "formatVersion">,
  plaintext: Uint8Array,
): SealedBackup {
  const ownedKey = ownBytes(key);
  if (ownedKey.length !== backupLimits.keyBytes)
    throw new WardError("backup_malformed");
  const ownedHeader = ownHeader({
    formatVersion: backupFormatVersion,
    ...header,
  });
  const ownedPlaintext = ownBytes(plaintext);
  if (ownedPlaintext.length > backupLimits.maxPlaintextBytes)
    throw new WardError("backup_too_large");
  const nonce = new Uint8Array(randomBytes(backupLimits.nonceBytes));
  const cipher = createCipheriv("aes-256-gcm", ownedKey, nonce, {
    authTagLength: backupLimits.tagBytes,
  });
  cipher.setAAD(encodeHeader(ownedHeader));
  const ciphertext = Buffer.concat([
    cipher.update(ownedPlaintext),
    cipher.final(),
  ]);
  return {
    formatVersion: ownedHeader.formatVersion,
    vaultId: ownedHeader.vaultId,
    revision: ownedHeader.revision,
    kdf: ownedHeader.kdf,
    nonce,
    ciphertext: new Uint8Array(ciphertext),
    tag: new Uint8Array(cipher.getAuthTag()),
  };
}

// No plaintext leaves this function until the tag has verified. Node's
// decipher hands out bytes before final() authenticates them, so they are
// held and zeroed if authentication fails; nothing is claimed about copies
// the runtime makes internally.
export function openBackup(key: Uint8Array, record: SealedBackup): Uint8Array {
  const ownedKey = ownBytes(key);
  if (ownedKey.length !== backupLimits.keyBytes)
    throw new WardError("backup_malformed");
  const owned = ownRecord(record);
  const decipher = createDecipheriv("aes-256-gcm", ownedKey, owned.nonce, {
    authTagLength: backupLimits.tagBytes,
  });
  decipher.setAAD(encodeHeader(owned));
  decipher.setAuthTag(owned.tag);
  const unverified = decipher.update(owned.ciphertext);
  try {
    decipher.final();
  } catch {
    unverified.fill(0);
    // A wrong passphrase and a damaged file are the same signal here, and
    // the catalog says so rather than guessing which one happened.
    throw new WardError("backup_open_failed");
  }
  const plaintext = new Uint8Array(unverified);
  unverified.fill(0);
  return plaintext;
}

// The container on disk: JSON text, so a person can see the format version,
// the parameters and that it holds no plaintext, without any part of it
// being trusted on the way back in.
export function encodeBackup(record: SealedBackup): Uint8Array {
  const owned = ownRecord(record);
  const text = `${JSON.stringify(
    {
      formatVersion: owned.formatVersion,
      vaultId: owned.vaultId,
      revision: owned.revision,
      kdf: {
        name: owned.kdf.name,
        N: owned.kdf.N,
        r: owned.kdf.r,
        p: owned.kdf.p,
        salt: Buffer.from(owned.kdf.salt).toString("base64"),
      },
      nonce: Buffer.from(owned.nonce).toString("base64"),
      ciphertext: Buffer.from(owned.ciphertext).toString("base64"),
      tag: Buffer.from(owned.tag).toString("base64"),
    },
    null,
    2,
  )}\n`;
  return new TextEncoder().encode(text);
}

function decodeBase64(value: unknown): Uint8Array {
  if (typeof value !== "string") throw new WardError("backup_malformed");
  const buffer = Buffer.from(value, "base64");
  // Node's decoder ignores characters it does not recognize, so a string
  // that is not the canonical encoding of its own bytes is refused rather
  // than accepted as a different value.
  if (buffer.toString("base64") !== value)
    throw new WardError("backup_malformed");
  return new Uint8Array(buffer);
}

export function parseBackup(bytes: Uint8Array): SealedBackup {
  const owned = ownBytes(bytes);
  if (owned.length > backupLimits.maxContainerBytes)
    throw new WardError("backup_too_large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(owned),
    );
  } catch {
    throw new WardError("backup_malformed");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    throw new WardError("backup_malformed");
  const source = parsed as Record<string, unknown>;
  const kdf = source.kdf;
  if (typeof kdf !== "object" || kdf === null || Array.isArray(kdf))
    throw new WardError("backup_malformed");
  const kdfFields = kdf as Record<string, unknown>;
  // Decoded before the parameter set is judged, and that order matters only
  // in the harmless direction: the bytes decoded are the file's own, already
  // bounded by the container limit above, and the parameters are still
  // refused before any derivation allocates for them.
  return ownRecord({
    formatVersion: source.formatVersion,
    vaultId: source.vaultId,
    revision: source.revision,
    kdf: { ...kdfFields, salt: decodeBase64(kdfFields.salt) },
    nonce: decodeBase64(source.nonce),
    ciphertext: decodeBase64(source.ciphertext),
    tag: decodeBase64(source.tag),
  });
}
