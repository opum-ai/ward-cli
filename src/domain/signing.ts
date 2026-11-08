// The Ed25519 sign operation (DEC-262 (2)). A key is generated inside Ward
// and held as a SecretRecord of kind "ed25519" whose value is the 32-byte
// private seed. Nothing here returns the seed: the only outputs are a public
// key and a signature, and every failure is a fixed error that carries no key
// material.
//
// Ward signs exactly the bytes it is given. Domain separation is the
// caller's: a caller prefixes its own bytes. `startsWithAllowedPrefix` only
// lets an approved profile restrict which prefixes may be signed; it never
// adds, strips or rewrites anything.
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { WardError } from "../contract/errors.ts";
import { signKeySeedBytes } from "./secret.ts";

// PKCS#8 for an Ed25519 private key is this fixed 16-byte prefix followed by
// the 32-byte seed (RFC 8410), so a seed alone is enough to rebuild the key.
const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");

export const signatureBytes = 64;
export const publicKeyBytes = 32;

export interface GeneratedSignKey {
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;
}

function privateKeyOf(seed: Uint8Array) {
  if (seed.length !== signKeySeedBytes)
    throw new WardError("vault_state_malformed");
  // The DER copy holds the seed, so it is zeroed once the key object exists.
  const der = Buffer.concat([pkcs8Prefix, seed]);
  try {
    return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } finally {
    der.fill(0);
  }
}

function rawPublicKey(key: ReturnType<typeof createPublicKey>): Uint8Array {
  // The SPKI form of an Ed25519 key ends with the 32 raw public bytes.
  const der = key.export({ format: "der", type: "spki" });
  return new Uint8Array(der.subarray(der.length - publicKeyBytes));
}

export function generateSignKey(): GeneratedSignKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const seed = new Uint8Array(der.subarray(der.length - signKeySeedBytes));
  der.fill(0);
  return { seed, publicKey: rawPublicKey(publicKey) };
}

export function publicKeyOf(seed: Uint8Array): Uint8Array {
  return rawPublicKey(createPublicKey(privateKeyOf(seed)));
}

export function signBytes(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(sign(null, message, privateKeyOf(seed)));
}

// An empty list allows no input at all: a sign approval must name at least
// one prefix, so an approval can never mean "any bytes".
export function startsWithAllowedPrefix(
  message: Uint8Array,
  prefixes: readonly Uint8Array[],
): boolean {
  return prefixes.some(
    (prefix) =>
      prefix.length > 0 &&
      message.length >= prefix.length &&
      prefix.every((byte, index) => message[index] === byte),
  );
}
