// Prints the CDHash of a thin arm64 or x86_64 Mach-O executable, the value
// `codesign -dvvv` reports as CDHash= and the one the macOS keychain's trust in
// an ad-hoc signed binary follows (WCLI-82). The release workflow runs on
// Linux, which has no codesign, and the release notes carry this value so a
// person can compare it with what the installed binary reports.
//
// The cdhash is the first 20 bytes of the hash of the primary CodeDirectory
// blob, hashed with the directory's own hash type.
//
// Usage: node scripts/macho-cdhash.mjs <file>
// Exit 0 with the 40 hex digits on stdout, or exit 1 naming what was not found.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const MH_MAGIC_64 = 0xfeedfacf;
const LC_CODE_SIGNATURE = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSSLOT_CODEDIRECTORY = 0;
const hashNames = { 1: "sha1", 2: "sha256", 3: "sha256", 4: "sha384" };

function fail(message) {
  console.error(`macho-cdhash: ${message}`);
  process.exit(1);
}

const file = process.argv[2];
if (file === undefined) fail("usage: macho-cdhash.mjs <file>");
const bytes = readFileSync(file);
if (bytes.length < 32 || bytes.readUInt32LE(0) !== MH_MAGIC_64)
  fail(`${file} is not a thin 64-bit little-endian Mach-O executable`);

const commandCount = bytes.readUInt32LE(16);
let offset = 32;
let signature;
for (let i = 0; i < commandCount; i++) {
  const command = bytes.readUInt32LE(offset);
  const size = bytes.readUInt32LE(offset + 4);
  if (command === LC_CODE_SIGNATURE) {
    signature = {
      start: bytes.readUInt32LE(offset + 8),
      length: bytes.readUInt32LE(offset + 12),
    };
    break;
  }
  if (size < 8) fail("a load command has an impossible size");
  offset += size;
}
if (signature === undefined) fail("no LC_CODE_SIGNATURE load command");

const blob = bytes.subarray(
  signature.start,
  signature.start + signature.length,
);
if (blob.readUInt32BE(0) !== CSMAGIC_EMBEDDED_SIGNATURE)
  fail("the signature is not an embedded superblob");

const entries = blob.readUInt32BE(8);
for (let i = 0; i < entries; i++) {
  const type = blob.readUInt32BE(12 + i * 8);
  const at = blob.readUInt32BE(16 + i * 8);
  if (type !== CSSLOT_CODEDIRECTORY) continue;
  if (blob.readUInt32BE(at) !== CSMAGIC_CODEDIRECTORY)
    fail("the primary slot is not a CodeDirectory");
  const length = blob.readUInt32BE(at + 4);
  const algorithm = hashNames[blob[at + 37]];
  if (algorithm === undefined)
    fail(`unknown CodeDirectory hash type ${blob[at + 37]}`);
  const directory = blob.subarray(at, at + length);
  console.log(
    createHash(algorithm).update(directory).digest("hex").slice(0, 40),
  );
  process.exit(0);
}
fail("no primary CodeDirectory in the signature");
