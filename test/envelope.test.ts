// Release gates T03 (crypto) and T04 (authentication) for the vault
// envelope, spec §6.3. Keys and plaintexts are synthetic; nothing here reads
// a keychain or ~/.ward.
import { describe, expect, test } from "bun:test";
import { createCipheriv, createDecipheriv } from "node:crypto";
import type { ErrorCode } from "../src/contract/errors.ts";
import { WardError } from "../src/contract/errors.ts";
import {
  associatedData,
  envelopeLimits,
  generateVaultKey,
  open,
  type SealedRecord,
  seal,
} from "../src/domain/envelope.ts";

const hex = (value: string) => new Uint8Array(Buffer.from(value, "hex"));
const toHex = (value: Uint8Array) => Buffer.from(value).toString("hex");
const utf8 = (value: string) => new TextEncoder().encode(value);

const VAULT_ID = "3f1c2b7e-9a4d-4e6f-8b21-5c7d9e0a1b2c";
const OTHER_VAULT_ID = "9b0e4d1a-2c3f-4a5b-9c6d-7e8f0a1b2c3d";

function failsWith(code: ErrorCode, run: () => unknown): void {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(WardError);
  expect((caught as WardError).code).toBe(code);
}

function sealed(plaintext = utf8('{"schema":1,"secrets":{}}')) {
  const key = generateVaultKey();
  const record = seal(key, { vaultId: VAULT_ID, revision: 3 }, plaintext);
  return { key, record, plaintext };
}

// McGrew and Viega, "The Galois/Counter Mode of Operation", test cases 13-16
// (the AES-256, 96-bit IV cases). Run against the runtime's node:crypto in
// both directions, which is the parity check spec §13 asks for. Matched by
// Bun (BoringSSL) and, when these were recorded, by Node 24.20 (OpenSSL
// 3.5.7).
const K16 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const P64 =
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const C64 =
  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
const knownAnswers: [
  name: string,
  key: string,
  nonce: string,
  aad: string,
  plaintext: string,
  ciphertext: string,
  tag: string,
][] = [
  [
    "test case 13",
    "00".repeat(32),
    "00".repeat(12),
    "",
    "",
    "",
    "530f8afbc74536b9a963b4f1c4cb738b",
  ],
  [
    "test case 14",
    "00".repeat(32),
    "00".repeat(12),
    "",
    "00".repeat(16),
    "cea7403d4d606b6e074ec5d3baf39d18",
    "d0d1c8a799996bf0265b98b5d48ab919",
  ],
  [
    "test case 15",
    K16,
    "cafebabefacedbaddecaf888",
    "",
    P64,
    C64,
    "b094dac5d93471bdec1a502270e3cc6c",
  ],
  [
    "test case 16",
    K16,
    "cafebabefacedbaddecaf888",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    P64.slice(0, 120),
    C64.slice(0, 120),
    "76fc6ece0f4e1768cddf8853bb2d551b",
  ],
];

describe("T03: AES-256-GCM known answers", () => {
  for (const [
    name,
    key,
    nonce,
    aad,
    plaintext,
    ciphertext,
    tag,
  ] of knownAnswers)
    test(name, () => {
      const cipher = createCipheriv("aes-256-gcm", hex(key), hex(nonce));
      cipher.setAAD(hex(aad));
      const out = Buffer.concat([
        cipher.update(hex(plaintext)),
        cipher.final(),
      ]);
      expect(out.toString("hex")).toBe(ciphertext);
      expect(cipher.getAuthTag().toString("hex")).toBe(tag);

      const decipher = createDecipheriv("aes-256-gcm", hex(key), hex(nonce));
      decipher.setAAD(hex(aad));
      decipher.setAuthTag(hex(tag));
      const back = Buffer.concat([
        decipher.update(hex(ciphertext)),
        decipher.final(),
      ]);
      expect(back.toString("hex")).toBe(plaintext);
    });

  // Pins the envelope's own format: the authenticated-data encoding, field
  // order and domain. Recorded identically under Bun and Node 24.20; changing
  // any of them is a format change and must bump formatVersion.
  test("golden envelope record opens, and its authenticated data is fixed", () => {
    const header = { formatVersion: 1, vaultId: VAULT_ID, revision: 7 };
    expect(new TextDecoder().decode(associatedData(header))).toBe(
      `["opum.ward.vault",1,"${VAULT_ID}",7]`,
    );
    const record: SealedRecord = {
      ...header,
      nonce: hex("000102030405060708090a0b"),
      ciphertext: hex("3c20a578ad80af7aaf7ba6f6"),
      tag: hex("b22cc8b3e67d938b56abe7bdf3d7d0b6"),
    };
    const key = new Uint8Array([...Array(32).keys()]);
    expect(new TextDecoder().decode(open(key, record))).toBe('{"schema":1}');
  });
});

describe("T03: round trip and limits", () => {
  for (const size of [0, 1, 64 * 1024, envelopeLimits.maxPlaintextBytes])
    test(`${size} bytes`, () => {
      const plaintext = new Uint8Array(size).fill(0x5a);
      const { key, record } = sealed(plaintext);
      expect(record.formatVersion).toBe(1);
      expect(record.nonce.length).toBe(envelopeLimits.nonceBytes);
      expect(record.tag.length).toBe(envelopeLimits.tagBytes);
      expect(record.ciphertext.length).toBe(size);
      expect(open(key, record)).toEqual(plaintext);
    });

  test("one byte over the limit is refused on seal and on open", () => {
    const over = new Uint8Array(envelopeLimits.maxPlaintextBytes + 1);
    failsWith("vault_record_too_large", () =>
      seal(generateVaultKey(), { vaultId: VAULT_ID, revision: 1 }, over),
    );
    const { key, record } = sealed();
    failsWith("vault_record_too_large", () =>
      open(key, { ...record, ciphertext: over }),
    );
  });

  test("generated keys are 32 bytes and distinct", () => {
    const keys = Array.from({ length: 64 }, () => toHex(generateVaultKey()));
    expect(keys.every((key) => key.length === 64)).toBe(true);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("T03: nonce sampling", () => {
  const samples = 10_000;
  const nonces = Array.from(
    { length: samples },
    () => sealed(utf8("same")).record,
  );

  test("every seal draws a fresh nonce", () => {
    expect(new Set(nonces.map((record) => toHex(record.nonce))).size).toBe(
      samples,
    );
  });

  test("identical plaintexts never produce identical ciphertexts", () => {
    const key = generateVaultKey();
    const outputs = Array.from({ length: 1000 }, () =>
      toHex(
        seal(key, { vaultId: VAULT_ID, revision: 1 }, utf8("same")).ciphertext,
      ),
    );
    expect(new Set(outputs).size).toBe(outputs.length);
  });

  // A crude bias check, not a randomness test: 960,000 bits from a uniform
  // source land within 0.5% of half set with overwhelming probability.
  test("nonce bits are balanced", () => {
    let ones = 0;
    for (const { nonce } of nonces)
      for (const byte of nonce)
        for (let bit = 0; bit < 8; bit++) ones += (byte >> bit) & 1;
    const fraction = ones / (samples * envelopeLimits.nonceBytes * 8);
    expect(Math.abs(fraction - 0.5)).toBeLessThan(0.005);
  });
});

describe("T03: wrong key and malformed lengths", () => {
  test("a different key fails authentication", () => {
    const { record } = sealed();
    failsWith("vault_authentication_failed", () =>
      open(generateVaultKey(), record),
    );
  });

  for (const length of [0, 16, 31, 33, 64])
    test(`a ${length}-byte key is refused`, () => {
      const key = new Uint8Array(length);
      failsWith("vault_key_invalid", () =>
        seal(key, { vaultId: VAULT_ID, revision: 1 }, utf8("x")),
      );
      failsWith("vault_key_invalid", () => open(key, sealed().record));
    });

  for (const [field, lengths] of [
    ["nonce", [0, 8, 11, 13, 16]],
    ["tag", [0, 4, 12, 15, 17]],
  ] as const)
    for (const length of lengths)
      test(`a ${length}-byte ${field} is refused`, () => {
        const { key, record } = sealed();
        failsWith("vault_record_malformed", () =>
          open(key, { ...record, [field]: new Uint8Array(length) }),
        );
      });

  for (const field of ["nonce", "tag", "ciphertext"] as const)
    test(`a ${field} that is not bytes is refused`, () => {
      const { key, record } = sealed();
      failsWith("vault_record_malformed", () =>
        open(key, { ...record, [field]: "AAAA" } as unknown as SealedRecord),
      );
    });

  const badVaultIds: unknown[] = [
    "",
    VAULT_ID.toUpperCase(),
    `${VAULT_ID} `,
    "3f1c2b7e-9a4d-1e6f-8b21-5c7d9e0a1b2c",
    "3f1c2b7e-9a4d-4e6f-cb21-5c7d9e0a1b2c",
    "../../etc/passwd",
    42,
  ];
  for (const vaultId of badVaultIds)
    test(`vault id ${JSON.stringify(vaultId)} is refused`, () => {
      const { key, record } = sealed();
      failsWith("vault_record_malformed", () =>
        open(key, { ...record, vaultId } as SealedRecord),
      );
      failsWith("vault_record_malformed", () =>
        seal(key, { vaultId, revision: 1 } as SealedRecord, utf8("x")),
      );
    });

  for (const revision of [0, -1, 1.5, Number.NaN, 2 ** 53, "1"])
    test(`revision ${String(revision)} is refused`, () => {
      const { key, record } = sealed();
      failsWith("vault_record_malformed", () =>
        open(key, { ...record, revision } as SealedRecord),
      );
    });

  for (const version of [0, 2, "1"])
    test(`format version ${JSON.stringify(version)} is unsupported`, () => {
      const { key, record } = sealed();
      failsWith("vault_format_unsupported", () =>
        open(key, { ...record, formatVersion: version } as SealedRecord),
      );
    });
});

describe("T04: any change fails before plaintext is returned", () => {
  for (const field of ["ciphertext", "nonce", "tag"] as const)
    for (const mask of [0x01, 0x80])
      test(`flipping mask 0x${mask.toString(16)} in every ${field} byte`, () => {
        const { key, record } = sealed(new Uint8Array(48).fill(0x33));
        for (let index = 0; index < record[field].length; index++) {
          const tampered = new Uint8Array(record[field]);
          tampered[index] = (tampered[index] ?? 0) ^ mask;
          failsWith("vault_authentication_failed", () =>
            open(key, { ...record, [field]: tampered }),
          );
        }
      });

  test("truncating or extending the ciphertext", () => {
    const { key, record } = sealed(new Uint8Array(48).fill(0x33));
    for (const ciphertext of [
      record.ciphertext.subarray(0, 47),
      new Uint8Array([...record.ciphertext, 0]),
      new Uint8Array(0),
    ])
      failsWith("vault_authentication_failed", () =>
        open(key, { ...record, ciphertext }),
      );
  });

  test("moving the record to another vault", () => {
    const { key, record } = sealed();
    failsWith("vault_authentication_failed", () =>
      open(key, { ...record, vaultId: OTHER_VAULT_ID }),
    );
  });

  test("changing one character of the vault id", () => {
    const { key, record } = sealed();
    for (let index = 0; index < VAULT_ID.length; index++) {
      const char = VAULT_ID[index];
      if (char === "-" || index === 14) continue;
      const replacement = char === "a" ? "b" : "a";
      const vaultId =
        VAULT_ID.slice(0, index) + replacement + VAULT_ID.slice(index + 1);
      failsWith("vault_authentication_failed", () =>
        open(key, { ...record, vaultId }),
      );
    }
  });

  for (const revision of [2, 4, 1, 1000])
    test(`relabelling revision 3 as ${revision}`, () => {
      const { key, record } = sealed();
      failsWith("vault_authentication_failed", () =>
        open(key, { ...record, revision }),
      );
    });
});

// Hostile-shaped inputs (review of PR #10). None of these is reachable from a
// record deserialized out of SQLite, but the envelope must not depend on that.
class LyingLength extends Uint8Array {
  constructor(
    bytes: number,
    private readonly claimed: number,
  ) {
    super(bytes);
  }
  override get length(): number {
    return this.claimed;
  }
}

describe("inputs are read once and copied before use", () => {
  test("a view claiming a smaller length cannot bypass the size limit", () => {
    const over = envelopeLimits.maxPlaintextBytes + 1;
    failsWith("vault_record_too_large", () =>
      seal(
        generateVaultKey(),
        { vaultId: VAULT_ID, revision: 1 },
        new LyingLength(over, 1),
      ),
    );
    const { key, record } = sealed();
    failsWith("vault_record_too_large", () =>
      open(key, { ...record, ciphertext: new LyingLength(over, 1) }),
    );
  });

  test("a short nonce, tag or key claiming the right length is refused", () => {
    const { key, record } = sealed();
    failsWith("vault_record_malformed", () =>
      open(key, { ...record, nonce: new LyingLength(8, 12) }),
    );
    failsWith("vault_record_malformed", () =>
      open(key, { ...record, tag: new LyingLength(4, 16) }),
    );
    failsWith("vault_key_invalid", () => open(new LyingLength(16, 32), record));
  });

  test("each header field is read exactly once", () => {
    const { key, record } = sealed();
    let reads = 0;
    const header = {
      ...record,
      get revision() {
        reads += 1;
        return reads === 1 ? 3 : 1e21;
      },
    };
    expect(open(key, header)).toEqual(sealed().plaintext);
    expect(reads).toBe(1);
  });

  test("a SharedArrayBuffer-backed key is copied, not used in place", () => {
    const { key, record } = sealed();
    const shared = new Uint8Array(new SharedArrayBuffer(32));
    shared.set(key);
    expect(open(shared, record)).toEqual(sealed().plaintext);
  });

  test("the sealed record carries only envelope fields", () => {
    const record = seal(
      generateVaultKey(),
      {
        vaultId: VAULT_ID,
        revision: 1,
        formatVersion: 9,
        note: "unencrypted",
      } as unknown as { vaultId: string; revision: number },
      utf8("x"),
    );
    expect(Object.keys(record)).toEqual([
      "formatVersion",
      "vaultId",
      "revision",
      "nonce",
      "ciphertext",
      "tag",
    ]);
    expect(record.formatVersion).toBe(1);
  });

  test("non-byte plaintext, a missing record or header, and a fake key are refused", () => {
    const key = generateVaultKey();
    failsWith("vault_record_malformed", () =>
      seal(
        key,
        { vaultId: VAULT_ID, revision: 1 },
        "text" as unknown as Uint8Array,
      ),
    );
    failsWith("vault_record_malformed", () =>
      open(key, null as unknown as SealedRecord),
    );
    failsWith("vault_record_malformed", () =>
      seal(
        key,
        null as unknown as { vaultId: string; revision: number },
        utf8("x"),
      ),
    );
    failsWith("vault_key_invalid", () =>
      open(Object.create(Uint8Array.prototype) as Uint8Array, sealed().record),
    );
  });
});
