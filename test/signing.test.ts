// WCLI-149 (DEC-262 (2), a3 (i) and (ii)): the Ed25519 sign operation's
// storage, key commands, backup exclusion and refusal as a credential.
//
// Every case runs against a temporary vault, a memory credential store and a
// throwaway checkout, with synthetic keys only.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import { createPublicKey, randomUUID, verify } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  deriveBackupKey,
  encodeBackup,
  newBackupKdf,
  openBackup,
  parseBackup,
  sealBackup,
} from "../src/domain/backup.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import type {
  GrantApprover,
  ProfileApprover,
  RegistrationApprover,
} from "../src/application/approvals.ts";
import type { PassphraseSource } from "../src/application/backup.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import { signWithKey } from "../src/application/sign.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { WardError } from "../src/contract/errors.ts";
import {
  type ApprovedSnapshot,
  approvedSnapshotsMatch,
  differingApprovedFields,
  normalizeProfile,
  normalizeSignProfile,
  normalizeStoredSnapshot,
  profileSnapshotVersion,
  signSnapshotVersion,
  snapshotVersionFor,
  withSignKeyId,
} from "../src/domain/profile.ts";
import {
  encodeSecretValue,
  signKeyKind,
  signKeySeedBytes,
} from "../src/domain/secret.ts";
import {
  generateSignKey,
  publicKeyOf,
  signBytes,
  startsWithAllowedPrefix,
} from "../src/domain/signing.ts";
import {
  emptyVaultState,
  parseVaultState,
  serializeVaultState,
  withSecret,
  withoutSignKeys,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const root = mkdtempSync(join(tmpdir(), "ward-signing-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const encoder = new TextEncoder();
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");

function verifies(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  const key = createPublicKey({
    key: Buffer.concat([spkiPrefix, publicKey]),
    format: "der",
    type: "spki",
  });
  return verify(null, message, key, signature);
}

describe("the signing domain", () => {
  test("a seed round-trips to the public key and a signature that verifies", () => {
    const { seed, publicKey } = generateSignKey();
    expect(seed.length).toBe(signKeySeedBytes);
    expect(Buffer.from(publicKeyOf(seed)).equals(Buffer.from(publicKey))).toBe(
      true,
    );
    const message = encoder.encode("domain-v1\0hello");
    const signature = signBytes(seed, message);
    expect(signature.length).toBe(64);
    expect(verifies(publicKey, message, signature)).toBe(true);
    expect(verifies(publicKey, encoder.encode("other"), signature)).toBe(false);
  });

  test("a fixed seed signs deterministically (RFC 8032 test vector 1)", () => {
    const seed = Buffer.from(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "hex",
    );
    expect(Buffer.from(publicKeyOf(seed)).toString("hex")).toBe(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    expect(Buffer.from(signBytes(seed, new Uint8Array())).toString("hex")).toBe(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
  });

  test("prefixes: a byte prefix is required, and an empty list allows nothing", () => {
    const prefix = encoder.encode("app/v1\0");
    const ok = encoder.encode("app/v1\0payload");
    expect(startsWithAllowedPrefix(ok, [prefix])).toBe(true);
    expect(startsWithAllowedPrefix(encoder.encode("app/v2\0x"), [prefix])).toBe(
      false,
    );
    expect(startsWithAllowedPrefix(prefix.slice(0, 3), [prefix])).toBe(false);
    expect(startsWithAllowedPrefix(ok, [])).toBe(false);
    expect(startsWithAllowedPrefix(ok, [new Uint8Array()])).toBe(false);
  });
});

describe("the vault document", () => {
  const base = {
    id: randomUUID(),
    projectId: randomUUID(),
    alias: "k",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    revision: 1,
  };
  const seed = encodeSecretValue(new Uint8Array(32).fill(7));

  test("an ordinary secret serializes exactly as an older build wrote it", () => {
    // Pinned to a literal (the key order and key set an older build wrote),
    // not to a property of this build's serializer. The whole-document
    // round trip is test/grant.test.ts "a well-formed document round-trips
    // byte for byte".
    const state = withSecret(emptyVaultState(), { ...base, value: seed });
    const text = new TextDecoder().decode(serializeVaultState(state));
    const older = JSON.stringify([
      {
        id: base.id,
        projectId: base.projectId,
        alias: base.alias,
        value: seed,
        createdAt: base.createdAt,
        updatedAt: base.updatedAt,
        revision: base.revision,
      },
    ]);
    expect(text).toContain(`"secrets":${older}`);
    expect(text).not.toContain("kind");
  });

  test("a sign key round-trips and a wrong kind or seed length is refused", () => {
    const state = withSecret(emptyVaultState(), {
      ...base,
      value: seed,
      kind: signKeyKind,
    });
    const round = parseVaultState(serializeVaultState(state));
    expect(round.secrets[0]?.kind).toBe(signKeyKind);
    const document = JSON.parse(
      new TextDecoder().decode(serializeVaultState(state)),
    );
    const refused = (mutate: (record: Record<string, unknown>) => void) => {
      const copy = structuredClone(document);
      mutate(copy.secrets[0]);
      expect(() =>
        parseVaultState(encoder.encode(JSON.stringify(copy))),
      ).toThrow();
    };
    refused((record) => {
      record.kind = "rsa";
    });
    refused((record) => {
      record.kind = null;
    });
    refused((record) => {
      record.value = encodeSecretValue(new Uint8Array(31).fill(1));
    });
  });

  test("withoutSignKeys drops sign keys and names them", () => {
    const state = withSecret(
      withSecret(emptyVaultState(), {
        ...base,
        value: seed,
        kind: signKeyKind,
      }),
      { ...base, id: randomUUID(), alias: "ordinary", value: seed },
    );
    const { state: carried, excluded } = withoutSignKeys(state);
    expect(excluded).toEqual(["k"]);
    expect(carried.secrets.map((secret) => secret.alias)).toEqual(["ordinary"]);
  });
});

const registration: RegistrationApprover = {
  available: () => true,
  ask: () => "approved",
};
const profileApprover: ProfileApprover = {
  available: () => true,
  ask: () => "approved",
};
const grantApprover: GrantApprover = {
  available: () => true,
  ask: () => "approved",
};
const passphrases: PassphraseSource = {
  available: () => true,
  read: () => encoder.encode("signing-test-passphrase"),
};
const ordinaryValue = encoder.encode("synthetic-ordinary-value");
const secrets: SecretValueSource = {
  available: () => true,
  readHidden: () => ordinaryValue.slice(),
  readStdin: () => ordinaryValue.slice(),
  confirmReplace: () => true,
};

let cases = 0;
function session(): { options: RunOptions; wardDirectory: string } {
  const keychain = new MemoryKeychain();
  const checkout = join(root, `repo-${++cases}`);
  mkdirSync(join(checkout, ".git"), { recursive: true });
  const wardDirectory = join(mkdtempSync(join(root, "case-")), ".ward");
  return {
    wardDirectory,
    options: {
      wardDirectory,
      keyProvider: createKeychainKeyProvider({
        service: "opum.ward.signing-test",
        entry: keychain.entry,
      }),
      cwd: checkout,
      passphrases,
      approver: registration,
      profileApprover,
      grantApprover,
      secrets,
    },
  };
}

async function ready(): Promise<ReturnType<typeof session>> {
  const made = session();
  expect((await runWard(["setup", "--json"], made.options)).exitCode).toBe(
    exitCodes.success,
  );
  expect((await runWard(["init", "--json"], made.options)).exitCode).toBe(
    exitCodes.success,
  );
  return made;
}

function data(stdout: string): Record<string, unknown> {
  return (JSON.parse(stdout) as { data: Record<string, unknown> }).data;
}

describe("ward key", () => {
  test("generate returns only a public key, and public reads the same one back", async () => {
    const { options } = await ready();
    const generated = await runWard(
      ["key", "generate", "signer", "--json"],
      options,
    );
    expect(generated.exitCode).toBe(exitCodes.success);
    const publicKey = data(generated.stdout).publicKey as string;
    expect(Buffer.from(publicKey, "base64").length).toBe(32);
    const again = await runWard(["key", "public", "signer", "--json"], options);
    expect(data(again.stdout).publicKey).toBe(publicKey);
    expect(Object.keys(data(generated.stdout)).sort()).toEqual([
      "algorithm",
      "alias",
      "createdAt",
      "id",
      "projectId",
      "publicKey",
    ]);
  });

  test("a duplicate alias, a missing key and an ordinary secret are fixed refusals", async () => {
    const { options } = await ready();
    await runWard(["key", "generate", "signer", "--json"], options);
    const duplicate = await runWard(
      ["key", "generate", "signer", "--json"],
      options,
    );
    expect(duplicate.exitCode).toBe(exitCodes.conflict);
    expect(duplicate.stdout + duplicate.stderr).toContain("sign_key_exists");
    const missing = await runWard(
      ["key", "public", "absent", "--json"],
      options,
    );
    expect(missing.exitCode).toBe(exitCodes.notFound);
    await runWard(["secret", "set", "plain", "--stdin", "--json"], options);
    const plain = await runWard(["key", "public", "plain", "--json"], options);
    expect(plain.exitCode).toBe(exitCodes.notFound);
    expect(plain.stdout + plain.stderr).toContain("sign_key_not_found");
    const overOrdinary = await runWard(
      ["key", "generate", "plain", "--json"],
      options,
    );
    expect(overOrdinary.exitCode).toBe(exitCodes.conflict);
  });

  test("an unknown action is a usage error", async () => {
    const { options } = await ready();
    const result = await runWard(
      ["key", "export", "signer", "--json"],
      options,
    );
    expect(result.exitCode).toBe(exitCodes.usage);
  });
});

describe("a sign key is never an ordinary secret", () => {
  test("secret set, grant and list treat it as a sign key", async () => {
    const { options } = await ready();
    await runWard(["key", "generate", "signer", "--json"], options);
    const replaced = await runWard(
      ["secret", "set", "signer", "--stdin", "--json"],
      options,
    );
    expect(replaced.exitCode).toBe(exitCodes.denied);
    expect(replaced.stdout + replaced.stderr).toContain("sign_key_refused");
    const granted = await runWard(
      [
        "secret",
        "grant",
        "signer",
        "--to",
        randomUUID(),
        "--as",
        "shared",
        "--json",
      ],
      options,
    );
    expect(granted.exitCode).toBe(exitCodes.denied);
    const listed = await runWard(["secret", "list", "--json"], options);
    const entries = data(listed.stdout).secrets as {
      alias: string;
      kind?: string;
    }[];
    expect(entries.find((entry) => entry.alias === "signer")?.kind).toBe(
      "ed25519",
    );
    const deleted = await runWard(
      ["secret", "delete", "signer", "--json"],
      options,
    );
    expect(deleted.exitCode).toBe(exitCodes.success);
  });

  test("a profile that names a sign key is reported, not thrown, and the others still report", async () => {
    const { options } = await ready();
    await runWard(["key", "generate", "signer", "--json"], options);
    await runWard(["secret", "set", "tok", "--stdin", "--json"], options);
    const manifestPath = join(options.cwd as string, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    const http = (secret: string) => ({
      adapter: "http",
      method: "GET",
      url: "https://example.invalid/status",
      auth: { type: "bearer", secret },
      output: "status",
    });
    manifest.profiles = { good: http("tok"), status: http("signer") };
    writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);
    for (const name of ["good", "status"])
      expect(
        (await runWard(["profile", "approve", name, "--json"], options))
          .exitCode,
      ).toBe(exitCodes.success);

    // Neither report fails because one profile names a signing key.
    const listed = await runWard(["profile", "list", "--json"], options);
    expect(listed.exitCode).toBe(exitCodes.success);
    const listedNames = (
      data(listed.stdout).profiles as { profile: string }[]
    ).map((entry) => entry.profile);
    expect(listedNames).toEqual(["good", "status"]);
    const secretStates = Object.fromEntries(
      (
        data(listed.stdout).profiles as { profile: string; secret: string }[]
      ).map((entry) => [entry.profile, entry.secret]),
    );
    expect(secretStates).toEqual({ good: "present", status: "sign-key" });

    type Entry = { profile: string; reasons: string[] };
    const all = await runWard(["check", "--json"], options);
    expect(all.exitCode).toBe(exitCodes.validation);
    const entries = data(all.stdout).profiles as Entry[];
    expect(entries.find((entry) => entry.profile === "good")?.reasons).toEqual(
      [],
    );
    expect(
      entries.find((entry) => entry.profile === "status")?.reasons,
    ).toEqual(["sign-key"]);
    const named = await runWard(["check", "status", "--json"], options);
    expect(named.exitCode).toBe(exitCodes.validation);

    // And `run` still refuses to deliver it, before admission.
    const ran = await runWard(["run", "status", "--json"], options);
    expect(ran.exitCode).toBe(exitCodes.denied);
    expect(ran.stdout + ran.stderr).toContain("sign_key_refused");
  });
});

describe("secret list and inspect name a sign key", () => {
  test("the text forms show its kind, and an ordinary secret shows none", async () => {
    const { options } = await ready();
    await runWard(["key", "generate", "signer", "--json"], options);
    await runWard(["secret", "set", "plain", "--stdin", "--json"], options);
    const listed = await runWard(["secret", "list"], options);
    expect(listed.stdout).toContain("signer  (ed25519 signing key)");
    expect(listed.stdout).not.toContain("plain  (");
    const inspected = await runWard(["secret", "inspect", "signer"], options);
    expect(inspected.stdout).toContain("kind:      ed25519");
    const ordinary = await runWard(["secret", "inspect", "plain"], options);
    expect(ordinary.stdout).not.toContain("kind:");
    const json = await runWard(
      ["secret", "inspect", "signer", "--json"],
      options,
    );
    expect(data(json.stdout).kind).toBe("ed25519");
  });
});

describe("backup", () => {
  test("a sign key is left out, named, and restores to nothing", async () => {
    const { options } = await ready();
    await runWard(["key", "generate", "signer", "--json"], options);
    await runWard(["secret", "set", "plain", "--stdin", "--json"], options);
    const file = join(options.cwd as string, "backup.json");
    const backed = await runWard(
      ["backup", "--output", file, "--json"],
      options,
    );
    expect(backed.exitCode).toBe(exitCodes.success);
    expect(data(backed.stdout).excludedSignKeys).toEqual(["signer"]);
    // The text form names them too: it is what a person reads.
    const textFile = join(options.cwd as string, "backup-text.json");
    const text = await runWard(["backup", "--output", textFile], options);
    expect(text.exitCode).toBe(exitCodes.success);
    expect(text.stdout).toContain("Signing keys are never part of a backup");
    expect(text.stdout).toContain("  signer");
    // And a backup of a vault with no sign key says nothing about them.
    const plainOnly = await ready();
    const plainFile = join(plainOnly.options.cwd as string, "plain.json");
    const plain = await runWard(
      ["backup", "--output", plainFile],
      plainOnly.options,
    );
    expect(plain.stdout).not.toContain("Signing keys");
    // The container itself carries no sign key. Restore also filters by kind,
    // so only opening the container shows the backup left it out.
    const record = parseBackup(readFileSync(file));
    const opened = openBackup(
      deriveBackupKey(encoder.encode("signing-test-passphrase"), record.kdf),
      record,
    );
    const carried = parseVaultState(opened);
    expect(carried.secrets.map((secret) => secret.alias)).toEqual(["plain"]);
    expect(carried.secrets.every((secret) => secret.kind === undefined)).toBe(
      true,
    );
    // Restore says in prose that signing keys are never carried (DEC-262
    // a6), into its own empty vault, and does not claim to name them: the
    // container records none.
    const textTarget = session();
    const restoredText = await runWard(["restore", "--input", file], {
      ...textTarget.options,
      cwd: options.cwd,
    });
    expect(restoredText.exitCode).toBe(exitCodes.success);
    expect(restoredText.stdout).toContain("Signing keys are never carried");
    expect(restoredText.stdout).not.toContain("signer");
    // The restored vault holds the ordinary secret and no sign key. The
    // checkout is re-registered, since a restore clears every binding.
    const target = session();
    const there = { ...target.options, cwd: options.cwd };
    const restored = await runWard(
      ["restore", "--input", file, "--json"],
      there,
    );
    expect(restored.exitCode).toBe(exitCodes.success);
    expect((await runWard(["init", "--json"], there)).exitCode).toBe(
      exitCodes.success,
    );
    const listed = await runWard(["secret", "list", "--json"], there);
    const aliases = (data(listed.stdout).secrets as { alias: string }[]).map(
      (entry) => entry.alias,
    );
    expect(aliases).toEqual(["plain"]);
    const gone = await runWard(["key", "public", "signer", "--json"], there);
    expect(gone.exitCode).toBe(exitCodes.notFound);
  });
});

describe("restore never carries a sign key", () => {
  test("a container that holds one still restores to nothing", async () => {
    const { options } = await ready();
    const manifest = JSON.parse(
      readFileSync(
        join(options.cwd as string, ".ward", "project.json"),
        "utf8",
      ),
    ) as { projectId: string };
    const at = "2026-01-01T00:00:00.000Z";
    const record = (alias: string, kind?: typeof signKeyKind) => ({
      id: randomUUID(),
      projectId: manifest.projectId,
      alias,
      value: encodeSecretValue(new Uint8Array(32).fill(5)),
      createdAt: at,
      updatedAt: at,
      revision: 1,
      ...(kind === undefined ? {} : { kind }),
    });
    const state = withSecret(
      withSecret(
        {
          ...emptyVaultState(),
          projects: [{ id: manifest.projectId, createdAt: at }],
        },
        record("plain"),
      ),
      record("smuggled", signKeyKind),
    );
    // A container this build's backup would never write: its sealed state
    // carries a sign key. Sealed with the domain functions, not the command.
    const kdf = newBackupKdf();
    const sealed = sealBackup(
      deriveBackupKey(encoder.encode("signing-test-passphrase"), kdf),
      { vaultId: randomUUID(), revision: 1, kdf },
      serializeVaultState(state),
    );
    const file = join(options.cwd as string, "smuggled.json");
    writeFileSync(file, encodeBackup(sealed));

    const target = session();
    const there = { ...target.options, cwd: options.cwd };
    expect(
      (await runWard(["restore", "--input", file, "--json"], there)).exitCode,
    ).toBe(exitCodes.success);
    expect((await runWard(["init", "--json"], there)).exitCode).toBe(
      exitCodes.success,
    );
    const listed = await runWard(["secret", "list", "--json"], there);
    const aliases = (data(listed.stdout).secrets as { alias: string }[]).map(
      (entry) => entry.alias,
    );
    expect(aliases).toEqual(["plain"]);
    const gone = await runWard(["key", "public", "smuggled", "--json"], there);
    expect(gone.exitCode).toBe(exitCodes.notFound);
  });
});

describe("signWithKey", () => {
  test("signs exactly the bytes given under an allowed prefix, and refuses others", () => {
    const { seed, publicKey } = generateSignKey();
    const projectId = randomUUID();
    const state = withSecret(emptyVaultState(), {
      id: randomUUID(),
      projectId,
      alias: "signer",
      value: encodeSecretValue(seed),
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      revision: 1,
      kind: signKeyKind,
    });
    const prefix = encoder.encode("app/v1\0");
    const message = encoder.encode("app/v1\0payload");
    const out = signWithKey(state, projectId, "signer", message, [prefix]);
    expect(verifies(publicKey, message, out.signature)).toBe(true);
    expect(() =>
      signWithKey(state, projectId, "signer", encoder.encode("other"), [
        prefix,
      ]),
    ).toThrow(new WardError("sign_input_refused"));
    expect(() =>
      signWithKey(state, projectId, "absent", message, [prefix]),
    ).toThrow(new WardError("sign_key_not_found"));
  });
});

// ---- Slice 2: the sign profile, `ward sign` and the version lines --------

const prefixBytes = encoder.encode("app/v1\0");
const prefixB64 = Buffer.from(prefixBytes).toString("base64");

function withInput(options: RunOptions, bytes: Uint8Array): RunOptions {
  return {
    ...options,
    secrets: { ...secrets, readStdin: () => bytes.slice() },
  };
}

function declareProfiles(
  options: RunOptions,
  profiles: Record<string, unknown>,
) {
  const manifestPath = join(options.cwd as string, ".ward", "project.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.profiles = profiles;
  writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);
}

async function signReady() {
  const made = await ready();
  const generated = await runWard(
    ["key", "generate", "signer", "--json"],
    made.options,
  );
  declareProfiles(made.options, {
    signer: { adapter: "sign", key: "signer", prefixes: [prefixB64] },
  });
  const approved = await runWard(
    ["profile", "approve", "signer", "--json"],
    made.options,
  );
  expect(approved.exitCode).toBe(exitCodes.success);
  return {
    ...made,
    publicKey: Buffer.from(
      data(generated.stdout).publicKey as string,
      "base64",
    ),
  };
}

describe("normalizeSignProfile", () => {
  const declaration = { adapter: "sign", key: "signer", prefixes: [prefixB64] };

  test("a declaration normalizes, and prefixes are sorted and de-duplicated", () => {
    const other = Buffer.from("zz").toString("base64");
    const snapshot = normalizeSignProfile({
      ...declaration,
      prefixes: [other, prefixB64, other],
    });
    expect(snapshot).toEqual({
      adapter: "sign",
      key: "signer",
      prefixes: [other, prefixB64].sort(),
    });
  });

  test("every malformed declaration is refused", () => {
    const refused = (value: unknown) =>
      expect(() => normalizeSignProfile(value)).toThrow();
    refused({ ...declaration, extra: 1 });
    refused({ ...declaration, adapter: "http" });
    refused({ ...declaration, key: "1bad" });
    refused({ ...declaration, key: undefined });
    // DEC-262 (a5): an empty list would admit any domain, so it is refused as
    // an invalid declaration, and a one-entry list is accepted.
    expect(() =>
      normalizeSignProfile({ ...declaration, prefixes: [] }),
    ).toThrow(new WardError("profile_invalid"));
    expect(() => normalizeSignProfile(declaration)).not.toThrow();
    refused({ ...declaration, prefixes: "app" });
    refused({ ...declaration, prefixes: [1] });
    // Not the canonical base64 of its bytes.
    refused({ ...declaration, prefixes: ["YXBw "] });
    refused({ ...declaration, prefixes: ["YXBw=="] });
    // Empty, and over 64 bytes.
    refused({ ...declaration, prefixes: [""] });
    refused({
      ...declaration,
      prefixes: [Buffer.alloc(65, 1).toString("base64")],
    });
    // More than eight.
    refused({
      ...declaration,
      prefixes: Array.from({ length: 9 }, (_, index) =>
        Buffer.from([index + 1]).toString("base64"),
      ),
    });
    expect(() =>
      normalizeSignProfile({
        ...declaration,
        prefixes: [Buffer.alloc(64, 1).toString("base64")],
      }),
    ).not.toThrow();
  });

  test("two spellings of one set are one approval; a changed field is named", () => {
    const left = normalizeSignProfile(declaration);
    const right = normalizeSignProfile({
      ...declaration,
      prefixes: [prefixB64, prefixB64],
    });
    expect(approvedSnapshotsMatch(left, right)).toBe(true);
    expect(
      differingApprovedFields(
        left,
        normalizeSignProfile({ ...declaration, key: "other" }),
      ),
    ).toEqual(["key"]);
    expect(
      differingApprovedFields(
        left,
        normalizeSignProfile({
          ...declaration,
          prefixes: [Buffer.from("x").toString("base64")],
        }),
      ),
    ).toEqual(["prefixes"]);
    expect(
      differingApprovedFields(
        left,
        normalizeProfile({
          adapter: "http",
          method: "GET",
          url: "https://example.invalid/",
          auth: { type: "bearer", secret: "t" },
        }),
      ),
    ).toEqual(["adapter"]);
  });
});

describe("the version lines (DEC-262 a4)", () => {
  const checkout = {
    root: "/tmp/ward-signing-root",
    device: "1",
    inode: "2",
  };
  function stateWith(snapshot: ApprovedSnapshot, version: number) {
    const base = withSecret(emptyVaultState(), {
      id: randomUUID(),
      projectId: randomUUID(),
      alias: "x",
      value: encodeSecretValue(new Uint8Array(4).fill(1)),
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      revision: 1,
    });
    return {
      ...base,
      profileApprovals: [
        {
          profile: "p",
          projectId: base.secrets[0]?.projectId as string,
          ...checkout,
          approvedAt: "2026-01-01T00:00:00.000Z",
          expiresAt: "2026-01-02T00:00:00.000Z",
          snapshotVersion: version,
          snapshot,
        },
      ],
    };
  }
  const sign = withSignKeyId(
    normalizeSignProfile({
      adapter: "sign",
      key: "signer",
      prefixes: [prefixB64],
    }),
    "11111111-1111-4111-8111-111111111111",
  ) as ApprovedSnapshot;
  const http = normalizeProfile({
    adapter: "http",
    method: "GET",
    url: "https://example.invalid/",
    auth: { type: "bearer", secret: "t" },
  });

  test("each kind is current at its own version and stale at the other's", () => {
    expect(snapshotVersionFor(sign)).toBe(signSnapshotVersion);
    expect(snapshotVersionFor(http)).toBe(profileSnapshotVersion);
    for (const [snapshot, version, active] of [
      [sign, signSnapshotVersion, true],
      [http, profileSnapshotVersion, true],
      [sign, signSnapshotVersion + 1, false],
      [http, profileSnapshotVersion + 1, false],
    ] as const) {
      const read = parseVaultState(
        serializeVaultState(stateWith(snapshot, version)),
      );
      expect(read.profileApprovals.length).toBe(active ? 1 : 0);
      expect(read.staleProfileApprovals.length).toBe(active ? 0 : 1);
    }
  });

  test("a sign approval round-trips byte for byte", () => {
    const bytes = serializeVaultState(stateWith(sign, signSnapshotVersion));
    const again = serializeVaultState(parseVaultState(bytes));
    expect(Buffer.from(again).equals(Buffer.from(bytes))).toBe(true);
  });
});

describe("ward sign", () => {
  test("signs exactly the bytes given under an approved prefix", async () => {
    const { options, publicKey } = await signReady();
    const message = encoder.encode("app/v1\0hello");
    const result = await runWard(
      ["sign", "signer"],
      withInput(options, message),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stdout).toBe("");
    const signature = result.stdoutBytes as Uint8Array;
    expect(signature.length).toBe(64);
    expect(verifies(publicKey, message, signature)).toBe(true);

    const text = await runWard(
      ["sign", "signer", "--base64"],
      withInput(options, message),
    );
    expect(text.stdoutBytes).toBeUndefined();
    expect(Buffer.from(text.stdout.trim(), "base64").length).toBe(64);

    const enveloped = await runWard(
      ["sign", "signer", "--json"],
      withInput(options, message),
    );
    const body = data(enveloped.stdout);
    expect(body.outcome).toBe("succeeded");
    expect(body.auditRecorded).toBe(true);
    expect(
      verifies(
        publicKey,
        message,
        new Uint8Array(Buffer.from(body.signature as string, "base64")),
      ),
    ).toBe(true);
    expect(Object.keys(body)).not.toContain("seed");
  });

  test("bytes outside every approved prefix are refused and not audited", async () => {
    const { options } = await signReady();
    const before = await runWard(["audit", "--json"], options);
    const refused = await runWard(
      ["sign", "signer", "--json"],
      withInput(options, encoder.encode("other/v1\0hello")),
    );
    expect(refused.exitCode).toBe(exitCodes.denied);
    expect(refused.stdout + refused.stderr).toContain("sign_input_refused");
    const empty = await runWard(
      ["sign", "signer", "--json"],
      withInput(options, new Uint8Array()),
    );
    expect(empty.exitCode).toBe(exitCodes.denied);
    const after = await runWard(["audit", "--json"], options);
    expect(after.stdout).toBe(before.stdout);
  });

  test("a sign is audited as admission then completion against the key's id", async () => {
    const { options } = await signReady();
    await runWard(
      ["sign", "signer", "--json", "--actor-label", "agent-one"],
      withInput(options, encoder.encode("app/v1\0x")),
    );
    const audit = await runWard(["audit", "--json"], options);
    expect(audit.exitCode).toBe(exitCodes.success);
    const text = audit.stdout;
    expect(text).toContain("signer");
    expect(text).toContain("agent-one");
    expect(text).toContain("admission");
    expect(text).toContain("completion");
    expect(text).toContain("succeeded");
  });

  test("an unapproved, stale or expired profile does not sign", async () => {
    const { options } = await ready();
    await runWard(["key", "generate", "signer", "--json"], options);
    declareProfiles(options, {
      signer: { adapter: "sign", key: "signer", prefixes: [prefixB64] },
    });
    const message = encoder.encode("app/v1\0x");
    const unapproved = await runWard(
      ["sign", "signer", "--json"],
      withInput(options, message),
    );
    expect(unapproved.exitCode).not.toBe(exitCodes.success);
    expect(unapproved.stdout + unapproved.stderr).toContain(
      "profile_not_approved",
    );
    await runWard(["profile", "approve", "signer", "--json"], options);
    declareProfiles(options, {
      signer: {
        adapter: "sign",
        key: "signer",
        prefixes: [prefixB64, Buffer.from("more").toString("base64")],
      },
    });
    const stale = await runWard(
      ["sign", "signer", "--json"],
      withInput(options, message),
    );
    expect(stale.exitCode).toBe(exitCodes.denied);
    expect(stale.stdout + stale.stderr).toContain("profile_approval_stale");
    const checked = await runWard(["check", "signer", "--json"], options);
    expect(checked.stdout).toContain("prefixes");
    // The same declaration, approved and then past its lifetime.
    declareProfiles(options, {
      signer: { adapter: "sign", key: "signer", prefixes: [prefixB64] },
    });
    await runWard(["profile", "approve", "signer", "--json"], options);
    const later = {
      ...options,
      now: () => new Date(Date.now() + 365 * 24 * 3600 * 1000),
    };
    const expired = await runWard(
      ["sign", "signer", "--json"],
      withInput(later, message),
    );
    expect(expired.stdout + expired.stderr).toContain(
      "profile_approval_expired",
    );
  });

  test("a missing key, a revoked approval and an HTTP profile do not sign", async () => {
    const { options } = await signReady();
    const message = encoder.encode("app/v1\0x");
    await runWard(["secret", "delete", "signer", "--json"], options);
    const gone = await runWard(
      ["sign", "signer", "--json"],
      withInput(options, message),
    );
    // The approval bound the deleted key's id (DEC-262 a8), so it is stale
    // before the missing key is even looked for.
    expect(gone.stdout + gone.stderr).toContain("profile_approval_stale");
    declareProfiles(options, {
      web: {
        adapter: "http",
        method: "GET",
        url: "https://example.invalid/status",
        auth: { type: "bearer", secret: "tok" },
        output: "status",
      },
    });
    const wrongKind = await runWard(
      ["sign", "web", "--json"],
      withInput(options, message),
    );
    expect(wrongKind.exitCode).not.toBe(exitCodes.success);
  });

  test("a signature whose completion audit cannot be written exits nonzero and says so on stderr (DEC-262 a7)", async () => {
    const { options, publicKey } = await signReady();
    const message = encoder.encode("app/v1\0x");
    // `runSign` reads the clock for the approval check, the admission event
    // and the completion event, in that order. Failing the third makes only
    // the completion write fail, after the signature exists.
    let reads = 0;
    const failing: RunOptions = {
      ...withInput(options, message),
      now: () => {
        if (++reads === 3) throw new Error("clock unavailable");
        return new Date();
      },
    };
    const raw = await runWard(["sign", "signer"], failing);
    expect(reads).toBe(3);
    expect(raw.exitCode).toBe(exitCodes.validation);
    expect(raw.stderr).toContain("completion audit event could not be written");
    // The signature is still there, and still verifies.
    expect(verifies(publicKey, message, raw.stdoutBytes as Uint8Array)).toBe(
      true,
    );
    reads = 0;
    const enveloped = await runWard(["sign", "signer", "--json"], failing);
    expect(enveloped.exitCode).toBe(exitCodes.validation);
    expect(data(enveloped.stdout).auditRecorded).toBe(false);
    expect(enveloped.stderr).toContain(
      "audit trail for this sign is incomplete",
    );
    // A clean sign writes nothing to stderr.
    const clean = await runWard(
      ["sign", "signer"],
      withInput(options, message),
    );
    expect(clean.exitCode).toBe(exitCodes.success);
    expect(clean.stderr).toBe("");
  });

  test("an HTTP run of a sign profile is refused", async () => {
    const { options } = await signReady();
    const ran = await runWard(["run", "signer", "--json"], options);
    expect(ran.exitCode).not.toBe(exitCodes.success);
  });

  test("an input over the limit is refused before the vault is read", async () => {
    const { options } = await signReady();
    const limited: RunOptions = {
      ...options,
      secrets: {
        ...secrets,
        readStdin: () => {
          throw new WardError("secret_value_too_large");
        },
      },
    };
    const result = await runWard(["sign", "signer", "--json"], limited);
    expect(result.stdout + result.stderr).toContain("sign_input_too_large");
  });
});

const httpProfile = {
  adapter: "http",
  method: "GET",
  url: "https://example.invalid/status",
  auth: { type: "bearer", secret: "tok" },
  output: "status",
};

describe("a sign profile whose key is not usable (WCLI-149 review B1)", () => {
  test("no key reads sign-key-missing and the advice is ward key generate", async () => {
    const { options } = await signReady();
    await runWard(["secret", "delete", "signer", "--json"], options);
    const json = await runWard(["check", "signer", "--json"], options);
    expect(json.stdout).toContain("sign-key-missing");
    expect(json.stdout).not.toContain('"secret"');
    const text = await runWard(["check", "signer"], options);
    expect(text.stdout).toContain("the signing key does not exist");
    expect(text.stdout).toContain("ward key generate <alias>");
    expect(text.stdout).not.toContain("ward secret set");
    const listed = await runWard(["profile", "list", "--json"], options);
    expect(listed.stdout).toContain('"secret":"sign-key-missing"');
    const listedText = await runWard(["profile", "list"], options);
    expect(listedText.stdout).toContain("signing key");
  });

  test("an ordinary secret under the alias reads sign-key-alias-taken and names ward secret delete first", async () => {
    const { options } = await signReady();
    await runWard(["secret", "delete", "signer", "--json"], options);
    await runWard(["secret", "set", "signer", "--stdin", "--json"], options);
    const json = await runWard(["check", "signer", "--json"], options);
    expect(json.stdout).toContain("sign-key-alias-taken");
    const text = await runWard(["check", "signer"], options);
    expect(text.stdout).toContain("an ordinary secret holds");
    expect(text.stdout).toContain("ward secret delete <alias>");
    expect(text.stdout).toContain("ward key generate <alias>");
    const listed = await runWard(["profile", "list", "--json"], options);
    expect(listed.stdout).toContain('"secret":"sign-key-alias-taken"');
    // The advice is followable: deleting the secret lets the key be created,
    // and approving again (the key id is new) makes the profile ready.
    await runWard(["secret", "delete", "signer", "--json"], options);
    const generated = await runWard(
      ["key", "generate", "signer", "--json"],
      options,
    );
    expect(generated.exitCode).toBe(exitCodes.success);
    await runWard(["profile", "approve", "signer", "--json"], options);
    const after = await runWard(["check", "signer", "--json"], options);
    expect(after.exitCode).toBe(exitCodes.success);
  });
});

describe("the two profile kinds cannot stand in for each other (WCLI-149 review N1)", () => {
  test("each command refuses the other kind's declaration with profile_unsupported", async () => {
    const { options } = await signReady();
    const message = encoder.encode("app/v1\0x");
    const ranSign = await runWard(["run", "signer", "--json"], options);
    expect(ranSign.stdout + ranSign.stderr).toContain("profile_unsupported");
    declareProfiles(options, { web: httpProfile });
    const signedHttp = await runWard(
      ["sign", "web", "--json"],
      withInput(options, message),
    );
    expect(signedHttp.stdout + signedHttp.stderr).toContain(
      "profile_unsupported",
    );
  });

  test("an HTTP approval redeclared as a sign profile is stale, not runnable by ward sign", async () => {
    const { options } = await ready();
    await runWard(["key", "generate", "web", "--json"], options);
    declareProfiles(options, { web: httpProfile });
    await runWard(["profile", "approve", "web", "--json"], options);
    declareProfiles(options, {
      web: { adapter: "sign", key: "web", prefixes: [prefixB64] },
    });
    const signed = await runWard(
      ["sign", "web", "--json"],
      withInput(options, encoder.encode("app/v1\0x")),
    );
    expect(signed.exitCode).toBe(exitCodes.denied);
    expect(signed.stdout + signed.stderr).toContain("profile_approval_stale");
  });

  test("a sign approval redeclared as an HTTP profile is stale, not runnable by ward run", async () => {
    const { options } = await signReady();
    declareProfiles(options, { signer: httpProfile });
    const ran = await runWard(["run", "signer", "--json"], options);
    expect(ran.exitCode).toBe(exitCodes.denied);
    expect(ran.stdout + ran.stderr).toContain("profile_approval_stale");
  });
});

describe("ward sign on a terminal (WCLI-149 review N2)", () => {
  test("a terminal stdin raises sign_input_terminal, not the secret --stdin advice", async () => {
    const { options } = await signReady();
    const onTerminal: RunOptions = {
      ...options,
      secrets: {
        ...secrets,
        readStdin: () => {
          throw new WardError("secret_stdin_terminal");
        },
      },
    };
    const result = await runWard(["sign", "signer", "--json"], onTerminal);
    expect(result.stdout + result.stderr).toContain("sign_input_terminal");
    expect(result.stdout + result.stderr).not.toContain("--stdin");
  });
});

describe("a sign approval binds the key id (DEC-262 a8)", () => {
  test("an unchanged key still signs", async () => {
    const { options, publicKey } = await signReady();
    const message = encoder.encode("app/v1\0x");
    const result = await runWard(
      ["sign", "signer"],
      withInput(options, message),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(verifies(publicKey, message, result.stdoutBytes as Uint8Array)).toBe(
      true,
    );
  });

  test("a key regenerated under the same alias leaves the approval stale until approved again", async () => {
    const { options } = await signReady();
    const message = encoder.encode("app/v1\0x");
    await runWard(["secret", "delete", "signer", "--json"], options);
    const regenerated = await runWard(
      ["key", "generate", "signer", "--json"],
      options,
    );
    expect(regenerated.exitCode).toBe(exitCodes.success);
    const refused = await runWard(
      ["sign", "signer", "--json"],
      withInput(options, message),
    );
    expect(refused.exitCode).toBe(exitCodes.denied);
    expect(refused.stdout + refused.stderr).toContain("profile_approval_stale");
    const checked = await runWard(["check", "signer", "--json"], options);
    expect(checked.stdout).toContain("approval-stale");
    expect(checked.stdout).toContain("keyId");
    // A person approving again, in a terminal, binds the new key.
    await runWard(["profile", "approve", "signer", "--json"], options);
    const again = await runWard(
      ["sign", "signer"],
      withInput(options, message),
    );
    expect(again.exitCode).toBe(exitCodes.success);
  });

  test("a stored sign snapshot without a key id is refused as a malformed vault", () => {
    const stored = {
      adapter: "sign",
      key: "signer",
      prefixes: [prefixB64],
    };
    expect(() => normalizeStoredSnapshot(stored)).toThrow(WardError);
    expect(() => normalizeStoredSnapshot({ ...stored, keyId: "" })).toThrow(
      WardError,
    );
    expect(() => normalizeSignProfile({ ...stored, keyId: "x" })).toThrow(
      WardError,
    );
  });
});
