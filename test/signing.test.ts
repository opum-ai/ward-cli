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
  openBackup,
  parseBackup,
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
    ).toThrow();
    expect(() =>
      signWithKey(state, projectId, "absent", message, [prefix]),
    ).toThrow();
  });
});
