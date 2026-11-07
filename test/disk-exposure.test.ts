// WCLI-15, T05 in full: no synthetic plaintext on disk after any command path.
//
// vault-store.test.ts proves it for the store's own operations. This proves it
// for the CLI: every command in the manifest is driven, with a synthetic value
// entered both hidden and on stdin, replaced, used, refused, backed up,
// restored, granted, revoked and deleted, and after EVERY step the whole
// temporary root is scanned. That root holds the vault directory with its
// -wal, -shm and -journal sidecars, each checkout, and the backup files, and
// TMPDIR is pointed into it so a temp file Ward wrote would sit in the scan.
// (Ward writes no temp file today, which `src` shows: it never calls
// mkdtemp or tmpdir. The scan keeps that true.)
//
// Three guards keep the scan from passing vacuously:
//   - the set of command PATHS exercised must equal the manifest's: a command
//     that takes an action is expanded into `command action` for every action
//     its vocabulary declares, so a new command, or a new action such as
//     `secret export`, fails here until it is driven or exempted with a reason;
//   - every scan reports how many files it read, and that must be positive;
//   - a planted-value case proves the scan finds the value in every form it
//     claims to (raw, base64, hex), in a sidecar, and in a backup-named file.
// Assertions report a label, never the value under test.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import type {
  GrantApprover,
  ProfileApprover,
  RegistrationApprover,
  UnregisterApprover,
} from "../src/application/approvals.ts";
import type { PassphraseSource } from "../src/application/backup.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import type {
  Transport,
  TransportOutcome,
  TransportRequest,
} from "../src/application/transport.ts";
import { profileActions } from "../src/application/profiles.ts";
import { secretActions } from "../src/application/secrets.ts";
import { keyActions } from "../src/application/sign.ts";
import { runWard } from "../src/cli/main.ts";
import { type ExitCode, exitCodes } from "../src/contract/envelope.ts";
import { commands } from "../src/contract/manifest.ts";
import { scanDisk } from "./support/disk-scan.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const FIRST = "ward-sentinel-first-5d1c9e";
const SECOND = "ward-sentinel-second-8b2f47";
const PASSPHRASE = "ward-passphrase-sentinel-3a9e61";
const PROFILE = "example-profile";
const ALIAS = "example-token";
const ALIAS_B = "shared-token";
const encoder = new TextEncoder();

const root = mkdtempSync(join(tmpdir(), "ward-disk-"));
const scratchTmp = join(root, "tmp");
mkdirSync(scratchTmp);
const savedTmpdir = process.env.TMPDIR;
process.env.TMPDIR = scratchTmp;
afterAll(() => {
  if (savedTmpdir === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = savedTmpdir;
  rmSync(root, { recursive: true, force: true });
});

// The commands this file does not drive, each with the reason. Empty today:
// every command in the manifest has a step below.
const EXEMPT: Record<string, string> = {};

// The commands that take an action, and the vocabulary each declares. The
// manifest says a command takes one (an `action` argument); these say which.
const actionVocabulary: Record<string, readonly string[]> = {
  secret: secretActions,
  key: keyActions,
  profile: profileActions,
};

// A transport that answers or fails as told, and records nothing of the
// request: what reaches the network is T14/T17's concern, not the disk's.
class ScriptedTransport implements Transport {
  outcome: TransportOutcome = { kind: "response", httpStatus: 200 };
  async send(_request: TransportRequest): Promise<TransportOutcome> {
    return this.outcome;
  }
}

function machine(name: string) {
  const directory = join(mkdtempSync(join(root, `${name}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: `opum.ward.disk.${name}`,
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  return { directory, keychain, keyProvider };
}

function checkout(): string {
  const path = mkdtempSync(join(root, "repo-"));
  mkdirSync(join(path, ".git"));
  return path;
}

describe("T05: no synthetic plaintext on disk after any command path", () => {
  test("every command in the manifest, then the failure paths", async () => {
    const vault = machine("main");
    const transport = new ScriptedTransport();
    const exercised = new Set<string>();
    let value = FIRST;
    let passphrase = PASSPHRASE;
    let ids = 0;
    let scans = 0;
    let filesRead = 0;

    const values: SecretValueSource = {
      available: () => true,
      readHidden: () => encoder.encode(value),
      readStdin: () => encoder.encode(value),
      confirmReplace: () => true,
    };
    const yes = { available: () => true, ask: () => "approved" as const };
    const passphrases: PassphraseSource = {
      available: () => true,
      read: () => encoder.encode(passphrase),
    };

    const ward = async (cwd: string, args: string[], dir = vault) => {
      exercised.add(
        actionVocabulary[args[0] as string] === undefined
          ? (args[0] as string)
          : `${args[0]} ${args[1]}`,
      );
      return runWard([...args, "--json"], {
        wardDirectory: dir.directory,
        keyProvider: dir.keyProvider,
        approver: yes as RegistrationApprover,
        profileApprover: yes as ProfileApprover,
        grantApprover: yes as GrantApprover,
        unregisterApprover: yes as UnregisterApprover,
        secrets: values,
        passphrases,
        cwd,
        now: () => new Date("2026-10-20T00:00:00.000Z"),
        newId: () =>
          `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
        transport,
        machine: () => ({ user: "disk-user", host: "disk-host" }),
      });
    };

    // After every step: the whole root, for each synthetic value, and the
    // command's own output too, since a value on stdout is a disclosure the
    // disk scan alone would not see.
    const settle = (
      label: string,
      result?: { stdout: string; stderr: string },
    ) => {
      for (const needle of [FIRST, SECOND, PASSPHRASE]) {
        const scan = scanDisk(root, needle);
        scans++;
        filesRead += scan.filesRead;
        expect({ label, found: scan.found }).toEqual({ label, found: [] });
        if (result !== undefined)
          expect({
            label,
            leaked: (result.stdout + result.stderr).includes(needle),
          }).toEqual({ label, leaked: false });
      }
    };

    const step = async (
      label: string,
      cwd: string,
      args: string[],
      expected: ExitCode = exitCodes.success,
    ) => {
      const result = await ward(cwd, args);
      expect({ label, exit: result.exitCode }).toEqual({
        label,
        exit: expected,
      });
      settle(label, result);
      return result;
    };

    const first = checkout();
    const second = checkout();
    await step("setup", first, ["setup"]);
    await step("init", first, ["init"]);
    const manifestPath = join(first, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      projectId: string;
      profiles?: Record<string, unknown>;
    };
    manifest.profiles = {
      [PROFILE]: {
        adapter: "http",
        method: "GET",
        url: "https://api.example.invalid/status",
        auth: { type: "bearer", secret: ALIAS },
        requestBody: "none",
        output: "status",
      },
      // A sign profile over the key the `key generate` step makes. The bytes
      // it signs are a synthetic sentinel, so the scan also shows a sign
      // leaves neither its input nor the key on disk.
      signer: {
        adapter: "sign",
        key: "signing-key",
        prefixes: [Buffer.from("ward-sentinel-").toString("base64")],
      },
    };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await step("secret set --stdin", first, [
      "secret",
      "set",
      ALIAS,
      "--stdin",
    ]);
    await step("secret set hidden", first, ["secret", "set", ALIAS_B]);
    value = SECOND;
    await step("secret replace", first, ["secret", "set", ALIAS, "--stdin"]);
    await step("secret list", first, ["secret", "list"]);
    await step("secret inspect", first, ["secret", "inspect", ALIAS]);
    await step("key generate", first, ["key", "generate", "signing-key"]);
    await step("key public", first, ["key", "public", "signing-key"]);
    await step("profile approve", first, ["profile", "approve", PROFILE]);
    await step("profile approve signer", first, [
      "profile",
      "approve",
      "signer",
    ]);
    await step("profile list", first, ["profile", "list"]);
    await step("check", first, ["check"]);
    await step("run", first, ["run", PROFILE]);
    await step("sign", first, ["sign", "signer"]);
    await step("status", first, ["status"]);
    await step("doctor", first, ["doctor"]);
    await step("audit", first, ["audit"]);
    await step("manifest", first, ["manifest"]);
    await step("instructions", first, ["instructions"]);
    await step("help", first, ["help"]);
    await step("agents --check", first, [
      "agents",
      "--check",
      "--target",
      "claude",
    ]);
    await step("agents --update-instructions", first, [
      "agents",
      "--update-instructions",
      "--target",
      "claude",
    ]);

    // A second project, and a grant to it and back.
    await step("init (second project)", second, ["init"]);
    const target = (
      JSON.parse(
        readFileSync(join(second, ".ward", "project.json"), "utf8"),
      ) as {
        projectId: string;
      }
    ).projectId;
    await step("secret grant", first, [
      "secret",
      "grant",
      ALIAS,
      "--to",
      target,
      "--as",
      ALIAS_B,
    ]);
    await step("secret revoke", first, [
      "secret",
      "revoke",
      ALIAS,
      "--from",
      target,
    ]);

    const backups = mkdtempSync(join(root, "backups-"));
    const backup = join(backups, "backup.json");
    await step("backup", first, ["backup", "--output", backup]);
    const restored = machine("restored");
    exercised.add("restore");
    const restore = await ward(
      checkout(),
      ["restore", "--input", backup],
      restored,
    );
    expect(restore.exitCode).toBe(exitCodes.success);
    settle("restore", restore);

    await step("secret delete", first, ["secret", "delete", ALIAS_B]);
    await step("profile revoke", first, ["profile", "revoke", PROFILE]);
    await step("unregister", first, ["unregister"]);

    // Failure paths, each followed by the same scan.
    transport.outcome = { kind: "not-sent", reason: "connection-failed" };
    await ward(first, ["run", PROFILE]);
    settle("run after unregister (refused admission)");
    passphrase = "a different wrong passphrase";
    const wrong = await ward(
      checkout(),
      ["restore", "--input", backup],
      machine("wrongpass"),
    );
    expect(wrong.exitCode).not.toBe(exitCodes.success);
    settle("restore with a wrong passphrase", wrong);

    // Ward wrote no temporary file: the directory TMPDIR pointed at is empty.
    expect(readdirSync(scratchTmp)).toEqual([]);

    // Guards against a vacuous pass.
    expect(scans).toBeGreaterThan(30);
    expect(filesRead).toBeGreaterThan(scans);
    // Every command the manifest gives an action argument has a vocabulary
    // here, so a new action-taking command cannot be missed.
    expect(
      commands
        .filter((command) => command.args.some((arg) => arg.name === "action"))
        .map((command) => command.name)
        .sort(),
    ).toEqual(Object.keys(actionVocabulary).sort());
    const manifested = new Set(
      commands.flatMap((command) =>
        (actionVocabulary[command.name] ?? [undefined]).map((action) =>
          action === undefined ? command.name : `${command.name} ${action}`,
        ),
      ),
    );
    const driven = new Set([...exercised, ...Object.keys(EXEMPT)]);
    expect([...manifested].filter((name) => !driven.has(name))).toEqual([]);
    expect([...driven].filter((name) => !manifested.has(name))).toEqual([]);
  });

  test("the scan finds the value in every form it claims, in a sidecar and a backup", () => {
    const planted = mkdtempSync(join(root, "planted-"));
    writeFileSync(join(planted, "vault.db-wal"), `x${FIRST}x`);
    writeFileSync(
      join(planted, "backup.json"),
      Buffer.from(FIRST).toString("base64"),
    );
    writeFileSync(
      join(planted, "other.db-journal"),
      Buffer.from(FIRST).toString("hex"),
    );
    writeFileSync(join(planted, "clean"), "nothing here");
    const scan = scanDisk(planted, FIRST);
    expect(scan.filesRead).toBe(4);
    expect(scan.found.sort()).toEqual([
      "backup.json",
      "other.db-journal",
      "vault.db-wal",
    ]);
  });
});
