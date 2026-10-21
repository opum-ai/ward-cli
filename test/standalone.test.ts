// WCLI-15, T23: the full P0 workflow works without Lore or Quest, and an
// optional integration failing does not disable the core vault operations.
//
// The spec's gate has two clauses and this proves both:
//   - NOT INSTALLED: the workflow runs with a PATH that holds neither tool,
//     checked as a precondition rather than assumed, since a developer
//     machine usually has both.
//   - INTEGRATION FAILURE: `lore` and `quest` shims that record that they were
//     called and exit nonzero sit first on PATH. The workflow must succeed and
//     the record must stay empty, which also shows Ward never reaches for them.
//     Calling a shim directly first proves the record can be written, so an
//     empty record means "not called" and not "could not record".
//
// Ward does not spawn either tool anywhere in src (grep for lore and quest
// finds only comments and the skill text); the one process it spawns,
// /bin/chmod, is an absolute path. This test keeps that true. It runs
// in-process with a memory credential store: the packaged binary would use the
// real keychain, so the packaged confirmation of this gate is T26's run of the
// qualification build under the same stripped PATH.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import type { PassphraseSource } from "../src/application/backup.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import type { Transport } from "../src/application/transport.ts";
import { runWard } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SYSTEM_PATH = "/usr/bin:/bin";
const PROFILE = "example-profile";
const ALIAS = "example-token";
const encoder = new TextEncoder();
const root = mkdtempSync(join(tmpdir(), "ward-standalone-"));
let cases = 0;

afterAll(() => rmSync(root, { recursive: true, force: true }));

function shimDirectory(record: string): string {
  const directory = mkdtempSync(join(root, "shims-"));
  for (const tool of ["lore", "quest"]) {
    const path = join(directory, tool);
    writeFileSync(
      path,
      `#!/bin/sh\necho "${tool} $*" >> "${record}"\nexit 9\n`,
    );
    chmodSync(path, 0o755);
  }
  return directory;
}

async function workflow(path: string): Promise<string[]> {
  const saved = process.env.PATH;
  process.env.PATH = path;
  try {
    const directory = join(
      mkdtempSync(join(root, `vault-${++cases}-`)),
      ".ward",
    );
    const keychain = new MemoryKeychain();
    const keyProvider = createKeychainKeyProvider({
      service: "opum.ward.standalone",
      entry: keychain.entry,
      timeoutMs: 2_000,
    });
    const yes = { available: () => true, ask: () => "approved" as const };
    const values: SecretValueSource = {
      available: () => true,
      readHidden: () => encoder.encode("synthetic-standalone-value"),
      readStdin: () => encoder.encode("synthetic-standalone-value"),
      confirmReplace: () => true,
    };
    const passphrases: PassphraseSource = {
      available: () => true,
      read: () => encoder.encode("synthetic-standalone-passphrase"),
    };
    const transport: Transport = {
      send: async () => ({ kind: "response", httpStatus: 200 }),
    };
    let ids = 0;
    const checkout = mkdtempSync(join(root, "repo-"));
    mkdirSync(join(checkout, ".git"));
    const ran: string[] = [];
    const ward = async (args: string[], expected = exitCodes.success) => {
      const result = await runWard([...args, "--json"], {
        wardDirectory: directory,
        keyProvider,
        approver: yes,
        profileApprover: yes,
        unregisterApprover: yes,
        secrets: values,
        passphrases,
        cwd: checkout,
        now: () => new Date("2026-10-20T00:00:00.000Z"),
        newId: () =>
          `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
        transport,
        machine: () => ({ user: "standalone-user", host: "standalone-host" }),
      });
      expect({ step: args[0], exit: result.exitCode }).toEqual({
        step: args[0],
        exit: expected,
      });
      ran.push(args.slice(0, 2).join(" "));
    };
    await ward(["setup"]);
    await ward(["init"]);
    const manifestPath = join(checkout, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.profiles = {
      [PROFILE]: {
        adapter: "http",
        method: "GET",
        url: "https://api.example.invalid/status",
        auth: { type: "bearer", secret: ALIAS },
        requestBody: "none",
        output: "status",
      },
    };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await ward(["secret", "set", ALIAS, "--stdin"]);
    await ward(["profile", "approve", PROFILE]);
    await ward(["check"]);
    await ward(["run", PROFILE]);
    await ward(["audit"]);
    await ward(["status"]);
    await ward(["doctor"]);
    const backup = join(mkdtempSync(join(root, "out-")), "backup.json");
    await ward(["backup", "--output", backup]);
    await ward(["unregister"]);
    return ran;
  } finally {
    process.env.PATH = saved;
  }
}

const find = (tool: string, path: string) =>
  Bun.which(tool, { PATH: path } as never);

describe("T23: standalone", () => {
  test("the full P0 workflow runs with neither Lore nor Quest on PATH", async () => {
    // The precondition, so "not installed" is a measurement.
    expect(find("lore", SYSTEM_PATH)).toBeNull();
    expect(find("quest", SYSTEM_PATH)).toBeNull();
    const ran = await workflow(SYSTEM_PATH);
    expect(ran.length).toBeGreaterThanOrEqual(11);
  });

  test("tools that are present and failing are never called and do not stop the workflow", async () => {
    const record = join(mkdtempSync(join(root, "record-")), "calls");
    const shims = shimDirectory(record);
    const path = `${shims}:${SYSTEM_PATH}`;
    // Positive control: the shim records when it is called.
    expect(find("lore", path)).toBe(join(shims, "lore"));
    expect(spawnSync(join(shims, "quest"), ["probe"]).status).toBe(9);
    expect(readFileSync(record, "utf8")).toBe("quest probe\n");
    rmSync(record);
    const ran = await workflow(path);
    expect(ran.length).toBeGreaterThanOrEqual(11);
    expect(existsSync(record)).toBe(false);
  });
});
