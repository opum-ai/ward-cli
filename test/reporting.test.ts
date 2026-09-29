// WCLI-26: `ward status` and `ward doctor` (spec §8). Both are read-only
// reports over the same state, so most of what these cases pin is shared:
// neither changes anything, neither names anything outside the current
// project, and neither renders key material. Doctor's half adds the exit
// contract: 6 when any check failed, with every check still reporting.
//
// The sentinel half covers the data that exists in the state model today --
// another project's id and another checkout's root. There are no secrets or
// aliases in the vault yet (WCLI-8+); when there are, this file's sentinels
// must be extended to them, and the "nothing outside this project" claim
// re-measured rather than assumed.
//
// Every case runs against a temporary vault, an in-memory credential store
// and a throwaway checkout; nothing touches the developer's ~/.ward, real
// keychain or repositories.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { locateCheckout } from "../src/adapters/checkout.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createProjectFiles } from "../src/adapters/project-files.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type { RegistrationApprover } from "../src/application/approvals.ts";
import { wardBlockBody } from "../src/application/bridges.ts";
import { runDoctor, runStatus } from "../src/application/reporting.ts";
import type { VaultStore } from "../src/application/vault-store.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { WardError } from "../src/contract/errors.ts";
import {
  parseVaultState,
  serializeVaultState,
  vaultStateFormatVersion,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SERVICE = "opum.ward.report";
const REGISTERED_AT = "2026-09-28T12:00:00.000Z";

const root = mkdtempSync(join(tmpdir(), "ward-report-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;

function worktree(name: string): string {
  const directory = join(root, `${name}-${++cases}`);
  mkdirSync(directory);
  mkdirSync(join(directory, ".git"));
  return directory;
}

const approver: RegistrationApprover = {
  available: () => true,
  ask: () => "approved",
};

function harness() {
  const directory = join(mkdtempSync(join(root, `case-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: SERVICE,
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  // A short busy timeout: nothing in this file contends for the vault except
  // the lock test below, which uses it to keep the wait bounded.
  const store = createSqliteVaultStore({ directory, busyTimeoutMs: 250 });

  const options = (
    cwd: string,
    extra: Partial<RunOptions> = {},
  ): RunOptions => ({
    wardDirectory: directory,
    keyProvider,
    approver,
    cwd,
    ...extra,
  });

  const setUp = async (cwd: string) => {
    const result = await runWard(["setup", "--json"], options(cwd));
    expect(result.exitCode).toBe(exitCodes.success);
  };

  const init = async (cwd: string, args: string[] = []) =>
    await runWard(["init", ...args, "--json"], options(cwd));

  const key = (): Uint8Array => {
    const stored = keychain.items.values().next().value as number[] | undefined;
    if (stored === undefined) throw new Error("no stored vault key");
    return new Uint8Array(stored);
  };

  return { directory, keychain, keyProvider, store, options, setUp, init, key };
}

interface StatusData {
  checkout: string;
  manifest: { status: string; projectId?: string; schemaVersion?: number };
  binding: { status: string };
  vault: { status: string; revision?: number; formatVersion?: number };
  keyProvider: { status: string };
}

interface DoctorData {
  ok: boolean;
  checks: {
    check: string;
    status: string;
    code: string;
    documents?: Record<string, string>;
  }[];
}

const json = (output: string) =>
  JSON.parse(output) as {
    schemaVersion: number;
    kind: string;
    data: unknown;
    principal: null;
  };

const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

const statusOf = async (h: ReturnType<typeof harness>, cwd: string) => {
  const result = await runWard(["status", "--json"], h.options(cwd));
  return { result, data: json(result.stdout).data as StatusData };
};

const doctorOf = async (h: ReturnType<typeof harness>, cwd: string) => {
  const result = await runWard(["doctor", "--json"], h.options(cwd));
  return { result, data: json(result.stdout).data as DoctorData };
};

// Works over both a parsed JSON report and the application's own readonly
// report, so the same accessor serves the end-to-end and port-level tests.
const checkFor = <T extends { check: string }>(
  data: { checks: readonly T[] },
  name: string,
): T => {
  const check = data.checks.find((entry) => entry.check === name);
  if (check === undefined) throw new Error(`no ${name} check reported`);
  return check;
};

describe("ward status", () => {
  test("reports this checkout, its project and the vault behind it", async () => {
    const h = harness();
    const checkout = worktree("status-happy");
    await h.setUp(checkout);
    const created = json((await h.init(checkout, ["--no-register"])).stdout)
      .data as { projectId: string };

    const { result, data } = await statusOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stderr).toBe("");
    expect(Object.keys(json(result.stdout))).toEqual([
      "schemaVersion",
      "kind",
      "data",
      "principal",
    ]);
    expect(json(result.stdout).kind).toBe("status.report");
    expect(json(result.stdout).schemaVersion).toBe(1);
    expect(data.checkout).toBe(realpathSync(checkout));
    expect(data.manifest).toEqual({
      status: "present",
      projectId: created.projectId,
      schemaVersion: 1,
    });
    expect(data.binding.status).toBe("unregistered");
    expect(data.vault).toEqual({
      status: "present",
      revision: 1,
      formatVersion: 1,
    });
    expect(data.keyProvider.status).toBe("present");

    // The human form carries the same answer.
    const text = (await runWard(["status"], h.options(checkout))).stdout;
    expect(text).toContain(created.projectId);
    expect(text).toContain("binding:       unregistered");
    expect(text).toContain("Ward read this state; it did not change anything.");
  });

  test("a registered checkout reports registered, and answers without the key", async () => {
    const h = harness();
    const checkout = worktree("status-registered");
    await h.setUp(checkout);
    await h.init(checkout);
    expect((await statusOf(h, checkout)).data.binding.status).toBe(
      "registered",
    );

    // A missing key is a recovery condition, not a refusal to report: the
    // vault and its format version are still readable without it.
    h.keychain.items.clear();
    const { result, data } = await statusOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(data.vault.status).toBe("present");
    expect(data.keyProvider.status).toBe("missing");
    expect(data.binding.status).toBe("unknown");
  });

  test("a conflict never names the other project, and the vault's other records stay in it", async () => {
    const h = harness();
    const checkout = worktree("status-conflict");
    await h.setUp(checkout);
    const bound = json((await h.init(checkout)).stdout).data as {
      projectId: string;
    };

    // Three ids must never surface: the project this checkout is actually
    // bound to — the one a conflict has to describe without naming — and a
    // second project with a second checkout's binding, seeded below.
    const otherProject = randomUUID();
    const otherRoot = "/tmp/ward-report-other-checkout";
    h.store.mutate(h.key(), (plaintext) => {
      const state = parseVaultState(plaintext);
      return serializeVaultState({
        ...state,
        projects: [
          ...state.projects,
          { id: otherProject, createdAt: REGISTERED_AT },
        ],
        localBindings: [
          ...state.localBindings,
          {
            projectId: otherProject,
            root: otherRoot,
            device: "1",
            inode: "2",
            registeredAt: REGISTERED_AT,
          },
        ],
      });
    });

    // The manifest is replaced, so this checkout's claim and its binding
    // disagree: the state a report has to describe without naming the project
    // the vault bound.
    const replacement = randomUUID();
    writeFileSync(
      join(checkout, ".ward", "project.json"),
      `${JSON.stringify({ schemaVersion: 1, projectId: replacement })}\n`,
    );

    const { result, data } = await statusOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(data.binding.status).toBe("conflict");
    // Positive controls first: the report did read the state, and it does
    // name this checkout's own claim.
    expect(data.manifest.projectId).toBe(replacement);
    expect(data.checkout).toBe(realpathSync(checkout));
    expect(result.stdout).not.toContain(bound.projectId);
    expect(result.stdout).not.toContain(otherProject);
    expect(result.stdout).not.toContain(otherRoot);
    const text = (await runWard(["status"], h.options(checkout))).stdout;
    expect(text).toContain(replacement);
    expect(text).not.toContain(bound.projectId);
    expect(text).not.toContain(otherProject);
    expect(text).not.toContain(otherRoot);
    // The doctor report over the same state carries the same verdict and the
    // same restraint.
    const doctor = await runWard(["doctor", "--json"], h.options(checkout));
    expect(doctor.stdout).not.toContain(bound.projectId);
    expect(doctor.stdout).not.toContain(otherProject);
    expect(doctor.stdout).not.toContain(otherRoot);
  });

  test("outside a Git worktree both commands exit 3", async () => {
    const h = harness();
    const nowhere = join(root, `nowhere-${++cases}`);
    mkdirSync(nowhere);
    for (const command of ["status", "doctor"]) {
      const result = await runWard([command, "--json"], h.options(nowhere));
      expect(result.exitCode).toBe(exitCodes.notFound);
      expect(errorCode(result.stderr)).toBe("worktree_not_found");
    }
  });
});

describe("ward doctor", () => {
  test("a healthy checkout passes every check and exits 0", async () => {
    const h = harness();
    const checkout = worktree("doctor-healthy");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude", "--codex"]);

    const { result, data } = await doctorOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stderr).toBe("");
    expect(Object.keys(json(result.stdout))).toEqual([
      "schemaVersion",
      "kind",
      "data",
      "principal",
    ]);
    expect(json(result.stdout).kind).toBe("doctor.report");
    expect(data.ok).toBe(true);
    expect(data.checks.map((entry) => entry.check)).toEqual([
      "permissions",
      "key_provider",
      "schema",
      "binding",
      "instructions",
    ]);
    expect(data.checks.every((entry) => entry.status === "pass")).toBe(true);
    expect(checkFor(data, "instructions").documents).toEqual({
      claude: "current",
      codex: "current",
    });
  });

  test("permissions: an insecure location fails, and fixing it passes", async () => {
    const h = harness();
    const checkout = worktree("doctor-permissions");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);

    chmodSync(h.directory, 0o755);
    try {
      const { result, data } = await doctorOf(h, checkout);
      expect(result.exitCode).toBe(exitCodes.validation);
      expect(data.ok).toBe(false);
      expect(checkFor(data, "permissions")).toMatchObject({
        status: "fail",
        code: "insecure",
      });
      // Every check still reports, and the checks the location blocks name
      // the block rather than reading as healthy.
      expect(data.checks).toHaveLength(5);
      for (const check of data.checks) expect(check.code).toBeTruthy();
      expect(checkFor(data, "key_provider").code).toBe("vault_insecure");
      expect(checkFor(data, "instructions").status).toBe("pass");
    } finally {
      chmodSync(h.directory, 0o700);
    }

    const restored = await doctorOf(h, checkout);
    expect(restored.result.exitCode).toBe(exitCodes.success);
    expect(restored.data.ok).toBe(true);
  });

  test("key provider: a missing vault key fails, and blocked checks say why", async () => {
    const h = harness();
    const checkout = worktree("doctor-key");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    h.keychain.items.clear();

    const { result, data } = await doctorOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(checkFor(data, "key_provider")).toMatchObject({
      status: "fail",
      code: "missing",
    });
    expect(checkFor(data, "permissions")).toMatchObject({
      status: "pass",
      code: "private",
    });
    // The state document and the binding cannot be judged without the key;
    // that is reported as a failure naming the reason, never as a pass.
    expect(checkFor(data, "schema").code).toBe("key_missing");
    expect(checkFor(data, "binding").code).toBe("key_missing");
  });

  test("key provider: a store that never answers is bounded and exits explicitly", async () => {
    const h = harness();
    const checkout = worktree("doctor-hang");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    h.keychain.mode = "hang";

    const { result, data } = await doctorOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(checkFor(data, "key_provider")).toMatchObject({
      status: "fail",
      code: "unavailable",
    });
    // The bounded call was abandoned with a native call possibly still
    // pending, so the process must exit explicitly rather than wait on it.
    expect(result.exitExplicitly).toBe(true);
  });

  test("a locked vault fails the checks that needed it, never passes them", async () => {
    const h = harness();
    const checkout = worktree("doctor-locked");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const identity = locateCheckout(checkout);
    // The harness store's short busy timeout is what keeps this quick; the
    // ports are driven directly so the locked read is a real SQLite lock
    // rather than a stub, with the same ports the composition root builds.
    const options = {
      checkout: identity,
      files: createProjectFiles(identity.root),
      store: h.store,
      keyProvider: h.keyProvider,
    };

    const locker = new Database(join(h.directory, "ward.db"));
    locker.exec("BEGIN EXCLUSIVE");
    try {
      const doctor = await runDoctor(options);
      expect(doctor.exitCode).toBe(exitCodes.validation);
      expect(checkFor(doctor.data, "permissions")).toMatchObject({
        status: "fail",
        code: "busy",
      });
      expect(checkFor(doctor.data, "key_provider")).toMatchObject({
        status: "fail",
        code: "vault_busy",
      });
      expect(checkFor(doctor.data, "schema").code).toBe("vault_busy");
      expect(checkFor(doctor.data, "binding").code).toBe("vault_busy");
      expect(checkFor(doctor.data, "instructions").status).toBe("pass");

      const status = await runStatus(options);
      expect(status.data.vault.status).toBe("busy");
      expect(status.data.keyProvider.status).toBe("unchecked");
    } finally {
      locker.exec("ROLLBACK");
      locker.close();
    }

    // Both halves of the gate, measured: the same checkout passes once the
    // writer is gone.
    const recovered = await runDoctor(options);
    expect(recovered.exitCode).toBe(exitCodes.success);
  });

  test("a vault store that fails is reported unreadable, never absent", async () => {
    const h = harness();
    const checkout = worktree("doctor-store-failed");
    const identity = locateCheckout(checkout);
    // The port is the seam: a store whose every read fails must not be
    // reported as a vault that was never there. A real SQLite failure and
    // "no vault" are different facts, and this pins the mapping between them.
    const failing: VaultStore = {
      header: () => {
        throw new WardError("vault_store_failed");
      },
      create: () => {
        throw new WardError("vault_store_failed");
      },
      read: () => {
        throw new WardError("vault_store_failed");
      },
      mutate: () => {
        throw new WardError("vault_store_failed");
      },
    };
    const options = {
      checkout: identity,
      files: createProjectFiles(identity.root),
      store: failing,
      keyProvider: h.keyProvider,
    };

    const doctor = await runDoctor(options);
    expect(doctor.exitCode).toBe(exitCodes.validation);
    expect(checkFor(doctor.data, "permissions")).toMatchObject({
      status: "fail",
      code: "unreadable",
    });
    expect(checkFor(doctor.data, "key_provider")).toMatchObject({
      status: "fail",
      code: "vault_unreadable",
    });
    expect(checkFor(doctor.data, "schema").code).toBe("vault_unreadable");
    expect(checkFor(doctor.data, "binding").status).toBe("skipped");

    const status = await runStatus(options);
    expect(status.data.vault.status).toBe("unreadable");
    expect(status.data.keyProvider.status).toBe("unchecked");
  });

  test("schema: a newer manifest and a future state document both fail", async () => {
    const h = harness();
    const checkout = worktree("doctor-schema");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const manifestPath = join(checkout, ".ward", "project.json");
    const manifest = readFileSync(manifestPath, "utf8");

    writeFileSync(
      manifestPath,
      `${JSON.stringify({
        schemaVersion: 2,
        projectId: randomUUID(),
        profiles: { deploy: {} },
      })}\n`,
    );
    const newer = await doctorOf(h, checkout);
    expect(newer.result.exitCode).toBe(exitCodes.validation);
    expect(checkFor(newer.data, "schema")).toMatchObject({
      status: "fail",
      code: "manifest_unsupported",
    });
    // A claim that exists but cannot be judged is a failure, not an absence.
    expect(checkFor(newer.data, "binding")).toMatchObject({
      status: "fail",
      code: "manifest_unsupported",
    });

    // A state document from another build is refused by the same parse the
    // real reads run. The version is one this build does not write — stated
    // relative to the format this build does write, so the case keeps meaning
    // "a build that is not this one" rather than pinning a number that a bump
    // would quietly turn into this build's own (WCLI-11 regenerated this
    // fixture; it read `2`, which was a future version until format 2 landed).
    writeFileSync(manifestPath, manifest);
    h.store.mutate(h.key(), () =>
      new TextEncoder().encode(
        JSON.stringify({ formatVersion: vaultStateFormatVersion + 1 }),
      ),
    );
    const future = await doctorOf(h, checkout);
    expect(future.result.exitCode).toBe(exitCodes.validation);
    expect(checkFor(future.data, "schema")).toMatchObject({
      status: "fail",
      code: "state_unsupported",
    });
    expect(checkFor(future.data, "permissions")).toMatchObject({
      status: "pass",
      code: "private",
    });
  });

  test("binding: unregistered, then registered, then a conflict", async () => {
    const h = harness();
    const checkout = worktree("doctor-binding");
    await h.setUp(checkout);
    await h.init(checkout, ["--no-register"]);

    const unregistered = await doctorOf(h, checkout);
    expect(unregistered.result.exitCode).toBe(exitCodes.validation);
    expect(checkFor(unregistered.data, "binding")).toMatchObject({
      status: "fail",
      code: "unregistered",
    });

    await h.init(checkout, ["--claude"]);
    const registered = await doctorOf(h, checkout);
    expect(registered.result.exitCode).toBe(exitCodes.success);
    expect(checkFor(registered.data, "binding")).toMatchObject({
      status: "pass",
      code: "registered",
    });

    writeFileSync(
      join(checkout, ".ward", "project.json"),
      `${JSON.stringify({ schemaVersion: 1, projectId: randomUUID() })}\n`,
    );
    const conflict = await doctorOf(h, checkout);
    expect(conflict.result.exitCode).toBe(exitCodes.validation);
    expect(checkFor(conflict.data, "binding")).toMatchObject({
      status: "fail",
      code: "conflict",
    });
  });

  test("instructions: stale and malformed blocks fail, a host with no block is reported", async () => {
    const h = harness();
    const checkout = worktree("doctor-instructions");
    const claude = join(checkout, "CLAUDE.md");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);

    writeFileSync(
      claude,
      "# Project\n\n<!-- ward:begin -->\nold guidance\n<!-- ward:end -->\n",
    );
    const stale = await doctorOf(h, checkout);
    expect(stale.result.exitCode).toBe(exitCodes.validation);
    expect(stale.data.checks.filter((c) => c.status === "fail").length).toBe(1);
    expect(checkFor(stale.data, "instructions")).toMatchObject({
      status: "fail",
      code: "stale",
      documents: { claude: "stale", codex: "absent" },
    });

    writeFileSync(claude, "<!-- ward:begin -->\nno end marker\n");
    const malformed = await doctorOf(h, checkout);
    expect(malformed.result.exitCode).toBe(exitCodes.validation);
    expect(checkFor(malformed.data, "instructions")).toMatchObject({
      status: "fail",
      code: "malformed",
    });

    // A file with no block at all is not a failure: bridge selection is
    // optional, and judging absence for a named host is `ward agents --check`.
    writeFileSync(claude, "# Project\n");
    const absent = await doctorOf(h, checkout);
    expect(absent.result.exitCode).toBe(exitCodes.success);
    expect(checkFor(absent.data, "instructions")).toMatchObject({
      status: "skipped",
      code: "absent",
      documents: { claude: "absent", codex: "absent" },
    });

    // A current block passes, and the refresh the stale case needs is the
    // one init performs.
    writeFileSync(
      claude,
      `<!-- ward:begin -->\n${wardBlockBody}<!-- ward:end -->\n`,
    );
    const current = await doctorOf(h, checkout);
    expect(current.result.exitCode).toBe(exitCodes.success);
    expect(checkFor(current.data, "instructions")).toMatchObject({
      status: "pass",
      code: "current",
    });
  });
});

describe("both commands change nothing and render nothing secret", () => {
  test("vault, manifest and bridge files are byte-identical, and the key never appears", async () => {
    const h = harness();
    const checkout = worktree("quiet");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude", "--codex"]);

    const dbPath = join(h.directory, "ward.db");
    const manifestPath = join(checkout, ".ward", "project.json");
    const claudePath = join(checkout, "CLAUDE.md");
    const agentsPath = join(checkout, "AGENTS.md");
    const before = {
      db: readFileSync(dbPath),
      manifest: readFileSync(manifestPath),
      // Both bridge files: a write through the codex path is a mutation too.
      claude: readFileSync(claudePath),
      agents: readFileSync(agentsPath),
      // And nothing new may appear beside them, in the checkout or in the
      // vault directory (which holds the database, its journal and the
      // setup lock).
      checkoutListing: readdirSync(checkout),
      vaultListing: readdirSync(h.directory),
      revision: h.store.header()?.revision,
      writes: h.keychain.writeAttempts,
    };
    const stored = h.key();
    const encodings = [
      Buffer.from(stored).toString("hex"),
      Buffer.from(stored).toString("base64"),
      Buffer.from(stored).toString("latin1"),
    ];

    for (const argv of [
      ["status", "--json"],
      ["status"],
      ["doctor", "--json"],
      ["doctor"],
    ]) {
      const result = await runWard(argv, h.options(checkout));
      expect(result.exitCode).toBe(exitCodes.success);
      for (const encoding of encodings) {
        expect(result.stdout.includes(encoding)).toBe(false);
        expect(result.stderr.includes(encoding)).toBe(false);
      }
    }

    expect(h.keychain.writeAttempts).toBe(before.writes);
    expect(h.store.header()?.revision).toBe(before.revision);
    expect(readFileSync(dbPath).equals(before.db)).toBe(true);
    expect(readFileSync(manifestPath).equals(before.manifest)).toBe(true);
    expect(readFileSync(claudePath).equals(before.claude)).toBe(true);
    expect(readFileSync(agentsPath).equals(before.agents)).toBe(true);
    expect(readdirSync(checkout)).toEqual(before.checkoutListing);
    expect(readdirSync(h.directory)).toEqual(before.vaultListing);
  });
});
