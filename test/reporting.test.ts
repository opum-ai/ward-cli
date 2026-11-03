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
import {
  bindCheckoutIdentity,
  locateCheckout,
  probeCheckout,
} from "../src/adapters/checkout.ts";
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
import { profileSnapshotVersion } from "../src/domain/profile.ts";
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

// A declaration this build normalizes. A record of header names to values, not
// a list: an array is refused as an invalid declaration, which would make a
// case inert for a reason it is not about.
const profileDeclaration = (): Record<string, unknown> => ({
  adapter: "http",
  method: "GET",
  url: "https://api.example.invalid/rate_limit",
  auth: { type: "bearer", secret: "example.token" },
  headers: { Accept: "application/json" },
  requestBody: "none",
  output: "status",
});

// Adds a profile declaration to the manifest `ward init` wrote, and returns
// the manifest's own project id — the value that decides whether a stale
// record is this project's or another's (DEC-246 a3 Q1), and, with the
// declaration, whether re-approving it is still possible (Q2).
function declareProfile(checkout: string, profile: string): string {
  const path = join(checkout, ".ward", "project.json");
  const manifest = JSON.parse(readFileSync(path, "utf8")) as {
    projectId: string;
    profiles?: Record<string, unknown>;
  };
  manifest.profiles = {
    ...(manifest.profiles ?? {}),
    [profile]: profileDeclaration(),
  };
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest.projectId;
}

// One stored approval record, raw: the shape the parser reads, before this
// build decides what to make of it. Raw on purpose, because these cases are
// about records another build wrote.
function approvalRecord(options: {
  profile: string;
  projectId: string;
  root: string;
  device: string;
  inode: string;
  checkoutId?: string;
  snapshotVersion?: number;
}): Record<string, unknown> {
  return {
    profile: options.profile,
    projectId: options.projectId,
    root: options.root,
    device: options.device,
    inode: options.inode,
    ...(options.checkoutId === undefined
      ? {}
      : { checkoutId: options.checkoutId }),
    approvedAt: "2026-09-29T00:00:00.000Z",
    expiresAt: "2026-09-30T00:00:00.000Z",
    snapshotVersion: options.snapshotVersion ?? profileSnapshotVersion + 1,
    snapshot: {
      adapter: "http",
      method: "GET",
      url: "https://api.example.invalid/a",
      auth: { type: "bearer", secret: "example.token" },
      headers: [],
      requestBody: "none",
      output: "status",
    },
  };
}

// Appends raw records to the vault's state document without disturbing
// anything already in it. The bindings `ward init` wrote matter here: a record
// no checkout is registered for can never be cleared, so a seed that replaced
// the whole document would make every case inert and the clearable half of
// DEC-246 (a3) Q2 would never be exercised.
function seedState(
  h: ReturnType<typeof harness>,
  extra: { approvals?: unknown[]; bindings?: unknown[] },
): void {
  h.store.mutate(h.key(), (plaintext) => {
    const document = JSON.parse(new TextDecoder().decode(plaintext)) as {
      profileApprovals?: unknown[];
      localBindings?: unknown[];
    };
    if (extra.approvals !== undefined)
      document.profileApprovals = [
        ...(document.profileApprovals ?? []),
        ...extra.approvals,
      ];
    if (extra.bindings !== undefined)
      document.localBindings = [
        ...(document.localBindings ?? []),
        ...extra.bindings,
      ];
    return new TextEncoder().encode(JSON.stringify(document));
  });
}

function seedApprovals(
  h: ReturnType<typeof harness>,
  records: unknown[],
): void {
  seedState(h, { approvals: records });
}

function bindingRecord(identity: {
  projectId: string;
  root: string;
  device: string;
  inode: string;
  checkoutId?: string;
}): Record<string, unknown> {
  return { ...identity, registeredAt: "2026-09-29T00:00:00.000Z" };
}

// A second directory that is its own checkout root, standing outside the one
// being reported. Records on such a directory are the case DEC-246 (a3) Q1
// keeps visible and Q2 sometimes finds clearable.
function siblingCheckout(withGitEntry = true): string {
  const directory = join(root, `sibling-${++cases}`);
  mkdirSync(directory);
  if (withGitEntry) mkdirSync(join(directory, ".git"));
  return directory;
}

function writeManifestAt(directory: string, document: unknown): void {
  mkdirSync(join(directory, ".ward"), { recursive: true });
  writeFileSync(
    join(directory, ".ward", "project.json"),
    `${JSON.stringify(document, null, 2)}\n`,
  );
}

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

interface StaleApprovalData {
  profile: string;
  projectId: string;
  checkout: string;
  snapshotVersion: number;
  clearable: boolean;
  remedy: string;
}

interface StatusData {
  checkout: string;
  manifest: { status: string; projectId?: string; schemaVersion?: number };
  binding: { status: string };
  vault: { status: string; revision?: number; formatVersion?: number };
  keyProvider: { status: string };
  staleApprovals: StaleApprovalData[];
  otherProjectStaleApprovals: number;
}

interface DoctorData {
  ok: boolean;
  checks: {
    check: string;
    status: string;
    code: string;
    documents?: Record<string, string>;
    staleApprovals?: StaleApprovalData[];
    otherProjectStaleApprovals?: number;
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
      "stale_approvals",
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
      expect(data.checks).toHaveLength(6);
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
      checkouts: { probe: probeCheckout },
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
      // Finding 14 (rv331): a check that could not be evaluated fails with the
      // blocking reason, exactly as schema and binding do. `skipped` is
      // reserved for a subject that is not there, and reporting "nothing
      // stale" for a vault Ward never opened is the answer that reads as a
      // healthy one without being one.
      expect(checkFor(doctor.data, "stale_approvals")).toMatchObject({
        status: "fail",
        code: "vault_busy",
      });
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
      checkouts: { probe: probeCheckout },
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

    // A state document this build did not write is refused by the same parse
    // the real reads run, and since DEC-38 that refusal is the ordinary
    // malformed one rather than a distinguished "another build" state: with a
    // single format there is no other build for the report to name. The
    // version is still stated relative to the one this build writes, so the
    // case keeps meaning "not this build's" rather than pinning a literal
    // that a later change would quietly turn into this build's own.
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
      code: "state_malformed",
    });
    expect(checkFor(future.data, "permissions")).toMatchObject({
      status: "pass",
      code: "private",
    });
  });

  // WCLI-51 review, F1, reshaped by DEC-246 (a2). A document carrying a
  // record whose snapshot version names another build is not malformed and is
  // no longer refused: the approval is absent for authorisation, the rest of
  // the document parses, and both reports name it with the re-approve step.
  test("a stored approval from another build is named, not trusted", async () => {
    const h = harness();
    const checkout = worktree("doctor-approval-version");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const identity = locateCheckout(checkout);
    // The profile is declared and the record names this manifest's project, so
    // the only thing wrong with the record is the version it was written under
    // — which is what makes it the clearable case DEC-246 (a3) Q2 fails on.
    const projectId = declareProfile(checkout, "deploy");

    // A complete, canonical approval, so the version it was written under is
    // the only thing about the record this build cannot read.
    seedApprovals(h, [
      approvalRecord({
        profile: "deploy",
        projectId,
        root: identity.root,
        device: identity.device,
        inode: identity.inode,
        checkoutId: identity.checkoutId,
      }),
    ]);

    const doctor = await doctorOf(h, checkout);
    expect(doctor.result.exitCode).toBe(exitCodes.validation);
    // The positive control for "the report reached stdout": every check is
    // present, so the read answered rather than throwing out of the command.
    expect(doctor.data.checks).toHaveLength(6);
    // The schema is intact: the version mismatch is a record-level fact, not
    // a broken document (DEC-246 a2 clause 4's other half).
    expect(checkFor(doctor.data, "schema")).toMatchObject({
      status: "pass",
      code: "current",
    });
    const stale = checkFor(doctor.data, "stale_approvals");
    expect(stale).toMatchObject({ status: "fail", code: "reapprove_required" });
    expect(stale.staleApprovals).toEqual([
      expect.objectContaining({
        profile: "deploy",
        checkout: identity.root,
        snapshotVersion: profileSnapshotVersion + 1,
        // Finding 8 (rv331): the remedy travels in the JSON as well, and it
        // names the checkout — the replacement only matches there, so a
        // caller that composed the command from the other fields would write
        // a second approval and leave this one in place.
        remedy: `from ${identity.root}, run ward profile approve deploy`,
      }),
    ]);
    // The reports a person reads name the record, its checkout, its version
    // and the step that clears it.
    const doctorText = await runWard(["doctor"], h.options(checkout));
    expect(doctorText.stdout).toContain("deploy");
    expect(doctorText.stdout).toContain(identity.root);
    expect(doctorText.stdout).toContain("ward profile approve deploy");
    expect(doctorText.stdout).toContain("run from that checkout");
    expect(doctorText.stdout).toContain(
      `snapshot version ${profileSnapshotVersion + 1}`,
    );

    // And status answers too, names the same record, and exits 0: the report
    // it was able to produce is its declared success.
    const status = await statusOf(h, checkout);
    expect(status.result.exitCode).toBe(exitCodes.success);
    expect(status.data.staleApprovals).toEqual([
      expect.objectContaining({
        profile: "deploy",
        checkout: identity.root,
        snapshotVersion: profileSnapshotVersion + 1,
      }),
    ]);
    const statusText = await runWard(["status"], h.options(checkout));
    expect(statusText.stdout).toContain("ward profile approve deploy");
    expect(statusText.stdout).toContain(identity.root);
  });

  // Finding 9 (rv331): these lines print a checkout path stored in the vault,
  // and a path is allowed to carry format characters. A bidi override reorders
  // what follows it on the line, so an unescaped one can make the checkout
  // Ward names read as a different directory than the one the record holds.
  test("a stale record's checkout is escaped before it is printed", async () => {
    const h = harness();
    const checkout = worktree("doctor-stale-escape");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const identity = locateCheckout(checkout);
    const projectId = declareProfile(checkout, "deploy");
    const bidiOverride = String.fromCodePoint(0x202e);
    const hostileRoot = `${identity.root}/wo${bidiOverride}rktree`;

    seedApprovals(h, [
      approvalRecord({
        profile: "deploy",
        projectId,
        root: hostileRoot,
        device: identity.device,
        inode: identity.inode,
        checkoutId: identity.checkoutId,
      }),
    ]);

    const status = await runWard(["status"], h.options(checkout));
    // The record is still named — escaping is display, not suppression — and
    // the character that could act on the terminal is shown as text.
    expect(status.stdout).toContain("/wo");
    expect(status.stdout).not.toContain(bidiOverride);
    expect(status.stdout).toContain("\\u202e");
  });

  // DEC-246 (a3) Q1. `status` is admin:false and the skill tells agents to
  // read its JSON, so an inventory of the whole vault would land in agent
  // context. Another project's records are counted and never named: no id, no
  // profile name, no path.
  test("another project's stale approvals are counted, never named", async () => {
    const h = harness();
    const checkout = worktree("doctor-stale-scope");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const identity = locateCheckout(checkout);
    const projectId = declareProfile(checkout, "deploy");
    const otherProject = randomUUID();
    const sentinelProfile = "sentinel-profile-name";
    const sentinelRoot = `${identity.root}/sentinel-checkout-path`;

    seedApprovals(h, [
      approvalRecord({
        profile: "deploy",
        projectId,
        root: identity.root,
        device: identity.device,
        inode: identity.inode,
        checkoutId: identity.checkoutId,
      }),
      approvalRecord({
        profile: sentinelProfile,
        projectId: otherProject,
        root: sentinelRoot,
        device: identity.device,
        inode: identity.inode,
        checkoutId: identity.checkoutId,
      }),
    ]);

    const status = await statusOf(h, checkout);
    // The positive control: this project's own record is named, so the
    // absence below is about scope rather than about the report being empty.
    expect(status.data.staleApprovals).toEqual([
      expect.objectContaining({ profile: "deploy", projectId }),
    ]);
    expect(status.data.otherProjectStaleApprovals).toBe(1);

    const text = await runWard(["status"], h.options(checkout));
    expect(text.stdout).toContain("stale approvals in other projects: 1");
    for (const sentinel of [sentinelProfile, sentinelRoot, otherProject]) {
      expect(text.stdout).not.toContain(sentinel);
      expect(JSON.stringify(status.data)).not.toContain(sentinel);
    }

    // Finding 4 (rv331b): ADR 0007 says "either output", so doctor is held to
    // the same rule — its text and its JSON, not only status's.
    const doctor = await doctorOf(h, checkout);
    const stale = checkFor(doctor.data, "stale_approvals");
    // The positive control again: this project's record IS named here, so the
    // absence below is about scope and not about an empty check.
    expect(stale.staleApprovals).toEqual([
      expect.objectContaining({ profile: "deploy", projectId }),
    ]);
    expect(stale.otherProjectStaleApprovals).toBe(1);
    const doctorText = await runWard(["doctor"], h.options(checkout));
    expect(doctorText.stdout).toContain("stale approvals in other projects: 1");
    for (const sentinel of [sentinelProfile, sentinelRoot, otherProject]) {
      expect(doctorText.stdout).not.toContain(sentinel);
      expect(JSON.stringify(doctor.data)).not.toContain(sentinel);
    }
  });

  // DEC-246 (a3) Q2. The pair with "a stored approval from another build is
  // named, not trusted": the same record, the same project, the same
  // declaration — only the directory it was written for is gone. Nothing can
  // clear it, so doctor names it and does not fail, rather than exiting 6 in
  // every checkout forever over a step nobody can carry out.
  test("an inert stale record is named without failing the doctor", async () => {
    const h = harness();
    const checkout = worktree("doctor-stale-inert");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const identity = locateCheckout(checkout);
    const projectId = declareProfile(checkout, "deploy");
    const gone = `${identity.root}/deleted-worktree`;

    seedApprovals(h, [
      approvalRecord({
        profile: "deploy",
        projectId,
        root: gone,
        device: identity.device,
        inode: identity.inode,
        checkoutId: identity.checkoutId,
      }),
    ]);

    const doctor = await doctorOf(h, checkout);
    expect(doctor.result.exitCode).toBe(exitCodes.success);
    const stale = checkFor(doctor.data, "stale_approvals");
    expect(stale).toMatchObject({ status: "pass", code: "inert" });
    expect(stale.staleApprovals).toEqual([
      expect.objectContaining({ profile: "deploy", clearable: false }),
    ]);
    const text = await runWard(["doctor"], h.options(checkout));
    expect(text.stdout).toContain("inert and unreachable");
    expect(text.stdout).toContain("no longer exists");
  });

  // Finding 3 (rv331b): one case per remaining arm of describeStaleApproval,
  // so mutating any single check turns exactly one case red. The arm above
  // covers "that directory no longer exists"; these cover everything that can
  // happen to a record whose checkout is still there.
  test("every other inert arm is named and none of them fails the doctor", async () => {
    interface Arm {
      readonly name: string;
      readonly reason: string;
      readonly arrange: (fixture: {
        sibling: string;
        record: Record<string, unknown>;
        bindings: unknown[];
        projectId: string;
        otherProject: string;
        withGitEntry: boolean;
      }) => void;
    }

    const arms: readonly Arm[] = [
      {
        name: "device mismatch",
        reason: "a different directory now stands at that path",
        arrange: ({ record }) => {
          record.device = String(Number(record.device) + 1);
        },
      },
      {
        name: "nonce mismatch",
        reason: "a different directory now stands at that path",
        arrange: ({ record }) => {
          record.checkoutId = "c".repeat(32);
        },
      },
      {
        name: "no binding",
        reason: "that checkout is no longer registered",
        arrange: ({ bindings }) => {
          bindings.length = 0;
        },
      },
      {
        name: "binding to another project",
        reason: "that checkout is registered to another project",
        arrange: ({ bindings, sibling, otherProject }) => {
          const original = bindings[0] as Record<string, unknown>;
          bindings[0] = { ...original, projectId: otherProject };
          void sibling;
        },
      },
      {
        name: "no manifest",
        reason: "that checkout has no project manifest",
        arrange: ({ sibling }) => {
          rmSync(join(sibling, ".ward"), { recursive: true, force: true });
        },
      },
      {
        name: "manifest names another project",
        reason: "that checkout now declares another project",
        arrange: ({ sibling, otherProject }) => {
          writeManifestAt(sibling, {
            schemaVersion: 1,
            projectId: otherProject,
            profiles: { deploy: profileDeclaration() },
          });
        },
      },
      {
        name: "manifest cannot be read",
        reason: "that checkout's project manifest cannot be read",
        arrange: ({ sibling }) => {
          writeFileSync(join(sibling, ".ward", "project.json"), "{ not json");
        },
      },
      {
        name: "profile no longer declared",
        reason: "that checkout no longer declares this profile",
        arrange: ({ sibling, projectId }) => {
          writeManifestAt(sibling, {
            schemaVersion: 1,
            projectId,
            profiles: {},
          });
        },
      },
      {
        name: "declaration cannot be read",
        reason: "that checkout's declaration of this profile cannot be read",
        arrange: ({ sibling, projectId }) => {
          writeManifestAt(sibling, {
            schemaVersion: 1,
            projectId,
            profiles: { deploy: { adapter: "http" } },
          });
        },
      },
      {
        name: "path resolves to a different root",
        reason: "a different directory now stands at that path",
        // A directory that is not itself a checkout root: locateCheckout walks
        // up to the enclosing one, so the resolved root is not the record's.
        arrange: ({ withGitEntry }) => {
          void withGitEntry;
        },
      },
    ];

    for (const arm of arms) {
      const h = harness();
      const checkout = worktree(`doctor-arm-${arm.name.replace(/\s+/g, "-")}`);
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const identity = locateCheckout(checkout);
      const projectId = declareProfile(checkout, "deploy");
      const otherProject = randomUUID();
      // Most arms use a sibling that is its own checkout root; the last uses a
      // path that is not one, so its recorded root is a directory nested in
      // this checkout and resolves upward to it.
      const lastArm = arm.name === "path resolves to a different root";
      const sibling = lastArm
        ? join(checkout, "not-a-root")
        : siblingCheckout();
      if (lastArm) mkdirSync(sibling);
      const siblingIdentity = lastArm
        ? {
            root: sibling,
            device: identity.device,
            inode: identity.inode,
            checkoutId: identity.checkoutId,
          }
        : bindCheckoutIdentity(locateCheckout(sibling));
      if (!lastArm)
        writeManifestAt(sibling, {
          schemaVersion: 1,
          projectId,
          profiles: { deploy: profileDeclaration() },
        });

      const record = approvalRecord({
        profile: "deploy",
        projectId,
        root: siblingIdentity.root,
        device: siblingIdentity.device,
        inode: siblingIdentity.inode,
        checkoutId: siblingIdentity.checkoutId,
      });
      const bindings: unknown[] = [
        bindingRecord({ projectId, ...siblingIdentity }),
      ];
      arm.arrange({
        sibling,
        record,
        bindings,
        projectId,
        otherProject,
        withGitEntry: !lastArm,
      });
      seedState(h, { approvals: [record], bindings });

      const doctor = await doctorOf(h, checkout);
      expect({ arm: arm.name, code: doctor.result.exitCode }).toEqual({
        arm: arm.name,
        code: exitCodes.success,
      });
      const stale = checkFor(doctor.data, "stale_approvals");
      expect({ arm: arm.name, check: stale }).toMatchObject({
        arm: arm.name,
        check: { status: "pass", code: "inert" },
      });
      expect(stale.staleApprovals).toEqual([
        expect.objectContaining({ profile: "deploy", clearable: false }),
      ]);
      const text = await runWard(["doctor"], h.options(checkout));
      expect({ arm: arm.name, text: text.stdout }).toMatchObject({
        arm: arm.name,
        text: expect.stringContaining(arm.reason),
      });
    }
  });

  // WCLI-137 (N4, opus rounds 1 and 2): a stale approval with no nonce (a legacy
  // one) is judged like any other stale record against the checkout as it stands.
  // It is clearable, and fails the doctor, only when its checkout is registered
  // under the nonce it holds now, so that plain `ward profile approve` replaces
  // it. Everywhere else it is inert and the doctor passes: asking for a
  // registration would grant access nobody asked for (DEC-255 a6), or name a step
  // that cannot run. Each case asserts the remedy clause itself.
  describe("a legacy stale approval", () => {
    const legacyRecord = (
      projectId: string,
      identity: { root: string; device: string; inode: string },
    ) => {
      const record = approvalRecord({
        profile: "deploy",
        projectId,
        ...identity,
      });
      delete record.checkoutId;
      return record;
    };

    test("is clearable by approving again when its checkout is registered", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-registered");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const identity = locateCheckout(checkout);
      const projectId = declareProfile(checkout, "deploy");
      seedApprovals(h, [legacyRecord(projectId, identity)]);

      const doctor = await doctorOf(h, checkout);
      expect(checkFor(doctor.data, "stale_approvals")).toMatchObject({
        status: "fail",
        code: "reapprove_required",
      });
      expect(checkFor(doctor.data, "stale_approvals").staleApprovals).toEqual([
        expect.objectContaining({
          clearable: true,
          remedy: `from ${identity.root}, run ward profile approve deploy`,
        }),
      ]);
      const text = await runWard(["doctor"], h.options(checkout));
      expect(text.stdout).toContain(
        "re-approve in a trusted terminal with ward profile approve deploy",
      );
      expect(text.stdout).not.toContain("inert and unreachable");
    });

    // The unregistered cases: the record is untouched residue, so the doctor
    // passes and does not ask for a registration that would grant access
    // (DEC-255 a6). The hint is worded from the `legacy` field and is not framed
    // as unreachable. Each variant is a different way for the checkout to hold
    // no current binding; each failed the doctor at b60ba1c.
    const expectInertLegacy = async (
      h: ReturnType<typeof harness>,
      checkout: string,
      found: { root: string },
    ) => {
      const doctor = await doctorOf(h, checkout);
      expect(doctor.result.exitCode).toBe(exitCodes.success);
      const stale = checkFor(doctor.data, "stale_approvals");
      expect(stale).toMatchObject({ status: "pass", code: "inert" });
      expect(stale.staleApprovals).toEqual([
        expect.objectContaining({
          clearable: false,
          legacy: true,
          remedy: expect.stringContaining(
            `register and approve again from ${found.root} (ward init, then ward profile approve deploy)`,
          ),
        }),
      ]);
      const text = await runWard(["doctor"], h.options(checkout));
      expect(text.stdout).toContain(
        "register and approve again from that checkout (ward init, then ward profile approve deploy)",
      );
      expect(text.stdout).not.toContain("inert and unreachable");
    };
    const unregisteredSibling = (projectId: string, bare: boolean) => {
      const sibling = siblingCheckout();
      writeManifestAt(sibling, {
        schemaVersion: 1,
        projectId,
        profiles: { deploy: profileDeclaration() },
      });
      if (!bare) bindCheckoutIdentity(locateCheckout(sibling));
      return locateCheckout(sibling);
    };

    test("is inert, with a hint, when its checkout holds no nonce", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-no-nonce");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const found = unregisteredSibling(projectId, true);
      seedState(h, { approvals: [legacyRecord(projectId, found)] });
      await expectInertLegacy(h, checkout, found);
    });

    // M1: the user unregistered that checkout on purpose. Its nonce file
    // survives, its binding is gone, and the stale record stays: the doctor must
    // not demand the registration the user withdrew.
    test("is inert after a deliberate unregister that left the nonce behind", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-unregistered");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const found = unregisteredSibling(projectId, false);
      expect(found.checkoutId).toBeDefined();
      seedState(h, { approvals: [legacyRecord(projectId, found)] });
      await expectInertLegacy(h, checkout, found);
    });

    // M2: a checkout whose identity cannot be bound is one `ward init` cannot
    // register, so no step the doctor could name would work.
    test("is inert when the checkout's git directory was pruned", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-pruned");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const sibling = siblingCheckout(false);
      writeFileSync(join(sibling, ".git"), `gitdir: ${sibling}-pruned\n`);
      writeManifestAt(sibling, {
        schemaVersion: 1,
        projectId,
        profiles: { deploy: profileDeclaration() },
      });
      const found = locateCheckout(sibling);
      seedState(h, { approvals: [legacyRecord(projectId, found)] });
      await expectInertLegacy(h, checkout, found);
    });

    test("is inert when the checkout's nonce file is invalid", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-bad-nonce");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const found = unregisteredSibling(projectId, true);
      mkdirSync(join(found.root, ".git", "ward"), { recursive: true });
      writeFileSync(
        join(found.root, ".git", "ward", "checkout-id"),
        "garbage\n",
      );
      seedState(h, { approvals: [legacyRecord(projectId, found)] });
      await expectInertLegacy(h, checkout, found);
    });

    test("is inert when the checkout's current binding is another project's", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-other-binding");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const found = unregisteredSibling(projectId, false);
      seedState(h, {
        approvals: [legacyRecord(projectId, found)],
        bindings: [bindingRecord({ projectId: randomUUID(), ...found })],
      });
      const doctor = await doctorOf(h, checkout);
      expect(doctor.result.exitCode).toBe(exitCodes.success);
      expect(checkFor(doctor.data, "stale_approvals")).toMatchObject({
        status: "pass",
        code: "inert",
      });
      const text = await runWard(["doctor"], h.options(checkout));
      expect(text.stdout).toContain(
        "that checkout is registered to another project",
      );
    });

    test("is inert only when its checkout no longer declares the profile", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-undeclared");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const sibling = siblingCheckout();
      writeManifestAt(sibling, { schemaVersion: 1, projectId, profiles: {} });
      seedState(h, {
        approvals: [legacyRecord(projectId, locateCheckout(sibling))],
      });

      const doctor = await doctorOf(h, checkout);
      expect(doctor.result.exitCode).toBe(exitCodes.success);
      expect(checkFor(doctor.data, "stale_approvals")).toMatchObject({
        status: "pass",
        code: "inert",
      });
      const text = await runWard(["doctor"], h.options(checkout));
      expect(text.stdout).toContain(
        "that checkout no longer declares this profile",
      );
    });
  });

  // Finding 3 (rv331b), the two whole-report shapes: only other projects'
  // records, and a checkout with no manifest at all.
  test("other projects alone give a count and the other_projects code", async () => {
    const h = harness();
    const checkout = worktree("doctor-other-only");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const identity = locateCheckout(checkout);
    declareProfile(checkout, "deploy");
    const otherProject = randomUUID();

    seedState(h, {
      approvals: [
        approvalRecord({
          profile: "sentinel-other-profile",
          projectId: otherProject,
          root: join(identity.root, "elsewhere"),
          device: identity.device,
          inode: identity.inode,
          checkoutId: identity.checkoutId,
        }),
      ],
    });

    const doctor = await doctorOf(h, checkout);
    expect(doctor.result.exitCode).toBe(exitCodes.success);
    const stale = checkFor(doctor.data, "stale_approvals");
    expect(stale).toMatchObject({
      status: "pass",
      code: "other_projects",
      staleApprovals: [],
      otherProjectStaleApprovals: 1,
    });
    const text = await runWard(["doctor"], h.options(checkout));
    expect(text.stdout).toContain("stale approvals in other projects: 1");
    expect(text.stdout).not.toContain("sentinel-other-profile");
  });

  test("a checkout with no manifest names nothing and counts everything", async () => {
    const h = harness();
    const checkout = worktree("doctor-no-manifest");
    await h.setUp(checkout);
    await h.init(checkout, ["--claude"]);
    const identity = locateCheckout(checkout);
    const projectId = declareProfile(checkout, "deploy");
    // The record is otherwise completely clearable: it names this very
    // checkout, its binding exists and its profile is declared. Only the
    // manifest is gone, and with it the claim that says whose records these
    // are.
    seedState(h, {
      approvals: [
        approvalRecord({
          profile: "deploy",
          projectId,
          root: identity.root,
          device: identity.device,
          inode: identity.inode,
          checkoutId: identity.checkoutId,
        }),
      ],
    });
    rmSync(join(checkout, ".ward", "project.json"));

    const status = await statusOf(h, checkout);
    expect(status.data.staleApprovals).toEqual([]);
    expect(status.data.otherProjectStaleApprovals).toBe(1);
    const text = await runWard(["status"], h.options(checkout));
    expect(text.stdout).toContain("stale approvals in other projects: 1");
    expect(text.stdout).not.toContain("ward profile approve deploy");
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
