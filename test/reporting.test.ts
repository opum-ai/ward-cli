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
import { realTpmHostRefusal } from "./support/no-real-tpm-host.ts";
import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  bindCheckoutIdentity,
  locateCheckout,
  probeCheckout,
} from "../src/adapters/checkout.ts";
import {
  keyRefusalState,
  selectKeyProvider,
  tpm2Diagnoser,
} from "../src/adapters/key-backend.ts";
import { TpmKeyError } from "../src/adapters/tpm2-provider.ts";
import {
  keyUnloadableHint,
  keyUnloadableSummary,
  Tpm2Error,
  type Tpm2Reason,
  tpm2ErrorCodes,
} from "../src/adapters/tpm2-tools.ts";
import {
  type KeyProvider,
  type KeyRefusalStateName,
  keyRefusalStateNames,
  type TpmDiagnoser,
} from "../src/application/key-provider.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createProjectFiles } from "../src/adapters/project-files.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type { RegistrationApprover } from "../src/application/approvals.ts";
import { wardBlockBody } from "../src/application/bridges.ts";
import {
  observeKey,
  runDoctor,
  tpmProbeReason,
  unknownRefusalReason,
  runStatus,
} from "../src/application/reporting.ts";
import type { VaultStore } from "../src/application/vault-store.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { errorCatalog, WardError } from "../src/contract/errors.ts";
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

// A host with no TPM and no tools, so doctor's probe is deterministic on any
// machine (the real /dev/tpmrm0 is never touched by a test).
const noTpmHost = { path: "", device: join(tmpdir(), "ward-no-such-tpmrm0") };

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
    // The harness's provider is the Keychain's, so the report is the macOS one
    // on every host (the Linux-only lines are tested with their own platform).
    keySelection: { platform: "darwin" },
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
  registerHint?: boolean;
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
      "tpm2",
      "secret_service",
    ]);
    // Every check passes but tpm2 and secret_service, which are skipped on
    // macOS (DEC-262 a25) and never a failure.
    expect(
      data.checks
        .filter((e) => e.check !== "secret_service" && e.check !== "tpm2")
        .every((entry) => entry.status === "pass"),
    ).toBe(true);
    expect(checkFor(data, "tpm2")).toMatchObject({
      status: "skipped",
      code: "not_applicable",
    });
    expect(checkFor(data, "secret_service")).toMatchObject({
      status: "skipped",
      code: "not_applicable",
    });
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
      expect(data.checks).toHaveLength(8);
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
    expect(doctor.data.checks).toHaveLength(8);
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

    // WCLI-140 (NIT-b): the whole remedy on a registered legacy record. The
    // doctor fails, the named `ward profile approve` replaces the record, and
    // the doctor then passes.
    test("is replaced by ward profile approve, after which the doctor passes", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-end-to-end");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const identity = locateCheckout(checkout);
      const projectId = declareProfile(checkout, "deploy");
      seedApprovals(h, [legacyRecord(projectId, identity)]);

      const before = await doctorOf(h, checkout);
      expect(before.result.exitCode).toBe(exitCodes.validation);
      expect(checkFor(before.data, "stale_approvals")).toMatchObject({
        status: "fail",
        code: "reapprove_required",
      });

      const approved = await runWard(
        ["profile", "approve", "deploy", "--json"],
        h.options(checkout, {
          profileApprover: { available: () => true, ask: () => "approved" },
        }),
      );
      expect(approved.exitCode).toBe(exitCodes.success);

      const after = await doctorOf(h, checkout);
      expect(after.result.exitCode).toBe(exitCodes.success);
      expect(checkFor(after.data, "stale_approvals")).toMatchObject({
        status: "pass",
        code: "current",
      });
    });

    // The unregistered cases: the record is untouched residue, so the doctor
    // passes and does not ask for a registration that would grant access
    // (DEC-255 a6). The hint is worded from the `registerHint` field and is not framed
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
          registerHint: true,
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
      // The probe only reads: the doctor must not have bound an identity.
      expect(existsSync(join(found.root, ".git", "ward"))).toBe(false);
    });

    // An empty real `ward` directory is not in init's way: it can create the
    // nonce file in it, so the register hint stands.
    test("is inert, with a hint, when its checkout has an empty ward directory", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-empty-ward");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const found = unregisteredSibling(projectId, true);
      mkdirSync(join(found.root, ".git", "ward"));
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
    // register (it throws checkout_identity_unavailable), so the doctor names
    // no register step there: the record reads as inert and unreachable, with
    // no registerHint.
    const expectInertUnregistrable = async (
      h: ReturnType<typeof harness>,
      checkout: string,
    ) => {
      const doctor = await doctorOf(h, checkout);
      expect(doctor.result.exitCode).toBe(exitCodes.success);
      const stale = checkFor(doctor.data, "stale_approvals");
      expect(stale).toMatchObject({ status: "pass", code: "inert" });
      const entry = stale.staleApprovals?.[0];
      expect(entry).toMatchObject({ clearable: false });
      expect(entry).not.toHaveProperty("registerHint");
      const text = await runWard(["doctor"], h.options(checkout));
      expect(text.stdout).not.toContain("ward init");
      expect(text.stdout).toContain("inert and unreachable");
    };
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
      await expectInertUnregistrable(h, checkout);
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
      await expectInertUnregistrable(h, checkout);
    });

    // A link where the `ward` directory belongs is one init refuses to write
    // through, so no register step is named.
    test("is inert when a link stands where the checkout's ward directory belongs", async () => {
      const h = harness();
      const checkout = worktree("doctor-legacy-ward-link");
      await h.setUp(checkout);
      await h.init(checkout, ["--claude"]);
      const projectId = declareProfile(checkout, "deploy");
      const found = unregisteredSibling(projectId, true);
      const elsewhere = siblingCheckout(false);
      symlinkSync(elsewhere, join(found.root, ".git", "ward"));
      seedState(h, { approvals: [legacyRecord(projectId, found)] });
      await expectInertUnregistrable(h, checkout);
    });

    // A git directory this account cannot write is one init cannot bind an
    // identity in (a root-owned .git after a sudo clone), though every other
    // part of it looks fine. As root the mode does not bind, so a root run
    // shows these three as skipped rather than passed.
    const asRoot = process.getuid?.() === 0;
    test.skipIf(asRoot)(
      "is inert when the checkout's git directory is not writable",
      async () => {
        const h = harness();
        const checkout = worktree("doctor-legacy-readonly-git");
        await h.setUp(checkout);
        await h.init(checkout, ["--claude"]);
        const projectId = declareProfile(checkout, "deploy");
        const found = unregisteredSibling(projectId, true);
        seedState(h, { approvals: [legacyRecord(projectId, found)] });
        chmodSync(join(found.root, ".git"), 0o555);
        try {
          await expectInertUnregistrable(h, checkout);
        } finally {
          chmodSync(join(found.root, ".git"), 0o755);
        }
      },
    );

    // When a real `ward` directory exists, the create writes into it, so it is
    // that directory's mode that decides, not the writable git directory
    // around it: removing the writesInto = ward directory choice reads the
    // writable .git instead and names a register step init cannot take.
    // 0o555 is not writable; 0o300 is writable and searchable but not
    // readable, and the bind opens the directory for reading first.
    for (const [mode, label] of [
      [0o555, "writable"],
      [0o300, "readable"],
    ] as const) {
      test.skipIf(asRoot)(
        `is inert when the checkout's ward directory is not ${label}`,
        async () => {
          const h = harness();
          const checkout = worktree(`doctor-legacy-ward-dir-${label}`);
          await h.setUp(checkout);
          await h.init(checkout, ["--claude"]);
          const projectId = declareProfile(checkout, "deploy");
          const found = unregisteredSibling(projectId, true);
          const ward = join(found.root, ".git", "ward");
          mkdirSync(ward);
          seedState(h, { approvals: [legacyRecord(projectId, found)] });
          chmodSync(ward, mode);
          try {
            await expectInertUnregistrable(h, checkout);
          } finally {
            chmodSync(ward, 0o755);
          }
        },
      );
    }

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

describe("a TPM-backed key provider answers status without throwing", () => {
  const tpmFailure = (reason: Tpm2Reason): KeyProvider => ({
    load: async () => {
      throw new TpmKeyError(tpm2ErrorCodes[reason], new Tpm2Error(reason));
    },
    create: async () => undefined,
  });

  async function statusWith(keyProvider: KeyProvider) {
    const h = harness();
    const checkout = worktree(`status-tpm-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const result = await runWard(
      ["status", "--json"],
      h.options(checkout, { keyProvider }),
    );
    return {
      result,
      data: json(result.stdout).data as StatusData,
    };
  }

  test("a lone private blob is never reported as a missing key", async () => {
    const { data } = await statusWith(tpmFailure("key_incomplete"));
    expect(data.keyProvider.status).not.toBe("missing");
    expect(data.keyProvider.status).toBe("unavailable");
  });

  test("a TPM refusal is reported as an unavailable key", async () => {
    for (const reason of [
      "tpm_not_accessible",
      "tool_untrusted",
      "tool_timeout",
      "session_not_encrypted",
    ] as const) {
      const { result, data } = await statusWith(tpmFailure(reason));
      expect(result.exitCode).toBe(exitCodes.success);
      expect(data.keyProvider.status).toBe("unavailable");
    }
  });

  test("every TPM code is reported as an unavailable key", async () => {
    for (const code of Object.values(tpm2ErrorCodes)) {
      const { result, data } = await statusWith({
        load: async () => {
          throw new WardError(code);
        },
        create: async () => undefined,
      });
      expect(result.exitCode).toBe(exitCodes.success);
      expect(data.keyProvider.status).toBe("unavailable");
    }
  });
});

// MUTANT REGISTER, slice 3d-2a, written BEFORE any run. Bun 1.3.14 recorded on each observation.
//   D1 observeKey has no vault_key_ambiguous case (falls through to the throw) -> "a vault two stores hold is ambiguous and names both", "status and doctor answer on an ambiguous vault instead of throwing"
//   D2 ambiguous is read as missing                                           -> the same two tests
//   D3 ambiguous drops its stores                                             -> "a vault two stores hold is ambiguous and names both"
//   D4 reportedKeyStatus passes "ambiguous" through to the report              -> "status and doctor answer on an ambiguous vault instead of throwing"
//   D5 observeKey never attaches the refusal                                  -> "a TPM refusal carries its doctor state...", "a load the tools rejected carries...", "a lone private blob keeps its own state..."
//   D6 a tpm_key_incomplete is read as a missing key                          -> "a lone private blob keeps its own state and is never missing", "a lone private blob is never reported as a missing key"
//   D7 keyRefusalState builds the state from a bare Tpm2Error(reason)         -> "a TPM refusal carries its doctor state...", "a load the tools rejected carries..."
//   D8 keyRefusalState answers for an error that is not a TpmKeyError         -> "without a classifier, or from a refusal that is not a TPM load, no state is attached"
//   D9 main.ts stops passing classifyKeyRefusal                               -> PREDICTED TO SURVIVE: nothing renders the refusal until the held ruling, so no runWard output can show it; wiring is pinned when the renderers land.
// OBSERVED (bun 1.3.14, 2026-11-17; predictions above unchanged). D1-D5, D7, D8 went red on exactly their predicted tests. D6 also reddened "every TPM code is reported as an unavailable key" and "without a classifier..." (the mutant hits every tpm_key_incomplete, which those two also load). D9 not run: predicted to survive.
describe("what observeKey carries (WCLI-21 slice 3d-2a)", () => {
  const failing = (error: unknown): KeyProvider => ({
    load: async () => {
      throw error;
    },
    create: async () => undefined,
  });
  const tpm = (reason: Tpm2Reason, detail?: string, path?: string) =>
    new TpmKeyError(
      tpm2ErrorCodes[reason],
      new Tpm2Error(reason, detail, path === undefined ? {} : { path }),
    );

  test("a vault two stores hold is ambiguous and names both", async () => {
    const stores = ["macOS Keychain", "TPM2"] as const;
    const observed = await observeKey(
      failing(
        new WardError("vault_key_ambiguous", undefined, undefined, [...stores]),
      ),
      "v",
    );
    expect(observed).toEqual({ status: "ambiguous", stores: [...stores] });
  });

  test("status and doctor answer on an ambiguous vault instead of throwing", async () => {
    const h = harness();
    const checkout = worktree(`ambiguous-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const keyProvider = failing(
      new WardError("vault_key_ambiguous", undefined, undefined, [
        "macOS Keychain",
        "TPM2",
      ]),
    );
    const status = await runWard(
      ["status", "--json"],
      h.options(checkout, { keyProvider }),
    );
    expect(status.exitCode).toBe(exitCodes.success);
    expect((json(status.stdout).data as StatusData).keyProvider.status).toBe(
      "unavailable",
    );
    const doctor = await runWard(
      ["doctor", "--json"],
      h.options(checkout, { keyProvider }),
    );
    // The WHOLE array and the exit code: every check that reads the key's
    // status renders it from one place, so a site that stopped doing so would
    // leak an unruled code here.
    expect(doctor.exitCode).toBe(exitCodes.validation);
    const checks = (json(doctor.stdout).data as DoctorData).checks.map((c) => [
      c.check,
      c.status,
      c.code,
    ]);
    expect(checks).toEqual([
      ["permissions", "pass", "private"],
      ["key_provider", "fail", "vault_key_ambiguous"],
      ["schema", "fail", "key_unavailable"],
      ["binding", "fail", "key_unavailable"],
      ["stale_approvals", "fail", "key_unavailable"],
      ["instructions", "skipped", "absent"],
      ["tpm2", "skipped", "not_applicable"],
      ["secret_service", "skipped", "not_applicable"],
    ]);
  });

  test("a TPM refusal carries its doctor state, never the WardError's text", async () => {
    const observed = await observeKey(
      failing(tpm("tool_untrusted", undefined, "/synthetic/tpm2_unseal")),
      "v",
      keyRefusalState,
    );
    // toEqual, so a refusal that also carried the error's message, or any
    // other key, fails: it is exactly the state, its code and the path.
    expect(observed).toEqual({
      status: "unavailable",
      refusal: {
        state: "tool_untrusted",
        code: tpm2ErrorCodes.tool_untrusted,
        path: "/synthetic/tpm2_unseal",
      },
    });
  });

  test("a load the tools rejected carries the unchanged key_unloadable wording", async () => {
    const observed = await observeKey(
      failing(tpm("tool_failed", "tpm2_load")),
      "v",
      keyRefusalState,
    );
    expect(observed).toEqual({
      status: "unavailable",
      refusal: {
        state: "key_unloadable",
        code: tpm2ErrorCodes.tool_failed,
        summary: keyUnloadableSummary,
        hint: keyUnloadableHint,
      },
    });
  });

  test("a lone private blob keeps its own state and is never missing", async () => {
    const observed = await observeKey(
      failing(tpm("key_incomplete")),
      "v",
      keyRefusalState,
    );
    expect(observed).toEqual({
      status: "unavailable",
      refusal: {
        state: "key_incomplete",
        code: tpm2ErrorCodes.key_incomplete,
      },
    });
  });

  test("without a classifier, or from a refusal that is not a TPM load, no state is attached", async () => {
    expect(await observeKey(failing(tpm("key_incomplete")), "v")).toEqual({
      status: "unavailable",
    });
    expect(
      await observeKey(
        failing(new WardError(tpm2ErrorCodes.tpm_not_accessible)),
        "v",
        keyRefusalState,
      ),
    ).toEqual({ status: "unavailable" });
  });

  test("a classifier that throws fails closed to a plain unavailable key", async () => {
    expect(
      await observeKey(failing(tpm("key_incomplete")), "v", () => {
        throw new Error("synthetic classifier fault");
      }),
    ).toEqual({ status: "unavailable" });
  });

  test("an incompatible tool's version is carried", async () => {
    expect(
      await observeKey(
        failing(tpm("tool_incompatible", "tpm2-tools 5.6")),
        "v",
        keyRefusalState,
      ),
    ).toEqual({
      status: "unavailable",
      refusal: {
        state: "tool_incompatible",
        code: tpm2ErrorCodes.tool_incompatible,
        version: "5.6",
      },
    });
  });

  test("an unrecognised failure still throws", async () => {
    await expect(
      observeKey(failing(new Error("synthetic")), "v", keyRefusalState),
    ).rejects.toThrow("synthetic");
  });
});

// MUTANT REGISTER, slice 3d-2a(ii), written BEFORE any run. Bun 1.3.14 recorded on each observation.
//   E1  the router's backend() always answers where a new key would go        -> test/key-backend.test.ts "the holder of the key is the backend in use..."
//   E2  two holders leave the settled store undefined (not null)               -> test/key-backend.test.ts "two holders leave no backend in use"
//   E3  load() does not reset the settled store first                          -> test/key-backend.test.ts "a later load does not inherit an earlier load's store"
//   E4  backendIn ignores the provider and answers by platform alone           -> "the backend field is always present..."
//   E5  the secret_service check is added on every platform                    -> "on macOS the backend is the keychain and nothing says Secret Service"
//   E6  notImplemented is added on every platform                              -> "on macOS the backend is the keychain..."
//   E7  key_incomplete is dropped from the codes reported under their own name -> "each of the five key states renders..."
//   E8  the ambiguous check drops its stores                                   -> "each of the five key states renders..."
//   E9  the human doctor output drops the path line                            -> "each of the five key states renders...", "a tool_untrusted state shows the word and the path..."
//   E10 refusedKeyCheck drops summary and hint                                 -> "each of the five key states renders..."
//   E11 the human status drops the Secret Service line                         -> "on Linux the Secret Service gap is named, reported and never failed"
//   E12 main.ts stops passing the platform to the report                       -> "on Linux the Secret Service gap...", "the backend field is always present..." (they run as linux on a darwin host)
//   E13 status stops carrying keyProvider.backend                              -> "the backend field is always present...", "the existing status and doctor fields are unchanged" is NOT predicted (it checks only the old keys)
// OBSERVED (bun 1.3.14, 2026-11-17; predictions above unchanged). E2-E4, E6-E11, E13 went red on exactly their predicted tests. Differences: E1 also reddened "two holders leave no backend in use" and "a later load does not inherit..." (an always-initialisation answer is wrong for both); E5 also reddened three existing doctor tests that assert the macOS check list ("a healthy checkout passes every check", "permissions: an insecure location fails...", "a stored approval from another build is named..."); E12 reddened only "on Linux the Secret Service gap...": the backend test did not go red because its injected provider answers backend() itself.
// MUTANT REGISTER, DEC-262 (a25) round, written BEFORE any run. Bun 1.3.14 recorded on each observation. (The E5/E6 test "on macOS the backend is the keychain and nothing says Secret Service" is renamed "... and status says nothing of Secret Service" under (a25), which puts the check on every platform.)
//   F1  reason carries the state name instead of the fixed wording             -> "each of the five key states renders in JSON and in human output"
//   F2  summary and hint are added back as JSON keys                           -> "key_provider's JSON carries no summary or hint key..."
//   F3  version is carried by every state that has one                         -> "version is carried only by tool_incompatible" (only if a state besides tool_incompatible sets one; PREDICTED TO SURVIVE: the classifier sets version only for tool_incompatible)
//   F4  secret_service is dropped on macOS                                     -> "secret_service is the last check on every platform...", "on macOS the backend is the keychain...", "a healthy checkout passes every check and exits 0"
//   F5  secret_service sits before instructions, not last                      -> "secret_service is the last check on every platform...", "a healthy checkout passes every check and exits 0"
//   F6  secret_service says not_implemented on macOS                           -> "secret_service is the last check on every platform...", "on macOS the backend is the keychain...", "a healthy checkout passes every check and exits 0"
//   F7  the hint is dropped from the human doctor output                       -> "key_provider's JSON carries no summary or hint key, and the hint is human output only"
// OBSERVED (a25 round, bun 1.3.14, 2026-11-17; predictions above unchanged). F2, F5, F7 went red on exactly their predicted tests; F3 survived, as predicted. F1 also reddened the hint test (it reads the reason); F4 also reddened three existing doctor tests that list the checks; F6 also reddened "a healthy checkout passes every check and exits 0".
// MUTANT REGISTER, #347 review carry-in round, written BEFORE any run. Bun 1.3.14 on each observation. D9 above is now PINNED (see G5); it was "not run: predicted to survive" until rendering existed.
//   G1  the human doctor prints the path unescaped                             -> "a path and a version from the host are escaped before they are printed"
//   G2  the human doctor prints the version unescaped                          -> "a path and a version from the host are escaped before they are printed"
//   G3  the classifier call is not guarded                                     -> "a classifier that throws fails closed to a plain unavailable key"
//   G4  the ambiguous recovery hint is dropped from the human output           -> "an ambiguous vault shows its recovery hint in human output only"
//   G5  main.ts stops passing classifyKeyRefusal (D9)                          -> "each of the five key states renders in JSON and in human output" (key_incomplete, key_unloadable, tool_untrusted and tool_incompatible lose their codes)
//   G6  schemaCheck stops rendering the key status through reportedKeyStatus   -> "status and doctor answer on an ambiguous vault instead of throwing" (its whole-array assertion)
//   G7  the ambiguous check reports exit 0 (key check passes)                  -> "status and doctor answer on an ambiguous vault..." and "a broken key exits 6..."
// OBSERVED (carry-in round, bun 1.3.14, 2026-11-17; predictions above unchanged). G1-G4, G7 went red on their predicted tests (G7 also reddened the five-state test, since the ambiguous provider is one of the five). G5 reddened six tests, not only the predicted one: every test that reads a classified state goes with it, which is the D9 pin. G6 was run once per `key_${reportedKeyStatus(key)}` site (three exist in schemaCheck, bindingCheck and staleApprovalsCheck; keyCheck switches on it directly) and each site reddened exactly the ambiguous whole-array test.
// MUTANT REGISTER, #350 round-1 fixes, written BEFORE any run. Bun 1.3.14 on each observation. F3 (above) was predicted to survive and did; H4 is its kill.
//   H1  reason falls back to the bare state token (no catalog message)         -> "each of the five key states is exactly its check object...", "a TPM refusal outside the five stays unavailable and names its state"
//   H2  the recovery hint has no catalog fallback                              -> "each of the five key states is exactly its check object..." (key_incomplete, ambiguous), "a TPM refusal outside the five stays unavailable..."
//   H3  key_unloadable's summary constant is reworded                          -> "each of the five key states is exactly its check object..." (a literal, so the constant moving is caught)
//   H4  version is emitted for any state that carries one (F3)                 -> "version is carried only for tool_incompatible, whatever the classifier hands back"
//   H5  a platform that is neither macOS nor Linux falls to initialisation()   -> test/key-backend.test.ts "a platform that is neither macOS nor Linux reports none, with no vault"
//   H6  the key_provider check gains a `summary` key                           -> "each of the five key states is exactly its check object..."
// OBSERVED (#350 round-1 fixes, bun 1.3.14, 2026-11-17; predictions above unchanged). H1-H5 went red on exactly their predicted tests; F3 is now killed by H4's test. H6 also reddened "key_provider's JSON carries no summary or hint key..." and "a TPM refusal outside the five..." (both read the key set).
// DEC-262 (a24), slice 3d-2a(ii). Proofs carried here: each of the five
// key_provider codes renders in JSON and in human output; a broken key exits 6
// and is shown on key_provider; the backend field is always present, null on a
// Linux host with no TPM; the Secret Service line is on Linux and not on macOS;
// the existing fields are unchanged; the key_unloadable strings are unchanged.
// Proofs that belong to 3d-2b: the tpm2 attention check leaves doctor's exit at
// 0, and it never repeats a key fault.
describe("DEC-262 (a24): the key backend and the key states in status and doctor", () => {
  const tpm = (
    reason: Tpm2Reason,
    detail?: string,
    path?: string,
  ): KeyProvider => ({
    load: async () => {
      throw new TpmKeyError(
        tpm2ErrorCodes[reason],
        new Tpm2Error(reason, detail, path === undefined ? {} : { path }),
      );
    },
    create: async () => undefined,
    backend: () => "tpm2",
  });
  const ambiguous: KeyProvider = {
    load: async () => {
      throw new WardError("vault_key_ambiguous", undefined, undefined, [
        "macOS Keychain",
        "TPM2",
      ]);
    },
    create: async () => undefined,
    backend: () => null,
  };

  async function reports(keyProvider: KeyProvider, platform = "linux") {
    const h = harness();
    const checkout = worktree(`a24-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const options = h.options(checkout, {
      keyProvider,
      keySelection: { platform, tpm2Host: noTpmHost },
    });
    const status = await runWard(["status", "--json"], options);
    const statusText = await runWard(["status"], options);
    const doctor = await runWard(["doctor", "--json"], options);
    const doctorText = await runWard(["doctor"], options);
    return {
      status: json(status.stdout).data as StatusData & {
        keyProvider: { backend: unknown; notImplemented?: unknown };
      },
      statusText: statusText.stdout,
      doctor,
      doctorData: json(doctor.stdout).data as DoctorData,
      doctorText: doctorText.stdout,
    };
  }
  const keyCheck = (data: DoctorData) =>
    data.checks.find((c) => c.check === "key_provider") as
      | (DoctorData["checks"][number] & Record<string, unknown>)
      | undefined;

  // Each state's full key_provider check and its human hint, by LITERAL string,
  // so the public contract is pinned by the text and not by the constant that
  // produces it (DEC-262 a25). `toEqual` pins the key set: exactly
  // {check, status, code, reason, path?, stores?, version?}.
  const five: [
    string,
    KeyProvider,
    Record<string, unknown>,
    string | undefined,
  ][] = [
    [
      "key_incomplete",
      tpm("key_incomplete"),
      {
        check: "key_provider",
        status: "fail",
        code: "key_incomplete",
        reason:
          "A sealed vault key exists but its pair is incomplete, so Ward cannot load it. Ward did not change it.",
      },
      "Do not run `ward setup`: this is a recovery condition, and Ward will not create a new key over a sealed one.",
    ],
    [
      "key_unloadable",
      tpm("tool_failed", "tpm2_load"),
      {
        check: "key_provider",
        status: "fail",
        code: "key_unloadable",
        reason:
          "The sealed vault key could not be loaded. A TPM clear (tpm2_clear) is a likely cause, among others.",
      },
      "Do not run `ward setup`: the cause may be recoverable, and setup would destroy the only copy of the sealed key.",
    ],
    [
      "tool_untrusted",
      tpm("tool_untrusted", undefined, "/synthetic/tpm2_unseal"),
      {
        check: "key_provider",
        status: "fail",
        code: "tool_untrusted",
        reason:
          "A tpm2 tool is not in a location Ward trusts to receive the vault key, so Ward did not run it.",
        path: "/synthetic/tpm2_unseal",
      },
      undefined,
    ],
    [
      "tool_incompatible",
      tpm("tool_incompatible", "tpm2-tools 5.6"),
      {
        check: "key_provider",
        status: "fail",
        code: "tool_incompatible",
        reason:
          "A tpm2 tool printed something Ward does not recognise when it was asked whether the session encrypts the unsealed key, so Ward refused to unseal. This is a tool compatibility problem, not a report that encryption is off.",
        version: "5.6",
      },
      undefined,
    ],
    [
      "vault_key_ambiguous",
      ambiguous,
      {
        check: "key_provider",
        status: "fail",
        code: "vault_key_ambiguous",
        reason:
          "More than one credential store holds a key for this vault, so Ward will not pick one.",
        stores: ["macOS Keychain", "TPM2"],
      },
      "This is a recovery condition: Ward did not change either key and will not choose between them.",
    ],
  ];

  test("each of the five key states is exactly its check object in JSON, and its hint is in human output", async () => {
    for (const [name, provider, expected, hint] of five) {
      const r = await reports(provider);
      expect([name, keyCheck(r.doctorData) as unknown]).toEqual([
        name,
        expected,
      ]);
      // Human output carries the code, the reason, and every field the JSON does.
      expect(r.doctorText).toContain(String(expected.code));
      expect(r.doctorText).toContain(String(expected.reason));
      if (expected.path !== undefined)
        expect(r.doctorText).toContain(String(expected.path));
      if (expected.version !== undefined)
        expect(r.doctorText).toContain(String(expected.version));
      if (hint !== undefined) expect(r.doctorText).toContain(hint);
    }
  });

  test("key_provider's JSON carries no summary or hint key, and the hint is human output only", async () => {
    for (const [name, provider] of five) {
      const check = keyCheck((await reports(provider)).doctorData);
      expect([name, "summary" in (check ?? {})]).toEqual([name, false]);
      expect([name, "hint" in (check ?? {})]).toEqual([name, false]);
    }
    const unloadable = await reports(tpm("tool_failed", "tpm2_load"));
    expect(unloadable.doctorText).toContain(keyUnloadableSummary);
    expect(unloadable.doctorText).toContain(keyUnloadableHint);
    expect(JSON.stringify(unloadable.doctorData)).not.toContain(
      keyUnloadableHint,
    );
  });

  test("version is carried only by tool_incompatible", async () => {
    for (const [name, provider] of five) {
      const check = keyCheck((await reports(provider)).doctorData);
      expect([name, "version" in (check ?? {})]).toEqual([
        name,
        name === "tool_incompatible",
      ]);
    }
  });

  test("secret_service is the last check on every platform, skipped, never failed", async () => {
    const linux = await reports(tpm("key_incomplete"), "linux");
    const mac = await reports(
      createKeychainKeyProvider({
        service: SERVICE,
        entry: new MemoryKeychain().entry,
        timeoutMs: 2_000,
      }),
      "darwin",
    );
    for (const [r, code] of [
      [linux, "not_implemented"],
      [mac, "not_applicable"],
    ] as const) {
      const last = r.doctorData.checks.at(-1);
      expect(last).toMatchObject({
        check: "secret_service",
        status: "skipped",
        code,
      });
      // The fixed prefix: the six checks of ADR 0007, in order.
      expect(r.doctorData.checks.slice(0, 6).map((c) => c.check)).toEqual([
        "permissions",
        "key_provider",
        "schema",
        "binding",
        "stale_approvals",
        "instructions",
      ]);
    }
  });

  test("a tool_untrusted state shows the word and the path in human output and JSON", async () => {
    const r = await reports(
      tpm("tool_untrusted", undefined, "/synthetic/tpm2_unseal"),
    );
    expect(r.doctorText).toContain("untrusted");
    expect(r.doctorText).toContain("/synthetic/tpm2_unseal");
    expect(JSON.stringify(r.doctorData)).toContain("tool_untrusted");
    expect(JSON.stringify(r.doctorData)).toContain("/synthetic/tpm2_unseal");
  });

  test("version is carried only for tool_incompatible, whatever the classifier hands back", async () => {
    const h = harness();
    const checkout = worktree(`f3-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const identity = locateCheckout(checkout);
    const doctor = await runDoctor({
      checkout: identity,
      files: createProjectFiles(identity.root),
      store: h.store,
      keyProvider: tpm("tool_untrusted", undefined, "/synthetic/tpm2_unseal"),
      checkouts: { probe: probeCheckout },
      platform: "linux",
      classifyKeyRefusal: () => ({
        state: "tool_untrusted",
        code: tpm2ErrorCodes.tool_untrusted,
        path: "/synthetic/tpm2_unseal",
        version: "x",
      }),
    });
    const check = doctor.data.checks.find((c) => c.check === "key_provider");
    // Positive control: the classifier WAS read (the state's own code is
    // there), so the absence of `version` is the rule at work, not a no-op.
    expect(check?.code).toBe("tool_untrusted");
    expect(check ? "version" in check : true).toBe(false);
  });

  test("a code the catalog does not know fails closed to fixed prose, never a throw", async () => {
    const h = harness();
    const checkout = worktree(`nocatalog-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const identity = locateCheckout(checkout);
    const doctor = await runDoctor({
      checkout: identity,
      files: createProjectFiles(identity.root),
      store: h.store,
      keyProvider: tpm("tool_failed"),
      checkouts: { probe: probeCheckout },
      platform: "linux",
      classifyKeyRefusal: () => ({
        state: "access_refused",
        code: "tpm_not_in_the_catalog" as never,
      }),
    });
    const check = doctor.data.checks.find((c) => c.check === "key_provider");
    expect(check).toEqual({
      check: "key_provider",
      status: "fail",
      code: "unavailable",
      reason:
        "The credential store did not give the vault key, and Ward has no more specific wording for why.",
    });
    expect(doctor.exitCode).toBe(exitCodes.validation);
  });

  test("a path and a version from the host are escaped before they are printed", async () => {
    const hostile = "\u001b[31m/synthetic/tpm2_unseal\u0007";
    const untrusted = await reports(tpm("tool_untrusted", undefined, hostile));
    expect(untrusted.doctorText).not.toContain("\u001b");
    expect(untrusted.doctorText).not.toContain("\u0007");
    expect(untrusted.doctorText).toContain("/synthetic/tpm2_unseal");
    const incompatible = await reports(
      tpm("tool_incompatible", "tpm2-tools 5.6\u001b[31m"),
    );
    expect(incompatible.doctorText).not.toContain("\u001b");
    expect(incompatible.doctorText).toContain("5.6");
  });

  test("an ambiguous vault shows its recovery hint in human output only", async () => {
    const r = await reports(ambiguous);
    expect(r.doctorText).toContain("recovery condition");
    expect(JSON.stringify(r.doctorData)).not.toContain("recovery condition");
  });

  test("a broken key exits 6 and the failure is on key_provider", async () => {
    const r = await reports(tpm("key_incomplete"));
    expect(r.doctor.exitCode).toBe(exitCodes.validation);
    expect(keyCheck(r.doctorData)?.status).toBe("fail");
  });

  test("a TPM refusal outside the five stays unavailable and names its state", async () => {
    const r = await reports(tpm("tpm_not_accessible"));
    // Prose under the code `unavailable`, never a bare state token.
    expect(keyCheck(r.doctorData) as unknown).toEqual({
      check: "key_provider",
      status: "fail",
      code: "unavailable",
      reason:
        "The TPM2 device is present but this user cannot use it, so Ward did not touch it.",
    });
    expect(r.doctorText).toContain("Join the group that owns /dev/tpmrm0");
  });

  test("the backend field is always present: the held store, and null with no TPM", async () => {
    const held = await reports(tpm("key_incomplete"));
    expect(held.status.keyProvider.backend).toBe("tpm2");
    expect(held.statusText).toContain("key backend:   TPM2");
    const none = await reports(ambiguous);
    expect(none.status.keyProvider).toHaveProperty("backend", null);
    expect(none.statusText).toContain("key backend:   none");
    // A real selection on a Linux host with no TPM and no vault: nothing is
    // usable for a new key, so the backend is null and status still answers.
    const h = harness();
    const checkout = worktree(`a24-none-${++cases}`);
    const provider = selectKeyProvider(h.directory, {
      platform: "linux",
      tpm2: {
        detect: () => {
          throw new Tpm2Error("tpm_absent");
        },
      },
    });
    const result = await runWard(
      ["status", "--json"],
      h.options(checkout, {
        keyProvider: provider,
        keySelection: { platform: "linux" },
      }),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(
      (json(result.stdout).data as { keyProvider: { backend: unknown } })
        .keyProvider.backend,
    ).toBeNull();
  });

  test("on macOS the backend is the keychain and status says nothing of Secret Service", async () => {
    const r = await reports(
      createKeychainKeyProvider({
        service: SERVICE,
        entry: new MemoryKeychain().entry,
        timeoutMs: 2_000,
      }),
      "darwin",
    );
    expect(r.status.keyProvider.notImplemented).toBeUndefined();
    expect(r.statusText).not.toContain("Secret Service");
    // The check itself is on every platform, and says it does not apply here.
    expect(
      r.doctorData.checks.find((c) => c.check === "secret_service"),
    ).toMatchObject({ status: "skipped", code: "not_applicable" });
  });

  test("on Linux the Secret Service gap is named, reported and never failed", async () => {
    const r = await reports(tpm("key_incomplete"));
    expect(r.status.keyProvider.notImplemented).toEqual(["secret-service"]);
    expect(r.statusText).toContain("Secret Service: not implemented");
    const check = r.doctorData.checks.find((c) => c.check === "secret_service");
    expect(check).toMatchObject({ code: "not_implemented" });
    expect(check?.status).not.toBe("fail");
  });

  test("the existing status and doctor fields are unchanged", async () => {
    const r = await reports(tpm("key_incomplete"));
    expect(Object.keys(r.status).sort()).toEqual(
      [
        "binding",
        "checkout",
        "keyProvider",
        "manifest",
        "otherProjectStaleApprovals",
        "staleApprovals",
        "vault",
      ].sort(),
    );
    expect(r.status.keyProvider.status).toBe("unavailable");
    for (const name of [
      "permissions",
      "key_provider",
      "schema",
      "binding",
      "stale_approvals",
      "instructions",
      "tpm2",
      "secret_service",
    ])
      expect(r.doctorData.checks.map((c) => c.check)).toContain(name);
  });
});

// MUTANT REGISTER, slice 3d-2b(ii-a), written BEFORE any run. Bun 1.3.14 on each observation.
//   K1  a usable host is reported skipped, not pass/ok                       -> "a usable host is pass with the code ok"
//   K2  the tpm2 check is dropped off Linux                                  -> "doctor reports eight checks in the fixed order on Linux and on macOS", "on macOS tpm2 is skipped as not_applicable...", "a healthy checkout passes every check and exits 0"
//   K3  tpm2 is placed after secret_service                                  -> "doctor reports eight checks in the fixed order..."
//   K4  tool_untrusted is dropped from the host states                       -> "no usable TPM is skipped as tpm2_absent with prose naming which..."
//   K5  key_incomplete is added to the host states (a key fault repeated)    -> "a key fault is reported once, in key_provider, and tpm2 does not repeat it"
//   K6  a tool_failed state makes the tpm2 check a fail                      -> "tpm2 takes only pass or skipped, whatever state the probe names, and never fails doctor"
//   K7  a throwing probe is not caught                                       -> "a probe that throws fails closed to tpm2_absent..."
//   K8  tpm2Diagnoser drops the abandon sink                                 -> "the real diagnosis is called with the vault's blob directory and the command's abandon sink..."
//   K9  tpm2Diagnoser hands the ward directory instead of the vault's        -> the same test (its directory assertion)
//   K10 the probe is never given the vault id                                -> "the probe is asked for the vault, and for the host alone when there is no vault"
//   K11 the path of an untrusted tool is dropped from the skipped check      -> "no usable TPM is skipped as tpm2_absent with prose naming which..."
// OBSERVED (3d-2b ii-a, bun 1.3.14, 2026-11-17; predictions above unchanged). K3-K11 went red on their predicted tests. Differences: K1 also reddened "a key fault is reported once..." (it reads the pass/ok shape); K2, written as `return undefined`, crashed every doctor test, which is louder than predicted but includes all the predicted ones; K10 also reddened "the real diagnosis is called with the vault's blob directory...", which needs the vault id too. Carry 5 (#351): the unguarded-sink mutant I3 was re-run COMBINED with doctor now wired (tpm2-tools.test.ts + reporting.test.ts, 30 s timeout): it did not stall this time, one red (the throwing-sink test), 220 pass.
// MUTANT REGISTER, #352 round-1 fixes, written BEFORE any run. Bun 1.3.14 on each observation.
//   L1  the tpm2 reason is plain unknownRefusalReason, ignoring the catalog        -> "no usable TPM is skipped as tpm2_absent with prose naming which..." (exact catalog message per state)
//   L2  the tpm2 fallback is the KEY's unknownRefusalReason, not tpmProbeReason   -> "a state with no catalog wording falls to the TPM probe's own fixed prose...", "a probe that throws fails closed..."
//   L3  tpm2Diagnoser hands diagnoseTpm2 a bare {} host, not the seam              -> "the diagnoser honours the host seam on both paths..."
//   L4  the no-vault path ignores the detect seam                                  -> "the diagnoser honours the host seam on both paths..."
//   L5  the diagnosis directory is tpm/<wrong vault id> (right prefix)             -> "the real diagnosis is called with the vault's blob directory..." (exact join)
// OBSERVED (#352 round-1 fixes, bun 1.3.14, 2026-11-17; predictions above unchanged). L1-L5 went red on exactly their predicted tests (L1 also reddened the no-wording test, since it ignores the catalog for every state). L1 is the reviewer's mutant that survived before.
// MUTANT REGISTER, DEC-262 (a27) proofs, written BEFORE any run. Bun 1.3.14 on each observation. The proof uses tpm2_unseal, a REQUIRED tool, not tpm2_getcap: an untrusted getcap leaves the state `ready` (ii-b's attention case), so it could not make key_provider fail.
//   M1  tpm2 says ok for tool_untrusted (it is dropped from the host states)   -> "a host fault that also breaks the key fails once in key_provider, and tpm2 skips naming it..."
//   M2  tpm2 adds a savedSessions key on the no-vault path                     -> "with no vault the tpm2 check has no savedSessions key..."
//   M3  tpm2 repeats the host fault as a FAILURE (status fail)                 -> "a host fault that also breaks the key fails once..." (the tpm2 fail filter and the skipped shape)
// OBSERVED ((a27) proofs, bun 1.3.14, 2026-11-17; predictions above unchanged). M1-M3 went red on their predicted tests. Extras: M1 also reddened the no-usable-TPM test (it loses its tool_untrusted case); M3 also reddened that test and "tpm2 takes only pass or skipped..." (both read tpm2's status).
// DEC-262 (a25, a26), slice 3d-2b(ii-a). Proofs carried: doctor reports EIGHT
// checks in the fixed order on Linux and macOS; `tpm2` takes only pass or
// skipped, never a failure, whatever state the probe names; it is skipped with
// tpm2_absent (and prose naming which) when no TPM is usable, and
// not_applicable off Linux; a key fault is reported once, in key_provider, and
// not repeated in tpm2. The usable-TPM attention states (saved sessions, an
// untrusted getcap) are 3d-2b(ii-b).
describe("DEC-262 (a26): doctor's tpm2 check", () => {
  const healthy = () =>
    createKeychainKeyProvider({
      service: SERVICE,
      entry: new MemoryKeychain().entry,
      timeoutMs: 2_000,
    });
  async function doctorWith(
    diagnose: TpmDiagnoser | undefined,
    options: { platform?: string; provider?: KeyProvider } = {},
  ) {
    const h = harness();
    const checkout = worktree(`tpm2-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const result = await runWard(
      ["doctor", "--json"],
      h.options(checkout, {
        keyProvider: options.provider ?? h.keyProvider,
        keySelection: {
          platform: options.platform ?? "linux",
          tpm2Host: noTpmHost,
          ...(diagnose === undefined ? {} : { diagnose }),
        },
      }),
    );
    const text = await runWard(
      ["doctor"],
      h.options(checkout, {
        keyProvider: options.provider ?? h.keyProvider,
        keySelection: {
          platform: options.platform ?? "linux",
          tpm2Host: noTpmHost,
          ...(diagnose === undefined ? {} : { diagnose }),
        },
      }),
    );
    return {
      result,
      data: json(result.stdout).data as DoctorData & {
        checks: { reason?: string; path?: string }[];
      },
      text: text.stdout,
    };
  }
  const tpm2Of = (data: DoctorData) =>
    data.checks.find((c) => c.check === "tpm2");
  const ready: TpmDiagnoser = async () => ({ state: { state: "ready" } });
  const order = [
    "permissions",
    "key_provider",
    "schema",
    "binding",
    "stale_approvals",
    "instructions",
    "tpm2",
    "secret_service",
  ];

  test("doctor reports eight checks in the fixed order on Linux and on macOS", async () => {
    const linux = await doctorWith(ready);
    const mac = await doctorWith(undefined, { platform: "darwin" });
    for (const r of [linux, mac])
      expect(r.data.checks.map((c) => c.check)).toEqual(order);
  });

  test("on macOS tpm2 is skipped as not_applicable and the probe is never asked", async () => {
    let asked = 0;
    const r = await doctorWith(
      async () => {
        asked += 1;
        return { state: { state: "ready" } };
      },
      { platform: "darwin" },
    );
    expect(tpm2Of(r.data)).toEqual({
      check: "tpm2",
      status: "skipped",
      code: "not_applicable",
    });
    expect(asked).toBe(0);
  });

  test("a usable host is pass with the code ok", async () => {
    const r = await doctorWith(ready);
    expect(tpm2Of(r.data)).toEqual({
      check: "tpm2",
      status: "pass",
      code: "ok",
    });
    expect(r.result.exitCode).toBe(exitCodes.success);
  });

  test("tpm2 takes only pass or skipped, whatever state the probe names, and never fails doctor", async () => {
    // The whole union, from the one list the type is made from.
    const states = keyRefusalStateNames;
    for (const state of states) {
      const r = await doctorWith(async () => ({ state: { state } }));
      const check = tpm2Of(r.data);
      expect([
        state,
        check?.status === "pass" || check?.status === "skipped",
      ]).toEqual([state, true]);
      expect([state, r.result.exitCode]).toEqual([state, exitCodes.success]);
    }
  });

  test("no usable TPM is skipped as tpm2_absent with prose naming which, and the path for an untrusted tool", async () => {
    const cases: [KeyRefusalStateName, string, string | undefined][] = [
      ["unsupported", tpm2ErrorCodes.tpm_absent, undefined],
      ["access_refused", tpm2ErrorCodes.tpm_not_accessible, undefined],
      ["tools_absent", tpm2ErrorCodes.tools_absent, undefined],
      ["tpm_unusable", tpm2ErrorCodes.tpm_unusable, undefined],
      [
        "tool_untrusted",
        tpm2ErrorCodes.tool_untrusted,
        "/synthetic/tpm2_unseal",
      ],
      ["tool_incompatible", tpm2ErrorCodes.tool_incompatible, undefined],
    ];
    for (const [state, code, path] of cases) {
      const r = await doctorWith(async () => ({
        state: {
          state,
          code: code as never,
          ...(path === undefined ? {} : { path }),
        },
      }));
      const check = tpm2Of(r.data) as Record<string, unknown>;
      expect([state, check.status, check.code]).toEqual([
        state,
        "skipped",
        "tpm2_absent",
      ]);
      // The catalog's exact wording for the state's code, not any prose.
      expect([state, check.reason]).toEqual([
        state,
        errorCatalog[code as keyof typeof errorCatalog].message,
      ]);
      expect([state, check.path]).toEqual([state, path]);
      // Human output carries the reason, and the path when there is one.
      expect(r.text).toContain(String(check.reason));
      if (path !== undefined) expect(r.text).toContain(path);
    }
  });

  test("a key fault is reported once, in key_provider, and tpm2 does not repeat it", async () => {
    const provider: KeyProvider = {
      load: async () => {
        throw new TpmKeyError(
          tpm2ErrorCodes.key_incomplete,
          new Tpm2Error("key_incomplete"),
        );
      },
      create: async () => undefined,
      backend: () => "tpm2",
    };
    const r = await doctorWith(
      async () => ({ state: { state: "key_incomplete" } }),
      { provider },
    );
    expect(r.data.checks.find((c) => c.check === "key_provider")?.status).toBe(
      "fail",
    );
    expect(tpm2Of(r.data)).toEqual({
      check: "tpm2",
      status: "pass",
      code: "ok",
    });
    expect(r.result.exitCode).toBe(exitCodes.validation);
  });

  test("a probe that throws fails closed to tpm2_absent with fixed prose, never a doctor failure", async () => {
    const r = await doctorWith(async () => {
      throw new Error("synthetic probe fault");
    });
    expect(tpm2Of(r.data) as unknown).toEqual({
      check: "tpm2",
      status: "skipped",
      code: "tpm2_absent",
      reason: tpmProbeReason,
    });
    expect(r.result.exitCode).toBe(exitCodes.success);
  });

  test("the real diagnosis is called with the vault's blob directory and the command's abandon sink, so a timed-out tool makes doctor exit explicitly", async () => {
    const h = harness();
    const checkout = worktree(`tpm2-sink-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const seen: { directory: string }[] = [];
    const options = (abandon: boolean) =>
      h.options(checkout, {
        keySelection: {
          platform: "linux",
          diagnoseTpm2: async (_host, directory, opts) => {
            seen.push({ directory });
            if (abandon) opts?.onAbandon?.();
            return { state: { state: "ready" } };
          },
        },
      });
    const abandoned = await runWard(["doctor", "--json"], options(true));
    expect(abandoned.exitExplicitly).toBe(true);
    const calm = await runWard(["doctor", "--json"], options(false));
    expect(calm.exitExplicitly).toBeUndefined();
    expect(seen.length).toBe(2);
    const vaultId = h.store.header()?.vaultId as string;
    expect(typeof vaultId).toBe("string");
    for (const { directory } of seen)
      expect(directory).toBe(join(h.directory, "tpm", vaultId));
  });

  test("a state with no catalog wording falls to the TPM probe's own fixed prose, not the key's", async () => {
    const r = await doctorWith(async () => ({
      state: { state: "tools_absent" },
    }));
    expect((tpm2Of(r.data) as Record<string, unknown>).reason).toBe(
      tpmProbeReason,
    );
    expect(tpmProbeReason).not.toBe(unknownRefusalReason);
    expect(tpmProbeReason).not.toContain("vault key");
  });

  test("the diagnoser honours the host seam on both paths and the detect seam without a vault", async () => {
    const h = harness();
    const checkout = worktree(`tpm2-diag-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const vaultId = h.store.header()?.vaultId as string;
    const hosts: unknown[] = [];
    const seam = {
      platform: "linux",
      tpm2Host: noTpmHost,
      diagnoseTpm2: async (host: unknown) => {
        hosts.push(host);
        return { state: { state: "ready" as const } };
      },
    };
    const withVault = await tpm2Diagnoser(
      join(tmpdir(), "ward-x"),
      seam,
    )(vaultId);
    expect(withVault.state.state).toBe("ready");
    expect(hosts).toEqual([noTpmHost]);
    // No vault: the host alone. On the fake host nothing is usable.
    const bare = await tpm2Diagnoser(join(tmpdir(), "ward-x"), seam)(undefined);
    expect(bare.state.state).not.toBe("ready");
    // And the detect seam is honoured over the host.
    const viaDetect = await tpm2Diagnoser(join(tmpdir(), "ward-x"), {
      platform: "linux",
      tpm2: {
        detect: () => {
          throw new Tpm2Error("tpm_not_accessible");
        },
      },
    })(undefined);
    expect(viaDetect.state.state).toBe("access_refused");
  });

  // The #352 reviewer's item A (WCLI-21 3d-2b ii-b).
  test("with a vault, the detect seam is honoured and no tool runs against the host", async () => {
    const h = harness();
    const checkout = worktree(`tpm2-vdetect-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const vaultId = h.store.header()?.vaultId as string;
    let detected = 0;
    const diagnoser = tpm2Diagnoser(join(tmpdir(), "ward-x"), {
      platform: "linux",
      tpm2: {
        detect: () => {
          detected += 1;
          throw new Tpm2Error("tpm_not_accessible");
        },
      },
    });
    expect((await diagnoser(vaultId)).state.state).toBe("access_refused");
    expect(detected).toBe(1);
  });

  test("a test that reaches the real TPM host fails loudly, on the vault path and on detection alone", async () => {
    const h = harness();
    const checkout = worktree(`tpm2-real-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const vaultId = h.store.header()?.vaultId as string;
    const diagnoser = tpm2Diagnoser(join(tmpdir(), "ward-x"), {
      platform: "linux",
    });
    await expect(diagnoser(vaultId)).rejects.toThrow(realTpmHostRefusal);
    await expect(diagnoser(undefined)).rejects.toThrow(realTpmHostRefusal);
  });

  // DEC-262 (a27) proofs.
  test("a host fault that also breaks the key fails once in key_provider, and tpm2 skips naming it, with doctor at exit 6", async () => {
    const path = "/synthetic/tpm2_unseal";
    const provider: KeyProvider = {
      load: async () => {
        throw new TpmKeyError(
          tpm2ErrorCodes.tool_untrusted,
          new Tpm2Error("tool_untrusted", undefined, { path }),
        );
      },
      create: async () => undefined,
      backend: () => "tpm2",
    };
    const r = await doctorWith(
      async () => ({
        state: {
          state: "tool_untrusted",
          code: tpm2ErrorCodes.tool_untrusted,
          path,
        },
      }),
      { provider },
    );
    const key = r.data.checks.find((c) => c.check === "key_provider");
    expect(key).toMatchObject({
      status: "fail",
      code: "tool_untrusted",
      path,
    });
    expect(tpm2Of(r.data) as unknown).toEqual({
      check: "tpm2",
      status: "skipped",
      code: "tpm2_absent",
      reason: errorCatalog.tpm_tool_untrusted.message,
      path,
    });
    // Doctor fails exactly once for it: only key_provider is a failure among
    // the two, and the tpm2 check is never `ok` on an untrusted tool.
    expect(
      r.data.checks.filter((c) => c.status === "fail" && c.check === "tpm2"),
    ).toEqual([]);
    expect(r.result.exitCode).toBe(exitCodes.validation);
  });

  test("with no vault the tpm2 check has no savedSessions key, and with a vault and no count it has none either", async () => {
    const probe: TpmDiagnoser = async () => ({ state: { state: "ready" } });
    const h = harness();
    const bare = worktree(`tpm2-nosessions-${++cases}`);
    const noVault = await runWard(
      ["doctor", "--json"],
      h.options(bare, {
        keySelection: { platform: "linux", diagnose: probe },
      }),
    );
    const without = (json(noVault.stdout).data as DoctorData).checks.find(
      (c) => c.check === "tpm2",
    );
    expect(without).toEqual({ check: "tpm2", status: "pass", code: "ok" });
    expect("savedSessions" in (without ?? {})).toBe(false);
    const withVault = tpm2Of((await doctorWith(probe)).data);
    expect("savedSessions" in (withVault ?? {})).toBe(false);
  });

  // DEC-262 (a26 Q1/Q2, a27 Q1), WCLI-21 3d-2b ii-b.
  test("a visible saved-session count is pass/saved_sessions carrying its count, in JSON and human output, and never fails doctor", async () => {
    const r = await doctorWith(async () => ({
      state: { state: "ready" },
      savedSessions: { count: 2 },
    }));
    expect(tpm2Of(r.data) as unknown).toEqual({
      check: "tpm2",
      status: "pass",
      code: "saved_sessions",
      count: 2,
    });
    expect(r.text).toContain("saved_sessions");
    expect(r.text).toContain("saved sessions: 2");
    expect(r.result.exitCode).toBe(exitCodes.success);
  });

  test("an untrusted getcap stays pass/ok with savedSessions unavailable, its reason and its path, in JSON and human output", async () => {
    const path = "/synthetic/bin/tpm2_getcap";
    const r = await doctorWith(async () => ({
      state: { state: "ready" },
      savedSessions: { unavailable: "tool_untrusted", path },
    }));
    const check = tpm2Of(r.data) as unknown as Record<string, unknown>;
    expect(check).toMatchObject({
      check: "tpm2",
      status: "pass",
      code: "ok",
      path,
      savedSessions: "unavailable",
    });
    expect(check.reason).toContain("untrusted");
    expect(r.text).toContain(path);
    expect(r.text).toContain("untrusted");
    expect(r.text).toContain("saved sessions: unavailable");
    // The key is fine, so key_provider passes and doctor exits 0.
    expect(r.data.checks.find((c) => c.check === "key_provider")?.status).toBe(
      "pass",
    );
    expect(r.result.exitCode).toBe(exitCodes.success);
  });

  test("each unavailable reason has its own fixed wording and only an untrusted tool carries a path", async () => {
    const reasons = new Set<unknown>();
    for (const unavailable of [
      "tool_absent",
      "tool_untrusted",
      "tool_failed",
      "output_unrecognised",
    ] as const) {
      const r = await doctorWith(async () => ({
        state: { state: "ready" },
        savedSessions:
          unavailable === "tool_untrusted"
            ? { unavailable, path: "/synthetic/bin/tpm2_getcap" }
            : { unavailable },
      }));
      const check = tpm2Of(r.data) as unknown as Record<string, unknown>;
      expect(check.status).toBe("pass");
      expect(check.code).toBe("ok");
      expect("path" in check).toBe(unavailable === "tool_untrusted");
      reasons.add(check.reason);
    }
    expect(reasons.size).toBe(4);
  });

  test("savedSessions is absent with no vault and with a zero count, and present with a vault when the count is unavailable", async () => {
    const volunteered: TpmDiagnoser = async () => ({
      state: { state: "ready" },
      savedSessions: { count: 3 },
    });
    // No vault: a count the diagnoser volunteers is not reported (a27 Q1).
    const h = harness();
    const bare = worktree(`tpm2-novault-count-${++cases}`);
    const noVault = await runWard(
      ["doctor", "--json"],
      h.options(bare, {
        keySelection: { platform: "linux", diagnose: volunteered },
      }),
    );
    const without = (json(noVault.stdout).data as DoctorData).checks.find(
      (c) => c.check === "tpm2",
    );
    expect(without).toEqual({ check: "tpm2", status: "pass", code: "ok" });
    expect("savedSessions" in (without ?? {})).toBe(false);
    expect("count" in (without ?? {})).toBe(false);
    // A vault with an unreadable count carries the key.
    const withVault = tpm2Of(
      (
        await doctorWith(async () => ({
          state: { state: "ready" },
          savedSessions: { unavailable: "tool_failed" },
        }))
      ).data,
    );
    expect("savedSessions" in (withVault ?? {})).toBe(true);
    // A vault with a zero count (no key at all) does not.
    const zero = tpm2Of(
      (await doctorWith(async () => ({ state: { state: "ready" } }))).data,
    );
    expect("savedSessions" in (zero ?? {})).toBe(false);
  });

  test("a count of zero is just ok, with no count key", async () => {
    const r = await doctorWith(async () => ({
      state: { state: "ready" },
      savedSessions: { count: 0 },
    }));
    expect(tpm2Of(r.data) as unknown).toEqual({
      check: "tpm2",
      status: "pass",
      code: "ok",
    });
  });

  test("the diagnoser hands the vault's saved-session answer to the check and none without a vault", async () => {
    const h = harness();
    const checkout = worktree(`tpm2-sessions-${++cases}`);
    await h.setUp(checkout);
    await h.init(checkout);
    const vaultId = h.store.header()?.vaultId as string;
    const diagnoser = tpm2Diagnoser(join(tmpdir(), "ward-x"), {
      platform: "linux",
      tpm2Host: noTpmHost,
      diagnoseTpm2: async () => ({
        state: { state: "ready" as const },
        savedSessions: { count: 1, clearedBy: "reset or reboot" as const },
      }),
    });
    expect((await diagnoser(vaultId)).savedSessions).toMatchObject({
      count: 1,
    });
    const bare = await diagnoser(undefined);
    expect("savedSessions" in bare).toBe(false);
  });

  test("the probe is asked for the vault, and for the host alone when there is no vault", async () => {
    const asked: (string | undefined)[] = [];
    const probe: TpmDiagnoser = async (vaultId) => {
      asked.push(vaultId);
      return { state: { state: "ready" } };
    };
    await doctorWith(probe);
    const h = harness();
    const bare = worktree(`tpm2-novault-${++cases}`);
    await runWard(
      ["doctor", "--json"],
      h.options(bare, {
        keySelection: { platform: "linux", diagnose: probe },
      }),
    );
    // doctorWith runs the JSON and the human report: two asks for the vault.
    expect(asked.length).toBe(3);
    expect(asked.slice(0, 2).every((id) => typeof id === "string")).toBe(true);
    expect(asked[2]).toBeUndefined();
  });
});

// MUTANT REGISTER, WCLI-21 3d-2b ii-b FIRST COMMIT (the #352 reviewer's items A-C), written BEFORE any run. Bun 1.3.14 on each observation.
//   P1  tpm2Diagnoser's vault path ignores the detect seam again                 -> "with a vault, the detect seam is honoured and no tool runs against the host"
//   P2  the preload guard's diagnoseTpm2 wrapper stops refusing the real host     -> "a test that reaches the real TPM host fails loudly..." (vault path)
//   P3  the preload guard's detectTpm2 wrapper stops refusing the real host       -> the same test (detection-alone path)
// OBSERVED (3d-2b ii-b first commit, bun 1.3.14, 2026-11-17; predictions above unchanged). P1-P3 each went red on exactly their one predicted test and no other. A first guard draft recursed (the mocked module's live bindings), which hung the run; it now snapshots the real functions before mocking.

// MUTANT REGISTER, WCLI-21 3d-2b ii-b (DEC-262 a26 Q1/Q2, a27 Q1), written BEFORE any run. Bun 1.3.14 on each observation.
//   Q1  a visible count is reported as code ok, not saved_sessions                -> "a visible saved-session count is pass/saved_sessions carrying its count..."
//   Q2  the count key is dropped from the saved_sessions check                    -> the same test
//   Q3  the human output drops the count line                                     -> the same test (its text assertion)
//   Q4  an unavailable count drops the path of an untrusted getcap                -> "an untrusted getcap stays pass/ok with savedSessions unavailable, its reason and its path, in JSON and human output"
//   Q5  an unavailable count drops the savedSessions key                          -> the same test, and "savedSessions is absent with no vault and with a zero count, and present with a vault when the count is unavailable"
//   Q6  an unavailable count makes the check skipped                              -> the same untrusted test (status pass, doctor exit 0)
//   Q7  the no-vault gate is dropped (a count is reported without a vault)        -> "savedSessions is absent with no vault..."
//   Q8  a count of zero is reported as saved_sessions                             -> "a count of zero is just ok, with no count key"
//   Q9  every unavailable reason shares one wording                               -> "each unavailable reason has its own fixed wording and only an untrusted tool carries a path"
//   Q10 tpm2Diagnoser's vault path drops savedSessions from the diagnosis         -> "the diagnoser hands the vault's saved-session answer to the check and none without a vault"
// OBSERVED (3d-2b ii-b, bun 1.3.14, 2026-11-17; predictions above unchanged). Q1-Q10 each went red on their predicted tests. Extras beyond the prediction: Q4 and Q9 also reddened "each unavailable reason has its own fixed wording..." (Q4: the untrusted path; Q9: the shared wording) and Q9 also reddened the untrusted test (its reason must say untrusted); Q6 also reddened the reasons test (status pass).
