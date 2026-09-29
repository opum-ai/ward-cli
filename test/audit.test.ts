// WCLI-11: `ward audit` (spec §8, §9.4).
//
// What these cases pin, beyond the happy path. First, scope: the report is
// the project the binding names and nothing else's records reach it. Second,
// the retention bound: it is stated, with the project's own retained count
// beside it, because the vault-wide bound alone would read as a guarantee
// about this project and the count alone would not be a bound. Third,
// refusal: a missing binding or vault is an error, not an empty list, since
// for this command "no events" and "no way to read events" would otherwise
// print the same answer.
//
// The second project seeded into these cases is the sentinel. In the same
// assertion block, this project's identifiers must appear and the other
// project's must not — the positive control is what makes the absence a
// reading rather than a silence.
//
// Every case runs against a temporary vault, an in-memory credential store
// and a throwaway checkout; nothing touches the developer's ~/.ward, real
// keychain or repositories.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type { RegistrationApprover } from "../src/application/approvals.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import {
  type AuditRecord,
  auditHistoryLimit,
  parseVaultState,
  serializeVaultState,
  withAuditRecord,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SERVICE = "opum.ward.audit";
const AT = "2026-09-29T00:00:00.000Z";

const root = mkdtempSync(join(tmpdir(), "ward-audit-"));
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
  const store = createSqliteVaultStore({ directory });

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

  // Appends events to the vault in the given order, through the same
  // appending rule the run path uses.
  const seed = (records: readonly AuditRecord[]): void => {
    store.mutate(key(), (plaintext) => {
      let state = parseVaultState(plaintext);
      for (const record of records) state = withAuditRecord(state, record);
      return serializeVaultState(state);
    });
  };

  return { directory, store, options, setUp, init, key, seed };
}

interface AuditData {
  projectId: string;
  events: AuditRecord[];
  retention: {
    bound: number;
    scope: string;
    eviction: string;
    retainedForProject: number;
  };
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

const auditOf = async (h: ReturnType<typeof harness>, cwd: string) => {
  const result = await runWard(["audit", "--json"], h.options(cwd));
  return { result, data: json(result.stdout).data as AuditData };
};

// One audit event. `over` names the fields a case is about; every other
// field is a fresh identifier, so two records cannot collide by accident.
function event(
  projectId: string,
  over: Partial<AuditRecord> = {},
): AuditRecord {
  return {
    id: randomUUID(),
    runId: randomUUID(),
    projectId,
    profile: "example-profile",
    secretId: randomUUID(),
    phase: "admission",
    outcome: null,
    at: AT,
    ...over,
  };
}

describe("ward audit", () => {
  test("reports this project's events, states the bound, and never reaches another project's records", async () => {
    const h = harness();
    const checkout = worktree("audit-happy");
    await h.setUp(checkout);
    const bound = json((await h.init(checkout)).stdout).data as {
      projectId: string;
    };

    const runId = randomUUID();
    const mine = [
      event(bound.projectId, { runId }),
      event(bound.projectId, {
        runId,
        phase: "completion",
        outcome: "succeeded",
      }),
    ];
    // A second project in the same vault, with a run of its own. Every value
    // here is a sentinel: none of it may reach the report.
    const otherProject = randomUUID();
    const otherRun = randomUUID();
    const other = [
      event(otherProject, { runId: otherRun, profile: "other-profile" }),
      event(otherProject, {
        runId: otherRun,
        profile: "other-profile",
        phase: "completion",
        outcome: "failed",
      }),
    ];
    h.seed([...mine, ...other]);

    const { result, data } = await auditOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stderr).toBe("");
    expect(json(result.stdout).schemaVersion).toBe(1);
    expect(json(result.stdout).kind).toBe("audit.report");
    expect(data.projectId).toBe(bound.projectId);
    // Oldest first, which is the order the vault stores them in.
    expect(data.events).toEqual(mine);
    expect(data.retention).toEqual({
      bound: auditHistoryLimit,
      scope: "vault",
      eviction: "oldest-first",
      retainedForProject: 2,
    });

    // Positive controls first: this project's identifiers are present, so the
    // absences below are a reading of the output rather than of nothing.
    expect(result.stdout).toContain(bound.projectId);
    for (const record of mine) {
      expect(result.stdout).toContain(record.runId);
      expect(result.stdout).toContain(record.secretId);
    }
    expect(result.stdout).not.toContain(otherProject);
    expect(result.stdout).not.toContain("other-profile");
    for (const record of other) {
      expect(result.stdout).not.toContain(record.runId);
      expect(result.stdout).not.toContain(record.secretId);
    }

    // The human form carries the same answer, including the bound in words
    // and the shared eviction rule that makes the count meaningful.
    const text = (await runWard(["audit"], h.options(checkout))).stdout;
    expect(text).toContain(bound.projectId);
    expect(text).toContain("retained here:  2");
    expect(text).toContain(`at most ${auditHistoryLimit} events in total`);
    expect(text).toContain("drops the oldest first");
    expect(text).toContain(mine[1]?.runId as string);
    expect(text).not.toContain(otherProject);
    expect(text).not.toContain("other-profile");
    expect(text).not.toContain(other[0]?.runId as string);
  });

  test("an empty history is a zero count, and the bound is still stated", async () => {
    const h = harness();
    const checkout = worktree("audit-empty");
    await h.setUp(checkout);
    await h.init(checkout);

    const { result, data } = await auditOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(data.events).toEqual([]);
    expect(data.retention.retainedForProject).toBe(0);
    expect(data.retention.bound).toBe(auditHistoryLimit);

    const text = (await runWard(["audit"], h.options(checkout))).stdout;
    expect(text).toContain("No events are retained for this project.");
    expect(text).toContain(`at most ${auditHistoryLimit} events in total`);
  });

  test("a project's retained count reflects events another project's activity pushed out", async () => {
    const h = harness();
    const checkout = worktree("audit-bounded");
    await h.setUp(checkout);
    const bound = json((await h.init(checkout)).stdout).data as {
      projectId: string;
    };

    // Three of this project's events first, then enough of the other
    // project's to take the collection past the bound: the oldest — this
    // project's — are the ones dropped. The count the report states has to be
    // the count that survived, not the number ever written.
    const mine = [
      event(bound.projectId),
      event(bound.projectId),
      event(bound.projectId),
    ];
    const otherProject = randomUUID();
    const other = Array.from({ length: auditHistoryLimit - 1 }, () =>
      event(otherProject, { profile: "other-profile" }),
    );
    h.seed([...mine, ...other]);

    const { result, data } = await auditOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(data.retention.retainedForProject).toBe(1);
    expect(data.events).toEqual([mine[2] as AuditRecord]);
    expect(result.stdout).not.toContain(otherProject);
    // The positive control for the eviction itself: the two events that were
    // dropped cannot be in the output, because nothing else holds them.
    expect(result.stdout).not.toContain(mine[0]?.id as string);
    expect(result.stdout).not.toContain(mine[1]?.id as string);
  });

  test("an unregistered checkout is refused, not reported as empty", async () => {
    const h = harness();
    const checkout = worktree("audit-unregistered");
    await h.setUp(checkout);
    await h.init(checkout, ["--no-register"]);

    const result = await runWard(["audit", "--json"], h.options(checkout));
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("project_not_registered");
    expect(result.stdout).toBe("");
  });

  test("a manifest and binding that disagree are a conflict, and neither project is named", async () => {
    const h = harness();
    const checkout = worktree("audit-conflict");
    await h.setUp(checkout);
    const bound = json((await h.init(checkout)).stdout).data as {
      projectId: string;
    };
    const mine = [event(bound.projectId)];
    h.seed(mine);

    // The manifest is replaced, so the checkout's claim and its binding
    // disagree: the state a report has to describe without naming either.
    const replacement = randomUUID();
    writeFileSync(
      join(checkout, ".ward", "project.json"),
      `${JSON.stringify({ schemaVersion: 1, projectId: replacement })}\n`,
    );

    const result = await runWard(["audit", "--json"], h.options(checkout));
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("binding_conflict");
    expect(result.stderr).not.toContain(bound.projectId);
    expect(result.stderr).not.toContain(replacement);
    expect(result.stderr).not.toContain(mine[0]?.runId as string);
  });

  test("a manifest without a vault is a refusal, not an empty report", async () => {
    const h = harness();
    const checkout = worktree("audit-no-vault");
    // --no-register writes the manifest without touching a vault, so this
    // checkout is registered nowhere and no vault exists behind it.
    expect((await h.init(checkout, ["--no-register"])).exitCode).toBe(
      exitCodes.success,
    );

    const result = await runWard(["audit", "--json"], h.options(checkout));
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(result.stderr)).toBe("vault_not_found");
  });

  test("outside a Git worktree it exits 3 without a report", async () => {
    const h = harness();
    const nowhere = join(root, `nowhere-${++cases}`);
    mkdirSync(nowhere);
    const result = await runWard(["audit", "--json"], h.options(nowhere));
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(result.stderr)).toBe("worktree_not_found");
    expect(result.stdout).toBe("");
  });

  test("it changes nothing", async () => {
    const h = harness();
    const checkout = worktree("audit-readonly");
    await h.setUp(checkout);
    const bound = json((await h.init(checkout)).stdout).data as {
      projectId: string;
    };
    h.seed([event(bound.projectId)]);
    const before = h.store.header()?.revision ?? 0;

    const { result, data } = await auditOf(h, checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(data.projectId).toBe(bound.projectId);
    // A read is not a write: the sealed revision is where it was.
    expect(h.store.header()?.revision).toBe(before);
  });
});
