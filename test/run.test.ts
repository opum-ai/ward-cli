// WCLI-10: `ward run` (spec §9.2-§9.4, docs/adr/0003, gates T14, T17, T18).
//
// The spine is the ordering, and it is asserted as an ordering rather than
// as a shape: admission is written before the transport is called, and it is
// the transport that reads the vault to prove it. Everything else here
// follows from the same decision — that the approved snapshot is what runs,
// that the credential is bytes in exactly one header, and that a run whose
// admission cannot be recorded does not happen at all.
//
// T14 is measured where it can actually fail. The sentinel is a synthetic
// credential stored in a temporary vault; the transport is a fake, so the
// request it receives is readable; and the assertions then look for that
// value in the argument vector, the environment, every file the run wrote,
// the agent-facing output, and every field of every audit record. A failing
// assertion names a label rather than the value, so a failing run cannot
// itself disclose what it was testing.
//
// Some cases drive `runOperation` directly rather than through `runWard`,
// because the store is what has to fail in them and `runWard` builds its own
// from a directory. Those cases are the ones about audit writes failing; the
// rest go through the real command line.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
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
import { locateCheckout } from "../src/adapters/checkout.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createProjectFiles } from "../src/adapters/project-files.ts";
import {
  createSqliteVaultStore,
  vaultFileName,
} from "../src/adapters/sqlite-vault-store.ts";
import type { ProfileApprover } from "../src/application/approvals.ts";
import { type OperationOptions, runOperation } from "../src/application/run.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import type {
  Transport,
  TransportOutcome,
  TransportRequest,
} from "../src/application/transport.ts";
import type { VaultStore } from "../src/application/vault-store.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { encodeSecretValue } from "../src/domain/secret.ts";
import {
  type AuditRecord,
  parseVaultState,
  serializeVaultState,
  type VaultState,
  withSecret,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SENTINEL = "synthetic-bearer-6c1f4a";
const SENTINEL_BYTES = Buffer.from(SENTINEL);
const PROFILE = "example-profile";
const ALIAS = "example.token";
const HOST = "api.example.invalid";
const PATH = "/rate_limit";
// What this suite's runs observe as their machine identity. Supplied rather
// than read, so the records a case asserts on carry values the case chose and
// no test depends on the host it runs on. Both are distinct from HOST above,
// which is the destination: the destination must never appear in a record and
// the observed machine must, so a case that conflated them would pass for the
// wrong reason.
const MACHINE_USER = "run-suite-user";
const MACHINE_HOST = "run-suite-host";
// The labels a case asserts are recorded. Both satisfy the alias grammar.
const ACTOR_LABEL = "example-agent";
const TASK_LABEL = "example-task";
const DECLARATION: Record<string, unknown> = {
  adapter: "http",
  method: "GET",
  url: `https://${HOST}${PATH}`,
  auth: { type: "bearer", secret: ALIAS },
  headers: { Accept: "application/json" },
  requestBody: "none",
  output: "status",
};

// The semantic code a refusal carries, read from the CLI's error envelope.
const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

const encoder = new TextEncoder();
const root = mkdtempSync(join(tmpdir(), "ward-run-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

interface CapturedRequest {
  readonly request: TransportRequest;
  // The run zeroes the buffer it handed over, so a case that asserts the
  // value must read a copy, and the case that asserts the zeroing must hold
  // the original.
  readonly valueAtSend: string;
}

class FakeTransport implements Transport {
  readonly captured: CapturedRequest[] = [];
  outcome: TransportOutcome = { kind: "response", httpStatus: 200 };
  onSend: (() => void) | undefined;

  async send(request: TransportRequest): Promise<TransportOutcome> {
    this.captured.push({
      request,
      valueAtSend: Buffer.from(request.authorization.value).toString(),
    });
    const hook = this.onSend;
    this.onSend = undefined;
    hook?.();
    return this.outcome;
  }

  get count(): number {
    return this.captured.length;
  }
}

class FakeApprover implements ProfileApprover {
  available(): boolean {
    return true;
  }
  ask(): "approved" {
    return "approved";
  }
}

class FakeValues implements SecretValueSource {
  value = encoder.encode(SENTINEL);
  available(): boolean {
    return true;
  }
  readHidden(): Uint8Array {
    return this.value.slice();
  }
  readStdin(): Uint8Array {
    return this.value.slice();
  }
  confirmReplace(): boolean {
    return true;
  }
}

let cases = 0;

function harness() {
  const directory = join(mkdtempSync(join(root, `vault-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  // A short busy timeout: the T19 cases at the end of this file hold the
  // vault's write lock from a second connection to make the real store fail,
  // and a bounded wait is what keeps them quick. Nothing else here contends
  // for the lock, so the timeout cannot change any other answer.
  const sqlite = createSqliteVaultStore({ directory, busyTimeoutMs: 250 });
  const keyProvider = createKeychainKeyProvider({
    service: "opum.ward.run",
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const approver = new FakeApprover();
  const values = new FakeValues();
  const transport = new FakeTransport();
  const clock = "2026-09-29T00:00:00.000Z";
  let ids = 0;
  let writes = 0;
  const setFailWritesFrom = (value: number | undefined): void => {
    failWritesFrom = value;
  };
  // When set, the nth write onwards throws. Used to fail the admission write
  // and the completion write separately, which is how the two halves of
  // spec §9.4's persistence rule are measured rather than argued.
  let failWritesFrom: number | undefined;

  // Fire a rotation immediately before a chosen write. That is what a
  // concurrent `ward secret set` landing in a run's window looks like from
  // inside this process, and the window is the point: the run has already
  // read and decoded the credential by then, so the value it is about to
  // deliver is no longer the one the vault holds. The count is the same one
  // `failWritesFrom` uses, so a test names which write it means the same way.
  let rotateBeforeWrite: number | undefined;
  const rotateSecret = (): void => {
    sqlite.mutate(key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const existing = current.secrets.find((secret) => secret.alias === ALIAS);
      if (existing === undefined) throw new Error("no secret to rotate");
      return serializeVaultState(
        withSecret(current, {
          ...existing,
          value: encodeSecretValue(encoder.encode("rotated-value")),
          revision: existing.revision + 1,
        }),
      );
    });
  };

  // Fire an arbitrary vault change immediately before a chosen write, on the
  // same counter `rotateBefore` uses. The run has already read the binding by
  // then, so this is the race the admission transaction's re-check exists for
  // (WCLI-39): the state the write is about to act on is not the one the run
  // resolved its project from.
  let mutateBeforeWrite:
    | { write: number; change: (vaultState: VaultState) => VaultState }
    | undefined;
  const mutateVault = (
    change: (vaultState: VaultState) => VaultState,
  ): void => {
    sqlite.mutate(key(), (plaintext) =>
      serializeVaultState(change(parseVaultState(plaintext))),
    );
  };

  const controlled: VaultStore = {
    header: () => sqlite.header(),
    create: (vaultId, key, plaintext) => sqlite.create(vaultId, key, plaintext),
    read: (key) => sqlite.read(key),
    mutate: (key, change) => {
      writes++;
      if (rotateBeforeWrite !== undefined && writes === rotateBeforeWrite) {
        rotateBeforeWrite = undefined;
        rotateSecret();
      }
      if (
        mutateBeforeWrite !== undefined &&
        writes === mutateBeforeWrite.write
      ) {
        const hook = mutateBeforeWrite;
        mutateBeforeWrite = undefined;
        mutateVault(hook.change);
      }
      if (failWritesFrom !== undefined && writes >= failWritesFrom)
        throw new Error("the vault could not be written");
      return sqlite.mutate(key, change);
    },
  };

  const key = (): Uint8Array => {
    const stored = keychain.items.values().next().value as number[] | undefined;
    if (stored === undefined) throw new Error("no vault key is stored");
    return new Uint8Array(stored);
  };

  const state = (): VaultState => parseVaultState(sqlite.read(key()).plaintext);

  const options = (cwd: string): RunOptions => ({
    wardDirectory: directory,
    keyProvider,
    approver,
    profileApprover: approver,
    secrets: values,
    passphrases: {
      available: () => true,
      read: () => encoder.encode("run-test"),
    },
    cwd,
    now: () => new Date(clock),
    newId: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
    transport,
    machine: () => ({ user: MACHINE_USER, host: MACHINE_HOST }),
  });

  const ward = (cwd: string, args: string[]) => runWard(args, options(cwd));

  // The same operation, with the store the caller controls. Everything else
  // is identical to what `runWard` composes.
  const operate = (
    checkout: string,
    input: { actorLabel?: string; taskLabel?: string } = {},
  ): Promise<unknown> => {
    const identity = locateCheckout(checkout);
    const operation: OperationOptions = {
      checkout: identity,
      files: createProjectFiles(identity.root),
      store: controlled,
      keyProvider,
      transport,
      now: () => new Date(clock),
      newId: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
      observeMachine: () => ({ user: MACHINE_USER, host: MACHINE_HOST }),
    };
    return runOperation(
      {
        profile: PROFILE,
        actorLabel: input.actorLabel,
        taskLabel: input.taskLabel,
      },
      operation,
    );
  };

  function worktree(): string {
    const path = join(root, `repo-${++cases}`);
    mkdirSync(path);
    mkdirSync(join(path, ".git"));
    return path;
  }

  function writeDeclaration(
    checkout: string,
    name: string,
    value: Record<string, unknown>,
  ): void {
    const path = join(checkout, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(path, "utf8")) as {
      profiles?: Record<string, unknown>;
    };
    manifest.profiles = { ...(manifest.profiles ?? {}), [name]: value };
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  }

  // Read-modify-write against the manifest as it is, so a case changes the
  // one thing it is about and leaves the project's identity alone — a
  // manifest rewritten from scratch is a different failure than the one
  // these cases are measuring.
  function editDeclaration(
    checkout: string,
    name: string,
    change: (value: Record<string, unknown>) => void,
  ): void {
    const path = join(checkout, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(path, "utf8")) as {
      profiles: Record<string, Record<string, unknown>>;
    };
    const value = manifest.profiles[name];
    if (value === undefined) throw new Error(`no declaration for ${name}`);
    change(value);
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  }

  // A registered checkout with the credential stored and the profile
  // approved. Every case below starts here and changes one thing, so nothing
  // but that change can explain the answer.
  async function ready(
    declaration: Record<string, unknown> = { ...DECLARATION },
  ): Promise<string> {
    const checkout = worktree();
    expect((await ward(checkout, ["setup", "--json"])).exitCode).toBe(
      exitCodes.success,
    );
    expect((await ward(checkout, ["init", "--json"])).exitCode).toBe(
      exitCodes.success,
    );
    writeDeclaration(checkout, PROFILE, declaration);
    expect(
      (await ward(checkout, ["secret", "set", ALIAS, "--stdin", "--json"]))
        .exitCode,
    ).toBe(exitCodes.success);
    expect(
      (await ward(checkout, ["profile", "approve", PROFILE, "--json"]))
        .exitCode,
    ).toBe(exitCodes.success);
    return checkout;
  }

  return {
    directory,
    // The sealed header, so a case can assert the revision a failed write
    // did or did not move.
    header: () => sqlite.header(),
    ward,
    ready,
    state,
    operate,
    transport,
    values,
    editDeclaration,
    addDeclaration: (
      checkout: string,
      name: string,
      value: Record<string, unknown>,
    ) => writeDeclaration(checkout, name, value),
    failWritesFrom: setFailWritesFrom,
    rotateBefore: (write: number) => {
      rotateBeforeWrite = write;
    },
    mutateBefore: (
      write: number,
      change: (vaultState: VaultState) => VaultState,
    ) => {
      mutateBeforeWrite = { write, change };
    },
    keychain,
    worktree,
    writes: () => writes,
  };
}

const forRun = (state: VaultState, runId: string): AuditRecord[] =>
  state.auditRecords.filter((record) => record.runId === runId);

const runIdOf = (result: { stdout: string }): string =>
  String((JSON.parse(result.stdout).data as { runId: string }).runId);

describe("T14: the credential reaches only the approved header", () => {
  test("it is in one header and absent from argv, environment, files, output and audit", async () => {
    const h = harness();
    const checkout = await h.ready();
    const argv = ["run", PROFILE, "--json"];
    expect(argv.some((token) => token.includes(SENTINEL))).toBe(false);
    const result = await h.ward(checkout, argv);
    expect(result.exitCode).toBe(exitCodes.success);

    const sent = h.transport.captured[0];
    expect(sent?.request.authorization.name).toBe("Authorization");
    expect(sent?.valueAtSend).toBe(`Bearer ${SENTINEL}`);
    expect(sent?.request.url).toBe(`https://${HOST}${PATH}`);
    expect(sent?.request.method).toBe("GET");
    expect(sent?.request.headers).toEqual([
      { name: "Accept", value: "application/json" },
    ]);
    // Nowhere else in the request.
    expect(JSON.stringify(sent?.request.headers)).not.toContain(SENTINEL);
    expect(sent?.request.url).not.toContain(SENTINEL);

    expect(result.stdout).not.toContain(SENTINEL);
    expect(result.stderr).not.toContain(SENTINEL);
    expect(
      Object.values(process.env).some((entry) => entry?.includes(SENTINEL)),
    ).toBe(false);

    // Every file this run wrote, read back as bytes. The vault is encrypted,
    // so this is a real search rather than a formality.
    const written: Buffer[] = [];
    const walk = (path: string): void => {
      for (const entry of readdirSync(path, { withFileTypes: true })) {
        const child = join(path, entry.name);
        if (entry.isDirectory()) walk(child);
        else written.push(readFileSync(child));
      }
    };
    walk(h.directory);
    walk(checkout);
    expect(written.length).toBeGreaterThan(0);
    expect(written.some((bytes) => bytes.includes(SENTINEL_BYTES))).toBe(false);

    // Audit: every field of every record, as text. There is no field a value
    // could be written into, and this is the check that says so out loud.
    const records = forRun(h.state(), runIdOf(result));
    expect(records.map((record) => record.phase)).toEqual([
      "admission",
      "completion",
    ]);
    expect(JSON.stringify(records)).not.toContain(SENTINEL);
    expect(JSON.stringify(records)).not.toContain(ALIAS);
    expect(JSON.stringify(records)).not.toContain(HOST);
  });

  test("the buffer the run handed the transport is zeroed once it has answered", async () => {
    const h = harness();
    const checkout = await h.ready();
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    const held = h.transport.captured[0]?.request.authorization.value;
    expect(held).toBeDefined();
    expect(Array.from(held ?? []).every((byte) => byte === 0)).toBe(true);
  });

  test("a credential carrying a control byte is refused and nothing is sent", async () => {
    const h = harness();
    const checkout = await h.ready();
    // Stored over the clean value through the real command, so the poisoned
    // bytes are in the vault exactly as a developer could leave them.
    h.values.value = encoder.encode(`token\r\nX-Injected: yes`);
    expect(
      (await h.ward(checkout, ["secret", "set", ALIAS, "--stdin", "--json"]))
        .exitCode,
    ).toBe(exitCodes.success);
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({
      exit: exitCodes.validation,
      code: "run_credential_invalid",
    });
    expect(h.transport.count).toBe(0);
    expect(result.stdout).not.toContain("X-Injected");
    expect(result.stderr).not.toContain("X-Injected");
  });
});

describe("T18: the transport is not retried, and its outcome is reported safely", () => {
  test("an indeterminate outcome is reported as indeterminate, with exactly one request", async () => {
    const h = harness();
    const checkout = await h.ready();
    h.transport.outcome = { kind: "indeterminate", reason: "timeout" };
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    const data = JSON.parse(result.stdout).data as Record<string, unknown>;
    expect({
      outcome: data.outcome,
      httpStatus: "httpStatus" in data,
      exit: result.exitCode,
    }).toEqual({
      outcome: "indeterminate",
      httpStatus: false,
      exit: exitCodes.indeterminate,
    });
    expect(h.transport.count).toBe(1);
    expect(
      forRun(h.state(), runIdOf(result)).map((record) => [
        record.phase,
        record.outcome,
      ]),
    ).toEqual([
      ["admission", null],
      ["completion", "indeterminate"],
    ]);
  });

  test("a non-2xx status is reported as failed with the status, and asked once", async () => {
    const h = harness();
    const checkout = await h.ready();
    h.transport.outcome = { kind: "response", httpStatus: 401 };
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    const data = JSON.parse(result.stdout).data as Record<string, unknown>;
    expect({
      outcome: data.outcome,
      httpStatus: data.httpStatus,
      exit: result.exitCode,
    }).toEqual({
      outcome: "failed",
      httpStatus: 401,
      exit: exitCodes.validation,
    });
    expect(h.transport.count).toBe(1);
  });

  test("a refused destination is an error, and the run is still admitted and completed", async () => {
    const h = harness();
    const checkout = await h.ready();
    h.transport.outcome = {
      kind: "not-sent",
      reason: "destination-not-public",
    };
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
      asked: h.transport.count,
    }).toEqual({
      exit: exitCodes.denied,
      code: "run_destination_refused",
      asked: 1,
    });
    // Nothing was sent, but the attempt is part of the record: the pair of
    // events says a run was admitted and did not happen.
    expect(
      h.state().auditRecords.map((record) => [record.phase, record.outcome]),
    ).toEqual([
      ["admission", null],
      ["completion", "failed"],
    ]);
    expect(result.stdout).not.toContain(SENTINEL);
  });
});

describe("the approved snapshot is what runs", () => {
  test("a declaration changed after approval refuses the run before the transport", async () => {
    const h = harness();
    const checkout = await h.ready();
    h.editDeclaration(checkout, PROFILE, (value) => {
      value.url = `https://elsewhere.invalid${PATH}`;
    });
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({
      exit: exitCodes.denied,
      code: "profile_approval_stale",
    });
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });

  test("an unapproved profile is refused before the transport", async () => {
    const h = harness();
    const checkout = await h.ready();
    h.addDeclaration(checkout, "other", { ...DECLARATION });
    const result = await h.ward(checkout, ["run", "other", "--json"]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({
      exit: exitCodes.notFound,
      code: "profile_not_approved",
    });
    expect(h.transport.count).toBe(0);
  });

  test("an approved body policy this build cannot honour refuses the run", async () => {
    const h = harness();
    const checkout = await h.ready({
      ...DECLARATION,
      requestBody: "json-stdin",
    });
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({
      exit: exitCodes.validation,
      code: "run_body_unsupported",
    });
    expect(h.transport.count).toBe(0);
  });

  test("an approved profile whose credential is gone is refused before the transport", async () => {
    const h = harness();
    const checkout = await h.ready();
    expect(
      (await h.ward(checkout, ["secret", "delete", ALIAS, "--json"])).exitCode,
    ).toBe(exitCodes.success);
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({
      exit: exitCodes.notFound,
      code: "secret_not_found",
    });
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });

  test("a credential rotated between the read and the admission is refused before the transport", async () => {
    const h = harness();
    const checkout = await h.ready();
    // The next write is the admission, so rotating immediately before it puts
    // the change inside the window this run opened when it read and decoded
    // the credential — after that read, before the admission commits. The run
    // must not deliver a value the vault no longer holds, and it must not
    // leave an audit pair describing a state that never existed (WCLI-10
    // review, F2).
    h.rotateBefore(h.writes() + 1);
    const error = (await h.operate(checkout).catch((e: unknown) => e)) as {
      code?: string;
    };
    expect(error.code).toBe("secret_changed");
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });
});

// `ward run` resolves its project through the same binding rule `ward secret`,
// `ward profile` and `ward audit` apply (application/binding.ts). Before
// WCLI-39 consolidated that rule this file asserted neither of its codes, so
// each call site in run.ts is covered here rather than the extraction being
// assumed safe because the body it replaced looks identical.
describe("a run resolves its project through the binding rule", () => {
  test("a checkout with no manifest is refused before the vault or the credential store", async () => {
    const h = harness();
    // No vault at all: the answer is the registration refusal, not a
    // missing-vault error.
    const bare = h.worktree();
    const bareResult = await h.ward(bare, ["run", PROFILE, "--json"]);
    expect(bareResult.exitCode).toBe(exitCodes.denied);
    expect(errorCode(bareResult.stderr)).toBe("project_not_registered");
    expect(h.transport.count).toBe(0);

    // With a vault whose key is gone: still the registration refusal, and
    // still no credential-store read. This second half is the ordering one —
    // the WCLI-39 review measured that the case as first written pinned
    // neither, because a removal of the early manifest check left every test
    // green while these two states answer vault_not_found and vault_key_missing
    // instead (review F1).
    await h.ward(h.worktree(), ["setup", "--json"]);
    h.keychain.items.clear();
    const readsBefore = h.keychain.readAttempts;
    const keyless = h.worktree();
    const result = await h.ward(keyless, ["run", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("project_not_registered");
    expect(h.keychain.readAttempts).toBe(readsBefore);
    expect(h.transport.count).toBe(0);
  });

  test("a manifest without a binding is not registered", async () => {
    const h = harness();
    await h.ward(h.worktree(), ["setup", "--json"]);
    const prepared = h.worktree();
    expect(
      (await h.ward(prepared, ["init", "--no-register", "--json"])).exitCode,
    ).toBe(exitCodes.success);
    // The profile is declared, so the binding rule is the only thing that can
    // explain the refusal; `ward run` answers an unknown profile before it
    // resolves the binding.
    h.addDeclaration(prepared, PROFILE, { ...DECLARATION });
    const result = await h.ward(prepared, ["run", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("project_not_registered");
    expect(h.transport.count).toBe(0);
  });

  test("a manifest naming another project than the binding is a conflict", async () => {
    const h = harness();
    const checkout = await h.ready();
    // The declaration is kept, so the binding rule is the only thing that
    // can explain the refusal: the profile is still declared and approved.
    const path = join(checkout, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(path, "utf8")) as Record<
      string,
      unknown
    >;
    manifest.projectId = "8b0d1ff6-6f2f-4d5c-9c33-0f5a0f1c7d21";
    writeFileSync(path, `${JSON.stringify(manifest)}\n`);
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("binding_conflict");
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });
});

describe("the admission re-checks the binding it resolved", () => {
  test("a binding that vanished before the admission refuses the run", async () => {
    const h = harness();
    const checkout = await h.ready();
    // The next write is the admission, so the binding is gone by the time
    // that transaction re-reads the state the run resolved its project from.
    h.mutateBefore(h.writes() + 1, (current) => ({
      ...current,
      localBindings: [],
    }));
    const error = (await h.operate(checkout).catch((e: unknown) => e)) as {
      code?: string;
    };
    expect(error.code).toBe("project_not_registered");
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });

  test("a binding that changed project before the admission refuses the run", async () => {
    const h = harness();
    const checkout = await h.ready();
    h.mutateBefore(h.writes() + 1, (current) => ({
      ...current,
      localBindings: current.localBindings.map((binding) => ({
        ...binding,
        projectId: "8b0d1ff6-6f2f-4d5c-9c33-0f5a0f1c7d21",
      })),
    }));
    const error = (await h.operate(checkout).catch((e: unknown) => e)) as {
      code?: string;
    };
    expect(error.code).toBe("binding_conflict");
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });
});

describe("admission precedes delivery, and completion follows it", () => {
  test("the transport sees the admission already written at the moment it is called", async () => {
    const h = harness();
    const checkout = await h.ready();
    let seenAtSend: readonly AuditRecord[] = [];
    h.transport.onSend = () => {
      seenAtSend = h.state().auditRecords;
    };
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(seenAtSend.map((record) => record.phase)).toEqual(["admission"]);
    expect(seenAtSend[0]?.outcome).toBeNull();
    expect(h.state().auditRecords.map((record) => record.phase)).toEqual([
      "admission",
      "completion",
    ]);
  });

  test("a failing admission blocks delivery entirely", async () => {
    const h = harness();
    const checkout = await h.ready();
    h.failWritesFrom(h.writes() + 1);
    const result = await h.operate(checkout).catch((error: Error) => error);
    expect(result).toBeInstanceOf(Error);
    expect(h.transport.count).toBe(0);
    h.failWritesFrom(undefined);
    expect(h.state().auditRecords.length).toBe(0);
    expect(h.transport.count).toBe(0);
  });

  test("a failing completion is reported without claiming the run did not happen", async () => {
    const h = harness();
    const checkout = await h.ready();
    // The next write is the admission; the one after it is the completion.
    h.failWritesFrom(h.writes() + 2);
    const result = (await h.operate(checkout)) as {
      data: Record<string, unknown>;
      exitCode: number;
    };
    expect({
      outcome: result.data.outcome,
      httpStatus: result.data.httpStatus,
      auditRecorded: result.data.auditRecorded,
      exit: result.exitCode,
    }).toEqual({
      outcome: "succeeded",
      httpStatus: 200,
      auditRecorded: false,
      exit: exitCodes.validation,
    });
    // Delivered exactly once, and the admission is the only record written.
    expect(h.transport.count).toBe(1);
    expect(h.state().auditRecords.map((record) => record.phase)).toEqual([
      "admission",
    ]);
    h.failWritesFrom(undefined);
  });
});

// A second connection holding the vault's write lock, which is what a
// concurrent Ward process mid-write looks like to the store: the next write
// waits out its busy timeout and is refused rather than lost.
function holdVaultLock(directory: string): { release: () => void } {
  const db = new Database(join(directory, vaultFileName));
  db.exec("BEGIN IMMEDIATE");
  return {
    release: () => {
      db.exec("ROLLBACK");
      db.close();
    },
  };
}

describe("T19: audit persistence failures, measured at the vault", () => {
  // The cases above fail the store through the wrapper, before SQLite is
  // called at all — so what they observe is the run path's handling, not the
  // store's own failure. These drive the real store into failure instead, by
  // holding the vault's write lock from a second connection, and then read
  // the vault back: after a refused admission it is exactly where it was,
  // and after a refused completion it holds exactly the admission and no
  // more. The delivered-once counts are asserted here too, because a vault
  // read alone cannot say whether a credential left the process.
  test("a pre-delivery write the vault refuses blocks delivery and leaves the vault where it was", async () => {
    const h = harness();
    const checkout = await h.ready();
    const before = h.header();
    const lock = holdVaultLock(h.directory);
    let error: { code?: string };
    try {
      error = (await h.operate(checkout).catch((e: unknown) => e)) as {
        code?: string;
      };
    } finally {
      lock.release();
    }
    expect(error.code).toBe("vault_busy");
    // Nothing was delivered, and the vault holds neither an admission nor a
    // completion: the failed write rolled back whole, revision included.
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
    expect(h.header()?.revision).toBe(before?.revision);
  });

  test("a post-delivery write the vault refuses is reported, and the admission is all the vault holds", async () => {
    const h = harness();
    const checkout = await h.ready();
    const before = h.header();
    // Take the lock at the moment the credential leaves: the completion
    // write is the next thing the run does, and it is the one that fails.
    let lock: { release: () => void } | undefined;
    h.transport.onSend = () => {
      lock = holdVaultLock(h.directory);
    };
    try {
      const result = (await h.operate(checkout)) as {
        data: Record<string, unknown>;
        exitCode: number;
      };
      expect({
        outcome: result.data.outcome,
        httpStatus: result.data.httpStatus,
        auditRecorded: result.data.auditRecorded,
        exit: result.exitCode,
      }).toEqual({
        outcome: "succeeded",
        httpStatus: 200,
        auditRecorded: false,
        exit: exitCodes.validation,
      });
      expect(h.transport.count).toBe(1);
    } finally {
      lock?.release();
    }
    expect(h.state().auditRecords.map((record) => record.phase)).toEqual([
      "admission",
    ]);
    // The admission is the one write that landed, so the sealed revision
    // moved exactly once — a failed completion that still bumped it would be
    // the vault claiming a record it does not hold.
    expect(h.header()?.revision).toBe((before?.revision ?? 0) + 1);
  });
});

describe("WCLI-11: the audit field set a run records", () => {
  test("the observed machine and the asserted labels are on both events", async () => {
    const h = harness();
    const checkout = await h.ready();
    const result = await h.ward(checkout, [
      "run",
      PROFILE,
      "--actor-label",
      ACTOR_LABEL,
      "--task-label",
      TASK_LABEL,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.success);

    const records = forRun(h.state(), runIdOf(result));
    expect(records.map((record) => record.phase)).toEqual([
      "admission",
      "completion",
    ]);
    // Both events carry all three, and the admission — written before the
    // credential leaves — carries them too: a field set that only appeared on
    // the completion would be missing from the record that exists when the
    // run is interrupted.
    for (const record of records) {
      expect(record.machine).toEqual({
        user: MACHINE_USER,
        host: MACHINE_HOST,
      });
      expect(record.actorLabel).toBe(ACTOR_LABEL);
      expect(record.taskLabel).toBe(TASK_LABEL);
    }
  });

  test("a run given no labels records the absence rather than a value", async () => {
    const h = harness();
    const checkout = await h.ready();
    const result = await h.ward(checkout, ["run", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);

    const records = forRun(h.state(), runIdOf(result));
    expect(records.map((record) => record.actorLabel)).toEqual([null, null]);
    expect(records.map((record) => record.taskLabel)).toEqual([null, null]);
    // The positive control: the machine is still observed on both, so the two
    // nulls above are the caller asserting nothing rather than the run
    // recording nothing at all.
    expect(records.map((record) => record.machine)).toEqual([
      { user: MACHINE_USER, host: MACHINE_HOST },
      { user: MACHINE_USER, host: MACHINE_HOST },
    ]);
  });

  test("a label outside the alias grammar is refused before the vault is opened", async () => {
    const h = harness();
    const checkout = await h.ready();
    const readsBefore = h.keychain.readAttempts;

    const result = await h.ward(checkout, [
      "run",
      PROFILE,
      "--actor-label",
      "9not-a-label",
      "--json",
    ]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({ exit: exitCodes.usage, code: "run_label_invalid" });
    // Nothing was admitted, nothing was sent, and answering the argument
    // fault cost no credential-store read: a usage fault is answered before
    // the vault is opened, so it cannot raise a prompt on a locked keychain.
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
    expect(h.keychain.readAttempts).toBe(readsBefore);
    // The refusal names the grammar the label failed, not the label itself.
    expect(result.stderr).not.toContain("9not-a-label");
  });

  test("a task label outside the grammar is refused too, so the bound is not one flag's", async () => {
    const h = harness();
    const checkout = await h.ready();
    const result = await h.ward(checkout, [
      "run",
      PROFILE,
      "--task-label",
      "has spaces",
      "--json",
    ]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({ exit: exitCodes.usage, code: "run_label_invalid" });
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });

  test("a label is not authorization: a labelled run with no approval is still refused", async () => {
    const h = harness();
    const checkout = await h.ready();
    expect(
      (await h.ward(checkout, ["profile", "revoke", PROFILE, "--json"]))
        .exitCode,
    ).toBe(exitCodes.success);

    // The labels are the only thing this run adds. If anything downstream
    // read one as authority, this is the run where it would show.
    const result = await h.ward(checkout, [
      "run",
      PROFILE,
      "--actor-label",
      ACTOR_LABEL,
      "--task-label",
      TASK_LABEL,
      "--json",
    ]);
    expect({
      exit: result.exitCode,
      code: JSON.parse(result.stderr).code,
    }).toEqual({ exit: exitCodes.notFound, code: "profile_not_approved" });
    expect(h.transport.count).toBe(0);
    expect(h.state().auditRecords.length).toBe(0);
  });
});
