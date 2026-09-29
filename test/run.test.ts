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
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
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
const DECLARATION: Record<string, unknown> = {
  adapter: "http",
  method: "GET",
  url: `https://${HOST}${PATH}`,
  auth: { type: "bearer", secret: ALIAS },
  headers: { Accept: "application/json" },
  requestBody: "none",
  output: "status",
};

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
  const sqlite = createSqliteVaultStore({ directory });
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
  });

  const ward = (cwd: string, args: string[]) => runWard(args, options(cwd));

  // The same operation, with the store the caller controls. Everything else
  // is identical to what `runWard` composes.
  const operate = (checkout: string): Promise<unknown> => {
    const identity = locateCheckout(checkout);
    const operation: OperationOptions = {
      checkout: identity,
      files: createProjectFiles(identity.root),
      store: controlled,
      keyProvider,
      transport,
      now: () => new Date(clock),
      newId: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
    };
    return runOperation({ profile: PROFILE }, operation);
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
