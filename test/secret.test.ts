// WCLI-8: `ward secret set/list/inspect/delete` (spec §6.2, §8, §7.1).
//
// T08's shapes: hidden and stdin entry create and replace, list and inspect
// return metadata, and delete removes the record — with no value, length or
// fingerprint in any output. T09: a sentinel value, and a sentinel inside a
// rejected argument or a failed adapter, never appears in stdout or stderr.
// T11: every lookup is scoped to the bound project — a missing alias neither
// falls back to another project's record nor enumerates its inventory. The
// write transaction's re-checks get their own cases: a second writer moves
// the vault between the command's read and its write, and each write is
// refused rather than acting on a state it no longer describes.
//
// Every case runs against a temporary vault, a memory credential store and
// throwaway checkouts; nothing touches the developer's ~/.ward, real keychain
// or repositories. The byte readers are driven through the same descriptor
// seam the real adapter uses (a file stands in for the terminal), so entry
// semantics are asserted without a pty.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { locateCheckout } from "../src/adapters/checkout.ts";
import { createProjectFiles } from "../src/adapters/project-files.ts";
import {
  createTerminalSecretValues,
  type HiddenReadScratch,
  type StdinReadScratch,
  readHiddenValueBytes,
  readOnce,
  readStdinValueBytes,
  waitReadable,
} from "../src/adapters/secret-value.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type { RegistrationApprover } from "../src/application/approvals.ts";
import {
  runSecret,
  type SecretCommandInput,
  type SecretValueSource,
} from "../src/application/secrets.ts";
import type { VaultStore } from "../src/application/vault-store.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { inputQueued } from "../src/adapters/terminal-input.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import {
  decodeSecretValue,
  encodeSecretValue,
  secretLimits,
} from "../src/domain/secret.ts";
import {
  emptyVaultState,
  findSecret,
  parseVaultState,
  serializeVaultState,
  type VaultState,
  withSecret,
  withoutSecret,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SENTINEL = "sentinel-4f7c22a1-secret-value";
const SENTINEL_ALIAS = "Sentinel-4f7c22a1-Secret-Value";
const SENTINEL_BASE64 = Buffer.from(SENTINEL).toString("base64");

const encode = (text: string) => new TextEncoder().encode(text);
const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const projectId = (): string => randomUUID();

const root = mkdtempSync(join(tmpdir(), "ward-secret-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;

function worktree(): string {
  const directory = join(root, `repo-${++cases}`);
  mkdirSync(directory);
  mkdirSync(join(directory, ".git"));
  return directory;
}

class FakeApprover implements RegistrationApprover {
  available(): boolean {
    return true;
  }

  ask(): "approved" {
    return "approved";
  }
}

// The value source a case drives: what the hidden read returns, what stdin
// holds, whether a terminal exists, and how the replacement question is
// answered. It counts its calls, so a case can assert that a value was never
// read rather than only that the result was unchanged.
class FakeValues implements SecretValueSource {
  hidden: Uint8Array | undefined = encode(SENTINEL);
  stdin: Uint8Array = encode(SENTINEL);
  terminal = true;
  replaceAnswer = true;
  hiddenReads = 0;
  stdinReads = 0;
  confirmations = 0;

  available(): boolean {
    return this.terminal;
  }

  readHidden(): Uint8Array | undefined {
    this.hiddenReads += 1;
    return this.hidden?.slice();
  }

  readStdin(_maxBytes: number): Uint8Array {
    this.stdinReads += 1;
    return this.stdin.slice();
  }

  confirmReplace(): boolean {
    this.confirmations += 1;
    return this.replaceAnswer;
  }
}

function harness() {
  const directory = join(mkdtempSync(join(root, `vault-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const store = createSqliteVaultStore({ directory });
  const keyProvider = createKeychainKeyProvider({
    service: "opum.ward.secret",
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const values = new FakeValues();
  const approver = new FakeApprover();
  let clock = "2026-09-29T00:00:00.000Z";

  const key = (): Uint8Array => {
    const stored = keychain.items.values().next().value as number[] | undefined;
    if (stored === undefined) throw new Error("no vault key is stored");
    return new Uint8Array(stored);
  };

  const state = (): VaultState => parseVaultState(store.read(key()).plaintext);

  // A second writer, standing in for another Ward process: it mutates the
  // vault out of band, which is exactly what the in-transaction re-checks
  // exist for.
  const mutate = (change: (state: VaultState) => VaultState) =>
    store.mutate(key(), (plaintext) =>
      serializeVaultState(change(parseVaultState(plaintext))),
    );

  // The seam a race runs through: the hook fires once, after the command's
  // own read returns and before its write opens — the command proceeds on
  // the state it read, while the vault has already moved.
  let afterRead: (() => void) | undefined;
  const hooked: VaultStore = {
    header: () => store.header(),
    create: (vaultId, vaultKey, plaintext) =>
      store.create(vaultId, vaultKey, plaintext),
    read: (readKey) => {
      const snapshot = store.read(readKey);
      const hook = afterRead;
      afterRead = undefined;
      hook?.();
      return snapshot;
    },
    mutate: (mutateKey, change) => store.mutate(mutateKey, change),
  };

  const options = (
    cwd: string,
    extra: Partial<RunOptions> = {},
  ): RunOptions => ({
    wardDirectory: directory,
    keyProvider,
    approver,
    secrets: values,
    cwd,
    now: () => new Date(clock),
    ...extra,
  });

  const setUp = async (cwd: string) => {
    const result = await runWard(["setup", "--json"], options(cwd));
    expect(result.exitCode).toBe(exitCodes.success);
  };

  const init = async (cwd: string, args: string[] = []) =>
    await runWard(["init", ...args, "--json"], options(cwd));

  const secret = async (cwd: string, args: string[]) =>
    await runWard(["secret", ...args, "--json"], options(cwd));

  // The same command through its application entry point, over the wrapped
  // store: the only way to place a second writer's mutation between this
  // command's read and its write, which is the race the re-checks exist for.
  const race = async (cwd: string, input: SecretCommandInput) => {
    const checkout = locateCheckout(cwd);
    return await runSecret(input, {
      checkout,
      files: createProjectFiles(checkout.root),
      store: hooked,
      keyProvider,
      values,
      grants: { available: () => false, ask: () => "unavailable" },
      now: () => new Date(clock),
      newSecretId: () => randomUUID(),
      newGrantId: () => randomUUID(),
    });
  };

  // A checkout with a vault, registered for a project of its own.
  const registered = async () => {
    const checkout = worktree();
    await setUp(checkout);
    const result = await init(checkout);
    expect(result.exitCode).toBe(exitCodes.success);
    return checkout;
  };

  return {
    directory,
    values,
    options,
    setUp,
    init,
    secret,
    race,
    registered,
    state,
    mutate,
    beforeWrite: (hook: () => void) => {
      afterRead = hook;
    },
    setClock: (value: string) => {
      clock = value;
    },
  };
}

type Harness = ReturnType<typeof harness>;

const json = (output: string) =>
  JSON.parse(output) as { kind: string; data: Record<string, unknown> };
const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

// The semantic code a thrown WardError carries, for the adapter's own
// refusals and for the application entry point, neither of which reaches the
// envelope in-process.
const codeOf = (run: () => unknown): string | undefined => {
  try {
    run();
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
};

const thrownCode = async (
  run: () => Promise<unknown>,
): Promise<string | undefined> => {
  try {
    await run();
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
};

function storedSecret(h: Harness, alias: string) {
  return h.state().secrets.find((entry) => entry.alias === alias);
}

function discloses(result: { stdout: string; stderr: string }): boolean {
  return (
    result.stdout.includes(SENTINEL) ||
    result.stderr.includes(SENTINEL) ||
    result.stdout.includes(SENTINEL_BASE64) ||
    result.stderr.includes(SENTINEL_BASE64)
  );
}

describe("T08: entry, metadata and deletion", () => {
  test("hidden entry stores the value and returns metadata only", async () => {
    const h = harness();
    const checkout = await h.registered();

    const result = await h.secret(checkout, ["set", "example-alias"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stderr).toBe("");
    const envelope = json(result.stdout);
    expect(envelope.kind).toBe("secret.set");
    // The pinned key set is the disclosure guard: a value, a length or a
    // fingerprint would have to appear here as a field to leak.
    expect(Object.keys(envelope.data).sort()).toEqual([
      "alias",
      "createdAt",
      "id",
      "projectId",
      "revision",
      "status",
      "updatedAt",
    ]);
    expect(envelope.data.status).toBe("created");
    expect(discloses(result)).toBe(false);

    const record = storedSecret(h, "example-alias");
    expect(record).toBeDefined();
    if (record === undefined) return;
    expect(decode(decodeSecretValue(record.value) ?? new Uint8Array())).toBe(
      SENTINEL,
    );
    expect(envelope.data.id).toBe(record.id);
    expect(envelope.data.revision).toBe(1);
    expect(envelope.data.createdAt).toBe("2026-09-29T00:00:00.000Z");
  });

  test("stdin entry stores exact bytes, terminator included", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.values.stdin = encode(`${SENTINEL}\n`);

    const result = await h.secret(checkout, ["set", "piped-alias", "--stdin"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(h.values.stdinReads).toBe(1);
    expect(h.values.hiddenReads).toBe(0);

    const record = storedSecret(h, "piped-alias");
    if (record === undefined) throw new Error("no record");
    expect(decode(decodeSecretValue(record.value) ?? new Uint8Array())).toBe(
      `${SENTINEL}\n`,
    );
  });

  test("a replacement keeps the identity, asks first, and counts a revision", async () => {
    const h = harness();
    const checkout = await h.registered();
    const first = await h.secret(checkout, ["set", "example-alias"]);
    const firstId = json(first.stdout).data.id as string;

    h.setClock("2026-09-29T01:00:00.000Z");
    const second = await h.secret(checkout, ["set", "example-alias"]);
    expect(second.exitCode).toBe(exitCodes.success);
    expect(h.values.confirmations).toBe(1);
    const data = json(second.stdout).data;
    expect(data.status).toBe("replaced");
    expect(data.id).toBe(firstId);
    expect(data.createdAt).toBe("2026-09-29T00:00:00.000Z");
    expect(data.updatedAt).toBe("2026-09-29T01:00:00.000Z");
    expect(data.revision).toBe(2);
  });

  test("a declined replacement changes nothing and never reads the value", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.secret(checkout, ["set", "example-alias"]);
    h.values.replaceAnswer = false;
    h.values.hiddenReads = 0;

    const result = await h.secret(checkout, ["set", "example-alias"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(json(result.stdout).data.status).toBe("declined");
    expect(h.values.confirmations).toBe(1);
    // Asked before the value is read: a declined replacement costs no
    // typing and touches no state.
    expect(h.values.hiddenReads).toBe(0);
    expect(storedSecret(h, "example-alias")?.revision).toBe(1);
    expect(discloses(result)).toBe(false);
  });

  test("list is scoped to the project, sorted, and metadata only", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.secret(checkout, ["set", "zeta-alias"]);
    await h.secret(checkout, ["set", "alpha-alias"]);

    const result = await h.secret(checkout, ["list"]);
    expect(result.exitCode).toBe(exitCodes.success);
    const data = json(result.stdout).data;
    expect(Object.keys(data).sort()).toEqual(["projectId", "secrets"]);
    const listed = data.secrets as { alias: string; revision: number }[];
    expect(listed.map((entry) => entry.alias)).toEqual([
      "alpha-alias",
      "zeta-alias",
    ]);
    expect(Object.keys(listed[0] ?? {}).sort()).toEqual([
      "alias",
      "ownership",
      "revision",
      "updatedAt",
    ]);
    expect(discloses(result)).toBe(false);
  });

  test("an empty project lists nothing rather than another project", async () => {
    const h = harness();
    const checkout = await h.registered();
    const result = await h.secret(checkout, ["list"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(json(result.stdout).data.secrets).toEqual([]);
    // The human form says so in words, not as an empty list.
    const text = await runWard(["secret", "list"], h.options(checkout));
    expect(text.stdout).toContain("No secrets in this project.");
  });

  test("inspect returns metadata and ownership, never a value", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.secret(checkout, ["set", "example-alias"]);

    const result = await h.secret(checkout, ["inspect", "example-alias"]);
    expect(result.exitCode).toBe(exitCodes.success);
    const envelope = json(result.stdout);
    expect(envelope.kind).toBe("secret.inspect");
    expect(Object.keys(envelope.data).sort()).toEqual([
      "alias",
      "createdAt",
      "id",
      "ownership",
      "projectId",
      "revision",
      "updatedAt",
    ]);
    expect(envelope.data.ownership).toBe("owner");
    expect(discloses(result)).toBe(false);
  });

  test("delete removes the record, and a second delete is not found", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.secret(checkout, ["set", "example-alias"]);

    const deleted = await h.secret(checkout, ["delete", "example-alias"]);
    expect(deleted.exitCode).toBe(exitCodes.success);
    const envelope = json(deleted.stdout);
    expect(envelope.kind).toBe("secret.delete");
    expect(Object.keys(envelope.data).sort()).toEqual([
      "alias",
      "id",
      "projectId",
    ]);
    expect(storedSecret(h, "example-alias")).toBeUndefined();

    const again = await h.secret(checkout, ["delete", "example-alias"]);
    expect(again.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(again.stderr)).toBe("secret_not_found");
  });

  test("a later registration keeps the project's stored secrets", async () => {
    const h = harness();
    const first = await h.registered();
    await h.secret(first, ["set", "example-alias"]);

    // Registering a second checkout writes the state document; the records
    // the first project holds must survive that write.
    const second = worktree();
    expect((await h.init(second)).exitCode).toBe(exitCodes.success);
    const listed = await h.secret(first, ["list"]);
    expect(json(listed.stdout).data.secrets).toHaveLength(1);
  });
});

describe("the alias grammar and value bounds", () => {
  test("the grammar is the spec's, and a refusal never echoes the alias", async () => {
    const h = harness();
    const checkout = await h.registered();
    const accepted = ["a", "A.b-c_d9", "a".concat("b".repeat(63))];
    for (const alias of accepted) {
      const result = await h.secret(checkout, ["set", alias]);
      expect(result.exitCode).toBe(exitCodes.success);
    }
    const refused = ["9abc", `a${"b".repeat(64)}`, "a b", "a/b", ""];
    for (const alias of refused) {
      const result = await h.secret(checkout, ["set", alias]);
      expect(result.exitCode).toBe(exitCodes.usage);
      expect(errorCode(result.stderr)).toBe("secret_alias_invalid");
      expect(result.stdout).toBe("");
    }
  });

  test("the value bound is 64 KiB and it fails rather than truncates", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.values.stdin = new Uint8Array(secretLimits.maxValueBytes).fill(0x61);
    const atBound = await h.secret(checkout, ["set", "big-alias", "--stdin"]);
    expect(atBound.exitCode).toBe(exitCodes.success);
    const record = storedSecret(h, "big-alias");
    expect(decodeSecretValue(record?.value ?? "")?.length).toBe(
      secretLimits.maxValueBytes,
    );

    h.values.stdin = new Uint8Array(secretLimits.maxValueBytes + 1).fill(0x62);
    const over = await h.secret(checkout, ["set", "over-alias", "--stdin"]);
    expect(over.exitCode).toBe(exitCodes.validation);
    expect(errorCode(over.stderr)).toBe("secret_value_too_large");
    expect(storedSecret(h, "over-alias")).toBeUndefined();

    // The hidden path refuses too: the real reader refuses one byte past the
    // bound itself, and a source that did not would still be refused here.
    h.values.hidden = new Uint8Array(secretLimits.maxValueBytes + 1).fill(0x63);
    const hiddenOver = await h.secret(checkout, ["set", "hidden-over"]);
    expect(hiddenOver.exitCode).toBe(exitCodes.validation);
    expect(errorCode(hiddenOver.stderr)).toBe("secret_value_too_large");
    expect(storedSecret(h, "hidden-over")).toBeUndefined();
  });

  test("an empty or cancelled read is refused, and no value is stored", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.values.stdin = new Uint8Array(0);
    const empty = await h.secret(checkout, ["set", "empty-alias", "--stdin"]);
    expect(empty.exitCode).toBe(exitCodes.validation);
    expect(errorCode(empty.stderr)).toBe("secret_value_rejected");

    h.values.hidden = undefined; // a cancelled terminal read
    const cancelled = await h.secret(checkout, ["set", "cancel-alias"]);
    expect(cancelled.exitCode).toBe(exitCodes.validation);
    expect(errorCode(cancelled.stderr)).toBe("secret_value_rejected");
    expect(storedSecret(h, "empty-alias")).toBeUndefined();
    expect(storedSecret(h, "cancel-alias")).toBeUndefined();
  });

  test("without a terminal and without --stdin, entry is denied", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.values.terminal = false;
    const denied = await h.secret(checkout, ["set", "example-alias"]);
    expect(denied.exitCode).toBe(exitCodes.denied);
    expect(errorCode(denied.stderr)).toBe("secret_requires_terminal");
    expect(h.values.hiddenReads).toBe(0);

    // --stdin needs no terminal: the same checkout accepts a piped value.
    const piped = await h.secret(checkout, ["set", "example-alias", "--stdin"]);
    expect(piped.exitCode).toBe(exitCodes.success);
  });

  test("--stdin applies to set only, and only one alias is named", async () => {
    const h = harness();
    const checkout = await h.registered();
    for (const args of [
      ["list", "--stdin"],
      ["inspect", "example-alias", "--stdin"],
      ["delete", "example-alias", "--stdin"],
      ["list", "example-alias"],
      ["set"],
      ["set", "example-alias", "other-alias"],
      ["unknown-action", "example-alias"],
    ]) {
      const result = await h.secret(checkout, args);
      expect(result.exitCode).toBe(exitCodes.usage);
      expect(result.stdout).toBe("");
    }
  });

  test("a missing vault is its own answer, before any value is read", async () => {
    const h = harness();
    // A manifest but no vault: initialization prepared the files without
    // granting access.
    const checkout = worktree();
    expect((await h.init(checkout, ["--no-register"])).exitCode).toBe(
      exitCodes.success,
    );
    const result = await h.secret(checkout, ["set", "example-alias"]);
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(result.stderr)).toBe("vault_not_found");
    expect(h.values.hiddenReads).toBe(0);
  });
});

describe("T09: sentinels never reach output", () => {
  test("a rejected alias, action or extra argument is not echoed", async () => {
    const h = harness();
    const checkout = await h.registered();
    for (const args of [
      ["set", `9${SENTINEL_ALIAS}`],
      [SENTINEL_ALIAS, "example-alias"],
      ["set", "example-alias", SENTINEL_ALIAS],
      ["set", `--stdin=${SENTINEL}`],
    ]) {
      const result = await h.secret(checkout, args);
      expect(result.exitCode).toBe(exitCodes.usage);
      expect(result.stdout).not.toContain(SENTINEL_ALIAS);
      expect(result.stderr).not.toContain(SENTINEL_ALIAS);
      expect(discloses(result)).toBe(false);
    }
  });

  test("a missing alias is reported without naming it", async () => {
    const h = harness();
    const checkout = await h.registered();
    const result = await h.secret(checkout, ["inspect", SENTINEL_ALIAS]);
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(result.stderr)).toBe("secret_not_found");
    expect(result.stderr).not.toContain(SENTINEL_ALIAS);
    expect(discloses(result)).toBe(false);
  });

  test("an oversized value in the stream is never echoed", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.values.stdin = encode(
      SENTINEL.padEnd(secretLimits.maxValueBytes + 1, "x"),
    );
    const result = await h.secret(checkout, ["set", "big-alias", "--stdin"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(discloses(result)).toBe(false);
  });

  test("a source that throws reports as an internal error, not its message", async () => {
    const h = harness();
    const checkout = await h.registered();
    const result = await runWard(
      ["secret", "set", "example-alias", "--stdin", "--json"],
      h.options(checkout, {
        secrets: {
          available: () => false,
          readHidden: () => undefined,
          readStdin: () => {
            throw new Error(`upstream said ${SENTINEL}`);
          },
          confirmReplace: () => false,
        },
      }),
    );
    expect(result.exitCode).toBe(exitCodes.uncaught);
    expect(errorCode(result.stderr)).toBe("uncaught");
    expect(discloses(result)).toBe(false);
  });
});

describe("T11: a lookup is scoped to the bound project", () => {
  test("a missing alias neither falls back nor enumerates another project", async () => {
    const h = harness();
    const bound = await h.registered();
    const other = worktree();
    expect((await h.init(other)).exitCode).toBe(exitCodes.success);

    // The other project stores the alias under the same name.
    const stored = await h.secret(other, ["set", "shared-alias"]);
    expect(stored.exitCode).toBe(exitCodes.success);

    const inspected = await h.secret(bound, ["inspect", "shared-alias"]);
    expect(inspected.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(inspected.stderr)).toBe("secret_not_found");
    expect(inspected.stderr).not.toContain("shared-alias");

    const listed = await h.secret(bound, ["list"]);
    expect(json(listed.stdout).data.secrets).toEqual([]);

    const deleted = await h.secret(bound, ["delete", "shared-alias"]);
    expect(deleted.exitCode).toBe(exitCodes.notFound);

    // The other project's record is untouched by every refusal above.
    expect(storedSecret(h, "shared-alias")).toBeDefined();
    expect(h.state().secrets).toHaveLength(1);
  });

  test("a checkout without a manifest is refused before any value is read", async () => {
    const h = harness();
    await h.setUp(worktree());
    const bare = worktree();
    for (const args of [
      ["list"],
      ["inspect", "example-alias"],
      ["set", "example-alias"],
    ]) {
      const result = await h.secret(bare, args);
      expect(result.exitCode).toBe(exitCodes.denied);
      expect(errorCode(result.stderr)).toBe("project_not_registered");
    }
    expect(h.values.hiddenReads).toBe(0);
  });

  test("a manifest without a binding is not registered", async () => {
    const h = harness();
    await h.setUp(worktree());
    const prepared = worktree();
    expect((await h.init(prepared, ["--no-register"])).exitCode).toBe(
      exitCodes.success,
    );
    const result = await h.secret(prepared, ["list"]);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("project_not_registered");
  });

  test("a manifest naming another project than the binding is a conflict", async () => {
    const h = harness();
    const bound = await h.registered();
    const other = worktree();
    expect((await h.init(other)).exitCode).toBe(exitCodes.success);

    // The copied manifest is a valid document naming the other project.
    mkdirSync(join(bound, ".ward"), { recursive: true });
    writeFileSync(
      join(bound, ".ward", "project.json"),
      readFileSync(join(other, ".ward", "project.json")),
    );
    const result = await h.secret(bound, ["list"]);
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("binding_conflict");
  });
});

// The race the write transaction's re-checks exist for: another writer moves
// the vault between this command's read and its write. Each case fails the
// write and leaves the concurrent writer's state untouched.
describe("a write re-checks the decision it read", () => {
  test("a binding that vanished before the write refuses it", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.beforeWrite(() =>
      h.mutate((current) => ({ ...current, localBindings: [] })),
    );
    const code = await thrownCode(() =>
      h.race(checkout, {
        action: "set",
        alias: "example-alias",
        viaStdin: true,
      }),
    );
    expect(code).toBe("project_not_registered");
    expect(storedSecret(h, "example-alias")).toBeUndefined();
  });

  test("a binding that changed project before the write refuses it", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.secret(checkout, ["set", "example-alias"]);
    const other = projectId();
    h.beforeWrite(() =>
      h.mutate((current) => ({
        ...current,
        localBindings: current.localBindings.map((binding) => ({
          ...binding,
          projectId: other,
        })),
      })),
    );
    const code = await thrownCode(() =>
      h.race(checkout, {
        action: "delete",
        alias: "example-alias",
        viaStdin: false,
      }),
    );
    expect(code).toBe("binding_conflict");
    // The write rolled back: the concurrent writer's binding stands, and the
    // record it names is still there.
    expect(storedSecret(h, "example-alias")).toBeDefined();
    expect(h.state().localBindings[0]?.projectId).toBe(other);
  });

  test("a record deleted before the write is not deleted twice", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.secret(checkout, ["set", "example-alias"]);
    h.beforeWrite(() =>
      h.mutate((current) => ({
        ...current,
        secrets: current.secrets.filter(
          (record) => record.alias !== "example-alias",
        ),
      })),
    );
    const code = await thrownCode(() =>
      h.race(checkout, {
        action: "delete",
        alias: "example-alias",
        viaStdin: false,
      }),
    );
    expect(code).toBe("secret_not_found");
  });

  test("an alias created after the decision is not replaced unasked", async () => {
    const h = harness();
    const checkout = await h.registered();
    const boundProject = h.state().localBindings[0]?.projectId ?? "";
    h.beforeWrite(() =>
      h.mutate((current) =>
        withSecret(current, {
          id: projectId(),
          projectId: boundProject,
          alias: "example-alias",
          value: encodeSecretValue(encode("concurrent-writer-value")),
          createdAt: "2026-09-29T00:00:00.000Z",
          updatedAt: "2026-09-29T00:00:00.000Z",
          revision: 1,
        }),
      ),
    );
    // The interactive path, with no confirmation asked: the alias did not
    // exist when the question would have been asked.
    const code = await thrownCode(() =>
      h.race(checkout, {
        action: "set",
        alias: "example-alias",
        viaStdin: false,
      }),
    );
    expect(code).toBe("secret_changed");
    expect(h.values.confirmations).toBe(0);
    expect(storedSecret(h, "example-alias")?.value).toBe(
      encodeSecretValue(encode("concurrent-writer-value")),
    );
  });
});

describe("the secrets collection", () => {
  const record = (project: string, alias: string, revision = 1) => ({
    id: projectId(),
    projectId: project,
    alias,
    value: encodeSecretValue(encode(SENTINEL)),
    createdAt: "2026-09-29T00:00:00.000Z",
    updatedAt: "2026-09-29T00:00:00.000Z",
    revision,
  });

  test("replacing one project's alias leaves the other project's record", () => {
    const a = projectId();
    const b = projectId();
    const state = {
      ...emptyVaultState(),
      secrets: [record(a, "shared"), record(b, "shared")],
    };
    const replaced = withSecret(state, record(a, "shared", 2));
    expect(replaced.secrets).toHaveLength(2);
    expect(findSecret(replaced, a, "shared")?.revision).toBe(2);
    expect(findSecret(replaced, b, "shared")?.revision).toBe(1);
    const removed = withoutSecret(
      replaced,
      a,
      "shared",
      "2026-01-01T00:00:00.000Z",
    );
    expect(findSecret(removed, a, "shared")).toBeUndefined();
    expect(findSecret(removed, b, "shared")?.revision).toBe(1);
  });

  test("a lookup for another project's alias is a miss", () => {
    const a = projectId();
    const b = projectId();
    const state = { ...emptyVaultState(), secrets: [record(b, "only-b")] };
    expect(findSecret(state, a, "only-b")).toBeUndefined();
    expect(findSecret(state, b, "only-b")).toBeDefined();
  });
});

describe("the terminal value adapters", () => {
  const withInput = <T>(bytes: Uint8Array, run: (fd: number) => T): T => {
    const path = join(mkdtempSync(join(root, `input-${++cases}-`)), "bytes");
    writeFileSync(path, bytes);
    const descriptor = openSync(path, "r");
    try {
      return run(descriptor);
    } finally {
      closeSync(descriptor);
    }
  };

  test("hidden entry applies backspace, ends on the terminator, and Ctrl-C abandons", () => {
    expect(
      decode(
        withInput(encode("abc\u007f\u007fde\nrest"), readHiddenValueBytes),
      ),
    ).toBe("ade");
    expect(
      decode(withInput(encode("ab\u0003de\n"), readHiddenValueBytes)),
    ).toBe("");
    expect(decode(withInput(encode("kept\u0004"), readHiddenValueBytes))).toBe(
      "kept",
    );
    // Carriage return terminates too.
    expect(decode(withInput(encode("cr\r\n"), readHiddenValueBytes))).toBe(
      "cr",
    );
  });

  test("hidden entry refuses past the bound and accepts the exact bound", () => {
    const atBound = new Uint8Array(secretLimits.maxValueBytes).fill(0x61);
    const read = withInput(atBound, readHiddenValueBytes);
    expect(read.length).toBe(secretLimits.maxValueBytes);
    const over = new Uint8Array(secretLimits.maxValueBytes + 16).fill(0x61);
    expect(codeOf(() => withInput(over, readHiddenValueBytes))).toBe(
      "secret_value_too_large",
    );
  });

  test("a hidden read that refused the value stays a refusal, not an empty answer", () => {
    const over = new Uint8Array(secretLimits.maxValueBytes + 1).fill(0x61);
    const path = join(mkdtempSync(join(root, `input-${++cases}-`)), "bytes");
    writeFileSync(path, over);
    const descriptor = openSync(path, "r");
    try {
      const values = createTerminalSecretValues({
        isInteractive: () => true,
        setRaw: () => {},
        writePrompt: () => {},
        readHiddenBytes: () => readHiddenValueBytes(descriptor),
        flushInput: () => {},
      });
      // The adapter rethrows a reader's refusal and swallows only a terminal
      // failure; swallowing both would report a too-large value as empty.
      expect(codeOf(() => values.readHidden())).toBe("secret_value_too_large");
    } finally {
      closeSync(descriptor);
    }
  });

  test("hidden entry flushes queued input before echo returns on every path", () => {
    // A paste carries bytes past the newline the read stops on. They must not
    // survive the read: on success, on a refusal at the bound, and on Ctrl-C,
    // the queue is discarded before echo comes back.
    const events = (input: Uint8Array): string[] =>
      withInput(input, (fd) => {
        const order: string[] = [];
        const values = createTerminalSecretValues({
          isInteractive: () => true,
          setRaw: (on) => order.push(on ? "raw:on" : "raw:off"),
          readHiddenBytes: () => readHiddenValueBytes(fd),
          flushInput: () => order.push("flush"),
          writePrompt: () => {},
        });
        try {
          values.readHidden();
        } catch {
          // A refusal is an answer; only the exit ordering is asserted.
        }
        return order;
      });

    // Success: the paste's later lines are queued behind the terminator.
    expect(events(encode("value\nLEFTOVER-ONE\nLEFTOVER-TWO\n"))).toEqual([
      "raw:on",
      "flush",
      "raw:off",
    ]);
    // Refusal at the bound: bytes past the refused value are queued.
    const over = new Uint8Array(secretLimits.maxValueBytes + 8).fill(0x61);
    expect(events(over)).toEqual(["raw:on", "flush", "raw:off"]);
    // Ctrl-C: the read is abandoned with the rest of the paste still queued.
    expect(events(encode("half\u0003LEFTOVER\n"))).toEqual([
      "raw:on",
      "flush",
      "raw:off",
    ]);
  });

  // DEC-255 (a2) clause 3: a value that ended on its terminator with input still
  // queued behind it is a multi-line paste. It is refused, and what is queued
  // is drained and flushed before echo comes back.
  test("a multi-line paste into the hidden prompt is refused, then flushed before echo returns", () => {
    const run = (input: Uint8Array, inputPending: () => boolean) =>
      withInput(input, (fd) => {
        const order: string[] = [];
        const values = createTerminalSecretValues({
          isInteractive: () => true,
          setRaw: (on) => order.push(on ? "raw:on" : "raw:off"),
          readHiddenBytes: () => readHiddenValueBytes(fd),
          flushInput: () => order.push("flush"),
          inputPending,
          writePrompt: () => {},
        });
        let outcome: string;
        try {
          outcome = decode(values.readHidden() ?? new Uint8Array(0));
        } catch (error) {
          outcome = `refused:${(error as { code?: string }).code}`;
        }
        return { order, outcome };
      });

    const refused = run(encode("line-one\nline-two\n"), () => true);
    expect(refused.outcome).toBe("refused:secret_value_multiline");
    expect(refused.order).toEqual(["raw:on", "flush", "raw:off"]);

    // The accepting half: nothing queued, the same bytes are the value.
    const accepted = run(encode("line-one\n"), () => false);
    expect(accepted.outcome).toBe("line-one");
    expect(accepted.order).toEqual(["raw:on", "flush", "raw:off"]);

    // A queue probe that fails is not a refusal.
    const failed = run(encode("line-one\n"), () => {
      throw new Error("poll failed");
    });
    expect(failed.outcome).toBe("line-one");

    // An abandoned read is refused on its own terms, not as a paste.
    const abandoned = run(encode("half\u0003LEFTOVER\n"), () => true);
    expect(abandoned.outcome).toBe("");
  });

  // The probe looks once; the discard that follows keeps looking for up to
  // 1.5 s. A paste whose tail arrives between the two is flushed by the
  // discard, and that is itself the evidence it was a paste (WCLI-134, review
  // finding 1). The refusal follows the flush, still before echo returns, and
  // the first line is zeroed rather than stored.
  test("a tail that arrives after the probe, and is flushed by the discard, is still refused", () => {
    const first = encode("line-one");
    const order: string[] = [];
    const values = createTerminalSecretValues({
      isInteractive: () => true,
      setRaw: (on) => order.push(on ? "raw:on" : "raw:off"),
      readHiddenBytes: () => first,
      inputPending: () => false,
      flushInput: () => {
        order.push("flush");
        return true;
      },
      writePrompt: () => {},
    });
    expect(codeOf(() => values.readHidden())).toBe("secret_value_multiline");
    expect(order).toEqual(["raw:on", "flush", "raw:off"]);
    expect([...first].every((byte) => byte === 0)).toBe(true);
  });

  test("a discard that flushed nothing after the read leaves a one-line value accepted", () => {
    for (const flushed of [false, undefined, 1]) {
      const values = createTerminalSecretValues({
        isInteractive: () => true,
        setRaw: () => {},
        readHiddenBytes: () => encode("line-one"),
        inputPending: () => false,
        flushInput: () => flushed,
        writePrompt: () => {},
      });
      expect(decode(values.readHidden() ?? new Uint8Array(0))).toBe("line-one");
    }
  });

  test("a probe-detected paste zeroes the first line too", () => {
    const first = encode("line-one");
    const values = createTerminalSecretValues({
      isInteractive: () => true,
      setRaw: () => {},
      readHiddenBytes: () => first,
      inputPending: () => true,
      flushInput: () => false,
      writePrompt: () => {},
    });
    expect(codeOf(() => values.readHidden())).toBe("secret_value_multiline");
    expect([...first].every((byte) => byte === 0)).toBe(true);
  });

  // A value that ended on a carriage return is followed by its own line feed
  // when it came from a CRLF source: that is the terminator, not a second line
  // (WCLI-134, review finding 4).
  test("a CRLF terminator is one terminator, and any other byte after a return is a refused paste", () => {
    expect(decode(withInput(encode("token\r\n"), readHiddenValueBytes))).toBe(
      "token",
    );
    expect(decode(withInput(encode("token\r"), readHiddenValueBytes))).toBe(
      "token",
    );
    expect(
      codeOf(() => withInput(encode("token\rX"), readHiddenValueBytes)),
    ).toBe("secret_value_multiline");
    // The line feed alone is still just a terminator.
    expect(decode(withInput(encode("token\n"), readHiddenValueBytes))).toBe(
      "token",
    );
  });

  // WCLI-136 (opus follow-up to WCLI-134): the first line of a refused paste is
  // zeroed on every way out of the reader, the CR refusal and the too-large
  // refusal included, not only on the path that reaches setSecret's own zeroing.
  test("a refused read zeroes what it read, and so does a read that returns", () => {
    const run = (input: string, expected: string, peak: number) => {
      const scratch: HiddenReadScratch = {};
      let outcome: string | undefined;
      const code = codeOf(() => {
        outcome = decode(
          withInput(encode(input), (fd) => readHiddenValueBytes(fd, scratch)),
        );
      });
      if (code !== undefined) outcome = code;
      expect(outcome).toBe(expected);
      // An every() over an empty array is vacuously true, so the length the
      // read held is asserted on every case: zeroing nothing would pass it.
      expect(scratch.peak).toBe(peak);
      expect(scratch.held?.length).toBe(secretLimits.maxValueBytes);
      expect(scratch.held?.every((byte) => byte === 0)).toBe(true);
      expect(scratch.buffer && [...scratch.buffer]).toEqual([0]);
      expect(scratch.next && [...scratch.next]).toEqual([0]);
      return scratch;
    };
    // The CR refusal: the first line and the byte behind the return.
    run("s3cretLINE\rLEAK", "secret_value_multiline", "s3cretLINE".length);
    // The bound refusal.
    run(
      "a".repeat(secretLimits.maxValueBytes + 1),
      "secret_value_too_large",
      secretLimits.maxValueBytes,
    );
    // Accepted values and an abandoned read.
    run("token\r\n", "token", "token".length);
    run("ab\u0003", "", "ab".length);
    // The peak is what was held at most. The all-zero check above is met by
    // the final fill(0) whatever a backspace does, so it is not evidence that
    // a backspace zeroes its slot.
    run("abc\u007f\u007fd\n", "ad", 3);
  });

  test("a stdin read holds one buffer and zeroes it on every way out", () => {
    const run = (input: Uint8Array, max: number, expected: string) => {
      const scratch: StdinReadScratch = {};
      let outcome: string | undefined;
      const code = codeOf(() => {
        outcome = decode(
          withInput(input, (fd) => readStdinValueBytes(max, fd, scratch)),
        );
      });
      if (code !== undefined) outcome = code;
      expect(outcome).toBe(expected);
      // One allocation, sized to the bound and one byte more, however many
      // reads the stream takes: nothing else holds the bytes.
      expect(scratch.buffer?.length).toBe(max + 1);
      expect(scratch.buffer?.every((byte) => byte === 0)).toBe(true);
    };
    run(encode("s3cret-value"), 1024, "s3cret-value");
    run(encode("a".repeat(9)), 8, "secret_value_too_large");
  });

  test("a stdin read of one byte at a time still fills the one buffer", () => {
    const scratch: StdinReadScratch = {};
    const source = encode("slow-producer");
    let offset = 0;
    const targets: ArrayBufferLike[] = [];
    const out = readStdinValueBytes(64, 0, scratch, {
      read: (_descriptor, buffer) => {
        targets.push(buffer.buffer);
        if (offset >= source.length) return 0;
        buffer[0] = source[offset++] as number;
        return 1;
      },
    });
    expect(decode(out)).toBe("slow-producer");
    expect(scratch.buffer?.length).toBe(65);
    expect(scratch.buffer?.every((byte) => byte === 0)).toBe(true);
    // Every read, the final empty one included, was handed a view of the one
    // buffer: a second allocation would show as a different backing store.
    expect(targets.length).toBe(source.length + 1);
    expect(targets.every((target) => target === scratch.buffer?.buffer)).toBe(
      true,
    );
  });

  test("a stdin read over a real descriptor fed in two writes keeps both, at the right offsets", async () => {
    // The real readSync offset path: the second read lands in a view that
    // begins after the first read's bytes. The two writes are ordered by a
    // handshake, not by timing: the writer sends its second write only after
    // the reader's recording port has seen the first read return, so a read can
    // never take both. The FIFO is opened non-blocking, so a writer that never
    // starts fails the test at the deadline below instead of hanging the
    // process in openSync, and the writer's own wait is bounded too.
    const dir = mkdtempSync(join(root, `fifo-${++cases}-`));
    const fifo = join(dir, "pipe");
    const opened = join(dir, "writer-opened");
    const firstRead = join(dir, "first-read-done");
    expect(Bun.spawnSync(["mkfifo", fifo]).exitCode).toBe(0);
    const descriptor = openSync(
      fifo,
      fsConstants.O_RDONLY | fsConstants.O_NONBLOCK,
    );
    let writer: ReturnType<typeof Bun.spawn> | undefined;
    try {
      writer = Bun.spawn([
        "sh",
        "-c",
        'exec 3>"$1" || exit 1; : > "$2"; printf first >&3; i=0; while [ ! -e "$3" ] && [ "$i" -lt 200 ]; do sleep 0.05; i=$((i+1)); done; printf second >&3; exec 3>&-',
        "sh",
        fifo,
        opened,
        firstRead,
      ]);
      // A read before the writer holds its end reports end of input, so the
      // read waits for the writer to say it has the FIFO open. The deadline is
      // 3 s, inside bun's 5 s per-test timeout, so a writer that never opens
      // the FIFO fails the assertion below rather than the test's timeout.
      for (let waited = 0; !existsSync(opened) && waited < 300; waited++)
        await Bun.sleep(10);
      expect(existsSync(opened)).toBe(true);
      const sizes: number[] = [];
      const out = readStdinValueBytes(
        64,
        descriptor,
        {},
        {
          read: (fd, buffer) => {
            const count = readSync(fd, buffer, 0, buffer.length, null);
            sizes.push(count);
            if (count > 0) writeFileSync(firstRead, "");
            return count;
          },
        },
      );
      expect(decode(out)).toBe("firstsecond");
      // At least two reads returned bytes, so the second landed past the first.
      expect(sizes.filter((size) => size > 0).length).toBeGreaterThanOrEqual(2);
    } finally {
      closeSync(descriptor);
      writeFileSync(firstRead, "");
      // A late writer would otherwise block in open(2) and outlive the test.
      writer?.kill();
      await writer?.exited;
    }
  });

  test("the wait polls for readability first and sleeps only where poll did not resolve", () => {
    const calls: string[] = [];
    waitReadable(9, {
      poll: (descriptor, timeoutMs) => {
        calls.push(`poll ${descriptor} ${timeoutMs}`);
        return { result: 0, revents: 0 };
      },
      sleep: (ms) => calls.push(`sleep ${ms}`),
    });
    // A poll that answered, even with nothing readable (result 0, no revents),
    // ends the wait: a quiet interval that passed inside poll is the wait.
    expect(calls).toEqual(["poll 9 30"]);
    calls.length = 0;
    waitReadable(9, {
      poll: (descriptor, timeoutMs) => {
        calls.push(`poll ${descriptor} ${timeoutMs}`);
        return undefined;
      },
      sleep: (ms) => calls.push(`sleep ${ms}`),
    });
    expect(calls).toEqual(["poll 9 30", "sleep 30"]);
  });

  test("a read that reports EAGAIN waits before it retries, and EINTR retries at once", () => {
    const scripted = ["EAGAIN", "EINTR", "EWOULDBLOCK"];
    const waits: number[] = [];
    const buffer = new Uint8Array(4);
    const read = readOnce(7, buffer, {
      read: (_descriptor, target) => {
        const code = scripted.shift();
        if (code !== undefined) throw Object.assign(new Error(code), { code });
        target[0] = 0x41;
        return 1;
      },
      wait: (descriptor) => waits.push(descriptor),
    });
    expect(read).toBe(1);
    // EAGAIN and EWOULDBLOCK each waited on the descriptor; EINTR did not.
    expect(waits).toEqual([7, 7]);
    // Any other error is not retried.
    expect(() =>
      readOnce(7, buffer, {
        read: () => {
          throw Object.assign(new Error("EBADF"), { code: "EBADF" });
        },
        wait: () => waits.push(-1),
      }),
    ).toThrow("EBADF");
    expect(waits).toEqual([7, 7]);
  });

  test("the queue probe reports nothing queued on a descriptor that is not a terminal", () => {
    expect(withInput(encode("queued\n"), (fd) => inputQueued(fd))).toBe(false);
  });

  test("stdin reads exact bytes and refuses more than the bound", () => {
    expect(
      decode(
        withInput(encode("exact\nbytes"), (fd) =>
          readStdinValueBytes(1024, fd),
        ),
      ),
    ).toBe("exact\nbytes");
    expect(
      codeOf(() =>
        withInput(new Uint8Array(9), (fd) => readStdinValueBytes(8, fd)),
      ),
    ).toBe("secret_value_too_large");
    // Exactly the bound is accepted: only a byte past it refuses, so a `>=`
    // in the bound check goes red here and nowhere above.
    expect(
      decode(
        withInput(encode("a".repeat(8)), (fd) => readStdinValueBytes(8, fd)),
      ),
    ).toBe("a".repeat(8));
  });

  test("the stdin path refuses a terminal, where typing would be echoed", () => {
    const values = createTerminalSecretValues({
      isInteractive: () => true,
    });
    expect(codeOf(() => values.readStdin(1024))).toBe("secret_stdin_terminal");
  });

  test("the replacement question is consent-shaped and fails closed", () => {
    const prompt = { text: "" };
    const answering = (answer: string, throwing = false) =>
      createTerminalSecretValues({
        isInteractive: () => true,
        writePrompt: (text) => {
          prompt.text = text;
        },
        readAnswer: () => {
          if (throwing) throw new Error("no terminal");
          return answer;
        },
      });
    expect(answering("y").confirmReplace(SENTINEL_ALIAS)).toBe(true);
    expect(answering(" yes ").confirmReplace(SENTINEL_ALIAS)).toBe(true);
    expect(answering("n").confirmReplace(SENTINEL_ALIAS)).toBe(false);
    expect(answering("", true).confirmReplace(SENTINEL_ALIAS)).toBe(false);
    // The alias is escaped rather than passed through: it came from argv,
    // and it cannot redraw the prompt that asks about it.
    answering("n").confirmReplace("esc\u000aaped");
    expect(prompt.text).toContain("\\x0a");
  });

  test("a prompt that cannot be written after the read does not drop the value or leave echo off", () => {
    const raw: boolean[] = [];
    const values = createTerminalSecretValues({
      isInteractive: () => true,
      setRaw: (on) => raw.push(on),
      writePrompt: (text) => {
        if (text === "\n") throw new Error("terminal gone");
      },
      readHiddenBytes: () => encode("kept"),
      flushInput: () => false,
      inputPending: () => false,
    });
    expect(decode(values.readHidden() as Uint8Array)).toBe("kept");
    // Echo went off for the read and back on afterwards.
    expect(raw).toEqual([true, false]);
  });

  test("no terminal means no hidden read and no confirmation", () => {
    const values = createTerminalSecretValues({
      isInteractive: () => false,
      readHiddenBytes: () => encode("never"),
    });
    expect(values.available()).toBe(false);
    expect(values.readHidden()).toBeUndefined();
    expect(values.confirmReplace(SENTINEL_ALIAS)).toBe(false);
  });
});
