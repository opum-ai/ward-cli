// WCLI-5: the KeyProvider over the credential store. Everything here runs
// against MemoryKeychain, the preloaded refusal mock (bunfig.toml), or a
// compiled probe that makes no store call. Nothing reads or writes a real
// keychain item. Assertions compare keys as booleans, so a failure report
// never prints key bytes.
import { afterAll, describe, expect, test } from "bun:test";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildExecutable } from "../scripts/build.ts";
import {
  createKeychainKeyProvider,
  defaultKeyTimeoutMs,
  keychainService,
} from "../src/adapters/keychain.ts";
import type { ErrorCode } from "../src/contract/errors.ts";
import { WardError } from "../src/contract/errors.ts";
import { generateVaultKey } from "../src/domain/envelope.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";
import { realKeychainRefusal } from "./support/no-real-keychain.ts";

const VAULT_ID = "3f1c2b7e-9a4d-4e6f-8b21-5c7d9e0a1b2c";
const TEST_SERVICE = "opum.ward.test";
const ITEM = `${TEST_SERVICE}\u0000vault-${VAULT_ID}`;

async function caught(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

async function rejectsWith(code: ErrorCode, run: () => Promise<unknown>) {
  const error = await caught(run);
  expect(error).toBeInstanceOf(WardError);
  expect((error as WardError).code).toBe(code);
}

const sameBytes = (a: ArrayLike<number>, b: ArrayLike<number>) =>
  a.length === b.length && Array.from(a).every((byte, i) => byte === b[i]);

function setup(timeoutMs = 200) {
  const store = new MemoryKeychain();
  const provider = createKeychainKeyProvider({
    service: TEST_SERVICE,
    timeoutMs,
    entry: store.entry,
  });
  return { store, provider };
}

describe("create and load", () => {
  test("a created key loads back byte for byte", async () => {
    const { provider } = setup();
    const key = generateVaultKey();
    const expected = [...key];
    await provider.create(VAULT_ID, key);
    expect(sameBytes(await provider.load(VAULT_ID), expected)).toBe(true);
  });

  test("the caller's key is left intact by create", async () => {
    const { provider } = setup();
    const key = generateVaultKey();
    const expected = [...key];
    await provider.create(VAULT_ID, key);
    expect(sameBytes(key, expected)).toBe(true);
  });

  test("the item is stored under the service and a vault-derived account", async () => {
    const { store, provider } = setup();
    await provider.create(VAULT_ID, generateVaultKey());
    expect([...store.items.keys()]).toEqual([ITEM]);
  });

  test("create never replaces a visible key", async () => {
    const { store, provider } = setup();
    const first = generateVaultKey();
    const expected = [...first];
    await provider.create(VAULT_ID, first);
    await rejectsWith("vault_key_exists", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writeAttempts).toBe(1);
    expect(sameBytes(await provider.load(VAULT_ID), expected)).toBe(true);
  });

  test("create refuses to write over an unreadable existing item", async () => {
    const { store, provider } = setup();
    store.items.set(ITEM, [1, 2, 3]);
    await rejectsWith("vault_key_exists", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writeAttempts).toBe(0);
  });

  for (const length of [0, 16, 31, 33])
    test(`create refuses a ${length}-byte key`, async () => {
      const { store, provider } = setup();
      await rejectsWith("vault_key_invalid", () =>
        provider.create(VAULT_ID, new Uint8Array(length)),
      );
      expect(store.readAttempts + store.writeAttempts).toBe(0);
    });

  test("an invalid vault id reaches no store entry", async () => {
    const { store, provider } = setup();
    await rejectsWith("vault_record_malformed", () =>
      provider.load("../../login"),
    );
    await rejectsWith("vault_record_malformed", () =>
      provider.create("not-a-uuid", generateVaultKey()),
    );
    expect(store.readAttempts + store.writeAttempts).toBe(0);
  });
});

describe("the key side of T02: failures never write a key", () => {
  test("a missing key is vault_key_missing", async () => {
    const { store, provider } = setup();
    await rejectsWith("vault_key_missing", () => provider.load(VAULT_ID));
    expect(store.writeAttempts).toBe(0);
  });

  const holed = new Array(32).fill(1);
  delete holed[5];
  const notKeys: [label: string, value: unknown][] = [
    ["an empty array", []],
    ["3 bytes", [1, 2, 3]],
    ["33 bytes", new Array(33).fill(7)],
    ["a byte of 256", [256, ...new Array(31).fill(0)]],
    ["a byte of -1", [-1, ...new Array(31).fill(0)]],
    ["a byte of 0.5", [0.5, ...new Array(31).fill(0)]],
    ["a fully sparse array", new Array(32)],
    ["an array with one hole", holed],
    ["a string", "x".repeat(32)],
    ["an object with a length", { length: 32 }],
  ];
  for (const [label, value] of notKeys)
    test(`${label} is vault_key_invalid`, async () => {
      const { store, provider } = setup();
      store.items.set(ITEM, value);
      await rejectsWith("vault_key_invalid", () => provider.load(VAULT_ID));
      expect(store.writeAttempts).toBe(0);
    });

  test("a locked store is vault_key_unavailable, and its message is not passed on", async () => {
    const { store, provider } = setup();
    store.mode = "locked";
    const error = await caught(() => provider.load(VAULT_ID));
    expect((error as WardError).code).toBe("vault_key_unavailable");
    expect((error as WardError).message).not.toContain("interaction");
    await rejectsWith("vault_key_unavailable", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writeAttempts).toBe(0);
  });

  test("create does not write when the existence check fails", async () => {
    const { store, provider } = setup();
    store.mode = "reads-fail";
    await rejectsWith("vault_key_unavailable", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writeAttempts).toBe(0);
  });

  test("create does not write when the existence check times out", async () => {
    const { store, provider } = setup(50);
    store.mode = "hang";
    await rejectsWith("vault_key_unavailable", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writeAttempts).toBe(0);
  });
});

describe("an unconfirmed create is indeterminate, not a failure to write", () => {
  test("a read-back that does not match", async () => {
    const { store, provider } = setup();
    store.mode = "write-corrupt";
    await rejectsWith("vault_key_write_unconfirmed", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
  });

  test("a write that lands after the bound is found by the next create", async () => {
    const { store, provider } = setup(50);
    store.mode = "late-write";
    store.lateMs = 150;
    await rejectsWith("vault_key_write_unconfirmed", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.items.has(ITEM)).toBe(true);
    store.mode = "normal";
    await rejectsWith("vault_key_exists", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writeAttempts).toBe(1);
  });
});

describe("every store call settles within its bound", () => {
  for (const operation of ["load", "create"] as const)
    test(`${operation} gives up at the bound`, async () => {
      const { store, provider } = setup(150);
      store.mode = "hang";
      const started = performance.now();
      await rejectsWith("vault_key_unavailable", () =>
        operation === "load"
          ? provider.load(VAULT_ID)
          : provider.create(VAULT_ID, generateVaultKey()),
      );
      const elapsed = performance.now() - started;
      expect(elapsed).toBeGreaterThanOrEqual(140);
      expect(elapsed).toBeLessThan(400);
    });

  test("the default bound is 10 s and is the one applied", async () => {
    expect(defaultKeyTimeoutMs).toBe(10_000);
    const store = new MemoryKeychain();
    const provider = createKeychainKeyProvider({
      service: TEST_SERVICE,
      entry: store.entry,
    });
    const delays: number[] = [];
    const realSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = ((
      handler: () => void,
      delay?: number,
      ...rest: unknown[]
    ) => {
      delays.push(delay ?? 0);
      return realSetTimeout(handler, delay, ...rest);
    }) as typeof setTimeout;
    try {
      await caught(() => provider.load(VAULT_ID));
    } finally {
      globalThis.setTimeout = realSetTimeout;
    }
    expect(delays).toEqual([defaultKeyTimeoutMs]);
  });

  test("the bound's timer is cleared once the call settles", async () => {
    const { provider } = setup(60_000);
    const cleared: unknown[] = [];
    const set: unknown[] = [];
    const realSetTimeout = globalThis.setTimeout;
    const realClearTimeout = globalThis.clearTimeout;
    globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
      const id = realSetTimeout(...args);
      set.push(id);
      return id;
    }) as typeof setTimeout;
    globalThis.clearTimeout = ((id: Parameters<typeof clearTimeout>[0]) => {
      cleared.push(id);
      realClearTimeout(id);
    }) as typeof clearTimeout;
    try {
      await caught(() => provider.load(VAULT_ID));
    } finally {
      globalThis.setTimeout = realSetTimeout;
      globalThis.clearTimeout = realClearTimeout;
    }
    expect(set.length).toBe(1);
    expect(cleared).toEqual(set);
  });
});

describe("the native credential store", () => {
  test("the production service is opum.ward", () => {
    expect(keychainService).toBe("opum.ward");
  });

  test("off macOS, nothing is constructed and the store is unsupported", async () => {
    const provider = createKeychainKeyProvider({
      service: TEST_SERVICE,
      platform: "linux",
    });
    await rejectsWith("vault_key_store_unsupported", () =>
      provider.load(VAULT_ID),
    );
    await rejectsWith("vault_key_store_unsupported", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
  });

  test("in a test process, the preloaded mock refuses the real binding", async () => {
    const provider = createKeychainKeyProvider({
      service: TEST_SERVICE,
      platform: "darwin",
    });
    const error = await caught(() => provider.load(VAULT_ID));
    expect(error).not.toBeInstanceOf(WardError);
    expect((error as Error).message).toBe(realKeychainRefusal);
  });
});

describe("the binding in a compiled executable", () => {
  const work = mkdtempSync(join(tmpdir(), "ward-keychain-"));
  afterAll(() => rmSync(work, { recursive: true, force: true }));

  function relocated(fixture: string): string {
    const built = buildExecutable({
      entry: join(import.meta.dir, "fixtures", `${fixture}.ts`),
      outfile: join(work, "build", fixture),
    });
    const moved = join(work, fixture);
    copyFileSync(built, moved);
    rmSync(join(work, "build"), { recursive: true, force: true });
    return moved;
  }

  // A harmless stand-in for a planted native module: it only prints.
  const override = join(work, "override.cjs");
  writeFileSync(
    override,
    'process.stdout.write("override-loaded\\n"); module.exports = {};\n',
  );

  function run(binary: string, env: Record<string, string> = {}) {
    const result = Bun.spawnSync([binary], {
      cwd: work,
      env: { ...process.env, ...env },
    });
    return { exitCode: result.exitCode, stdout: result.stdout.toString() };
  }

  test("embeds and loads after the executable is moved", () => {
    const result = run(relocated("keychain-probe"));
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      service: "opum.ward",
      load: "function",
    });
  }, 30_000);

  test("the guard stops NAPI_RS_NATIVE_LIBRARY_PATH replacing the binding", () => {
    const result = run(relocated("keychain-probe"), {
      NAPI_RS_NATIVE_LIBRARY_PATH: override,
    });
    expect(result.stdout.includes("override-loaded")).toBe(false);
  }, 30_000);

  test("control: without the guard, the override loads", () => {
    const result = run(relocated("keychain-probe-unguarded"), {
      NAPI_RS_NATIVE_LIBRARY_PATH: override,
    });
    expect(result.stdout.includes("override-loaded")).toBe(true);
  }, 30_000);
});
