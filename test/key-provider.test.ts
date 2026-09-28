// WCLI-5: the KeyProvider over the credential store. Everything here runs
// against MemoryKeychain or a compiled probe that makes no store call;
// nothing reads or writes a real keychain item.
import { afterAll, describe, expect, test } from "bun:test";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildExecutable } from "../scripts/build.ts";
import {
  createKeychainKeyProvider,
  keychainService,
} from "../src/adapters/keychain.ts";
import type { ErrorCode } from "../src/contract/errors.ts";
import { WardError } from "../src/contract/errors.ts";
import { generateVaultKey } from "../src/domain/envelope.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const VAULT_ID = "3f1c2b7e-9a4d-4e6f-8b21-5c7d9e0a1b2c";
const TEST_SERVICE = "opum.ward.test";

async function rejectsWith(code: ErrorCode, run: () => Promise<unknown>) {
  let caught: unknown;
  try {
    await run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(WardError);
  expect((caught as WardError).code).toBe(code);
}

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
    expect([...(await provider.load(VAULT_ID))]).toEqual(expected);
  });

  test("the item is stored under the service and a vault-derived account", async () => {
    const { store, provider } = setup();
    await provider.create(VAULT_ID, generateVaultKey());
    expect([...store.items.keys()]).toEqual([
      `${TEST_SERVICE}\u0000vault-${VAULT_ID}`,
    ]);
  });

  test("create never replaces an existing key", async () => {
    const { store, provider } = setup();
    const first = generateVaultKey();
    const expected = [...first];
    await provider.create(VAULT_ID, first);
    await rejectsWith("vault_key_exists", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writes).toBe(1);
    expect([...(await provider.load(VAULT_ID))]).toEqual(expected);
  });

  test("create refuses to write over an unreadable existing item", async () => {
    const { store, provider } = setup();
    store.items.set(`${TEST_SERVICE}\u0000vault-${VAULT_ID}`, [1, 2, 3]);
    await rejectsWith("vault_key_exists", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writes).toBe(0);
  });

  for (const length of [0, 16, 31, 33])
    test(`create refuses a ${length}-byte key`, async () => {
      const { store, provider } = setup();
      await rejectsWith("vault_key_invalid", () =>
        provider.create(VAULT_ID, new Uint8Array(length)),
      );
      expect(store.writes).toBe(0);
    });

  test("an invalid vault id reaches no store entry", async () => {
    const { store, provider } = setup();
    await rejectsWith("vault_record_malformed", () =>
      provider.load("../../login"),
    );
    await rejectsWith("vault_record_malformed", () =>
      provider.create("not-a-uuid", generateVaultKey()),
    );
    expect(store.items.size).toBe(0);
  });
});

describe("the key side of T02: failures never create a key", () => {
  test("a missing key is vault_key_missing, and nothing is written", async () => {
    const { store, provider } = setup();
    await rejectsWith("vault_key_missing", () => provider.load(VAULT_ID));
    expect(store.writes).toBe(0);
  });

  for (const stored of [
    [],
    [1, 2, 3],
    new Array(33).fill(7),
    [256, ...new Array(31).fill(0)],
    [-1, ...new Array(31).fill(0)],
    [0.5, ...new Array(31).fill(0)],
  ])
    test(`a stored value of ${stored.length} entries that is not a 32-byte key is vault_key_invalid`, async () => {
      const { store, provider } = setup();
      store.items.set(`${TEST_SERVICE}\u0000vault-${VAULT_ID}`, stored);
      await rejectsWith("vault_key_invalid", () => provider.load(VAULT_ID));
      expect(store.writes).toBe(0);
    });

  test("a locked store is vault_key_unavailable, and its message is not passed on", async () => {
    const { store, provider } = setup();
    store.mode = "locked";
    let caught: unknown;
    try {
      await provider.load(VAULT_ID);
    } catch (error) {
      caught = error;
    }
    expect((caught as WardError).code).toBe("vault_key_unavailable");
    expect((caught as WardError).message).not.toContain("interaction");
    await rejectsWith("vault_key_unavailable", () =>
      provider.create(VAULT_ID, generateVaultKey()),
    );
    expect(store.writes).toBe(0);
  });
});

describe("criterion 5: a hung store fails within the bound", () => {
  for (const operation of ["load", "create"] as const)
    test(`${operation} gives up at the timeout`, async () => {
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
      expect(elapsed).toBeLessThan(1000);
      expect(store.writes).toBe(0);
    });

  test("the default bound is stated and finite", async () => {
    const { defaultKeyTimeoutMs } = await import("../src/adapters/keychain.ts");
    expect(defaultKeyTimeoutMs).toBe(10_000);
  });
});

describe("the production keychain service", () => {
  test("is opum.ward", () => {
    expect(keychainService).toBe("opum.ward");
  });

  test("refuses to be reached from a test process", async () => {
    const provider = createKeychainKeyProvider();
    let caught: unknown;
    try {
      await provider.load(VAULT_ID);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(Error);
    expect(caught).not.toBeInstanceOf(WardError);
  });
});

describe("criterion 2: the binding in a compiled executable", () => {
  const work = mkdtempSync(join(tmpdir(), "ward-keychain-"));
  afterAll(() => rmSync(work, { recursive: true, force: true }));

  test("embeds and loads after the executable is moved", () => {
    const built = buildExecutable({
      entry: join(import.meta.dir, "fixtures", "keychain-probe.ts"),
      outfile: join(work, "build", "keychain-probe"),
    });
    const moved = join(work, "keychain-probe");
    copyFileSync(built, moved);
    rmSync(join(work, "build"), { recursive: true, force: true });
    const run = Bun.spawnSync([moved], { cwd: work });
    expect(run.exitCode).toBe(0);
    expect(JSON.parse(run.stdout.toString())).toEqual({
      service: "opum.ward",
      load: "function",
    });
  }, 30_000);
});
