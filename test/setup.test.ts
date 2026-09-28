// WCLI-20: `ward setup` — the one place Ward creates a vault key or a
// vault. Everything here runs against MemoryKeychain or FileKeychain and a
// temporary directory; nothing touches the real ~/.ward or a real
// credential store. Keys are compared as booleans and the vault id is
// reported, never key bytes.
//
// The mock is imported first, whatever the working directory: bunfig.toml's
// preload only applies from the repository root (test-isolation.test.ts).
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import {
  acquireSetupSession,
  setupJournalFileName,
  setupLockFileName,
} from "../src/adapters/setup-session.ts";
import {
  createSqliteVaultStore,
  vaultFileName,
} from "../src/adapters/sqlite-vault-store.ts";
import { initialVaultSnapshot } from "../src/application/setup.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { FileKeychain } from "./support/file-keychain.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const TEST_SERVICE = "opum.ward.test";
const EXIT_PROBE = join(import.meta.dir, "fixtures", "setup-exit-probe.ts");
const STAGE_PROBE = join(import.meta.dir, "fixtures", "setup-stage-probe.ts");

const root = mkdtempSync(join(tmpdir(), "ward-setup-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;
function fresh(options?: { timeoutMs?: number }) {
  const home = mkdtempSync(join(root, `case-${++cases}-`));
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: TEST_SERVICE,
    timeoutMs: options?.timeoutMs ?? 2_000,
    entry: keychain.entry,
  });
  return {
    home,
    directory: join(home, ".ward"),
    keychain,
    keyProvider,
    options: () => ({ wardDirectory: join(home, ".ward"), keyProvider }),
    store: createSqliteVaultStore({ directory: join(home, ".ward") }),
  };
}

const json = (stdout: string) => JSON.parse(stdout) as Record<string, unknown>;
const mode = (path: string) => statSync(path).mode & 0o777;

function spawnProbe(entry: string, args: string[]) {
  return Bun.spawn([process.execPath, entry, ...args], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function untilReady(worker: ReturnType<typeof spawnProbe>) {
  const reader = worker.stdout.getReader();
  let seen = "";
  while (!seen.includes("ready\n")) {
    const { value, done } = await reader.read();
    if (done) throw new Error("probe exited before it was ready");
    seen += new TextDecoder().decode(value);
  }
  reader.releaseLock();
}

// `runWard(["setup"])` without touching runWard's own composition, so the
// flow can be driven with a store built on a specific directory.
async function setupViaRunWard(options: RunOptions) {
  return await runWard(["setup", "--json"], options);
}

describe("T01: setup and non-initialization", () => {
  test("setup creates a keychain item and an encrypted vault", async () => {
    const { directory, keychain, options } = fresh();
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stderr).toBe("");
    const envelope = json(result.stdout);
    expect(envelope.kind).toBe("setup.complete");
    const data = envelope.data as { vaultId: string; revision: number };
    expect(data.revision).toBe(1);
    expect(keychain.items.size).toBe(1);
    expect(mode(directory)).toBe(0o700);
    expect(mode(join(directory, vaultFileName))).toBe(0o600);
    // The lock file persists (flock lives in the kernel; the file content
    // is advisory); only the journal disappears.
    expect(existsSync(join(directory, setupLockFileName))).toBe(true);
    expect(existsSync(join(directory, setupJournalFileName))).toBe(false);
    // The sealed snapshot is the minimal skeleton document.
    const key = keychain.items.values().next().value as number[];
    const store = createSqliteVaultStore({ directory });
    const snapshot = store.read(new Uint8Array(key));
    expect(
      Buffer.from(snapshot.plaintext).equals(
        Buffer.from(initialVaultSnapshot()),
      ),
    ).toBe(true);
    expect(snapshot.vaultId).toBe(data.vaultId);
  });

  test("a rerun on a completed setup refuses and changes nothing", async () => {
    const { keychain, options, directory, store } = fresh();
    expect((await setupViaRunWard(options())).exitCode).toBe(exitCodes.success);
    const before = readFileSync(join(directory, vaultFileName));
    const items = keychain.items.size;
    const second = await setupViaRunWard(options());
    expect(second.exitCode).toBe(exitCodes.conflict);
    expect(json(second.stderr).code).toBe("vault_exists");
    expect(keychain.items.size).toBe(items);
    expect(keychain.writeAttempts).toBe(1);
    expect(readFileSync(join(directory, vaultFileName)).equals(before)).toBe(
      true,
    );
    expect(store.header()?.revision).toBe(1);
  });

  test("--help and instructions never initialize a store", async () => {
    const { directory, options } = fresh();
    for (const argv of [
      ["--help"],
      ["help"],
      ["instructions"],
      ["instructions", "--list"],
      ["manifest"],
      ["setup", "--help"],
    ]) {
      const result = await runWard(argv, options());
      expect(result.exitCode).toBe(exitCodes.success);
      expect(existsSync(directory)).toBe(false);
    }
  });
});

describe("T02: an existing vault fails closed", () => {
  async function setUp() {
    const f = fresh();
    expect((await setupViaRunWard(f.options())).exitCode).toBe(
      exitCodes.success,
    );
    const before = readFileSync(join(f.directory, vaultFileName));
    const id = f.store.header()?.vaultId ?? "";
    return { ...f, before, id };
  }

  test("missing key is a recovery condition and the vault is unchanged", async () => {
    const { keychain, options, before, directory } = await setUp();
    keychain.items.clear();
    const writesBefore = keychain.writeAttempts;
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(json(result.stderr).code).toBe("vault_key_missing");
    expect(readFileSync(join(directory, vaultFileName)).equals(before)).toBe(
      true,
    );
    expect(keychain.items.size).toBe(0);
    expect(keychain.writeAttempts).toBe(writesBefore);
  });

  test("a locked store fails closed and the vault is unchanged", async () => {
    const { keychain, options, before, directory } = await setUp();
    keychain.mode = "locked";
    const writesBefore = keychain.writeAttempts;
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.indeterminate);
    expect(json(result.stderr).code).toBe("vault_key_unavailable");
    expect(readFileSync(join(directory, vaultFileName)).equals(before)).toBe(
      true,
    );
    expect(keychain.writeAttempts).toBe(writesBefore);
  });

  test("an unresponsive store fails within the bound and demands an explicit exit", async () => {
    const { keychain, options, before, directory } = await setUp();
    keychain.mode = "hang";
    const writesBefore = keychain.writeAttempts;
    const started = performance.now();
    const result = await setupViaRunWard(options());
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(result.exitCode).toBe(exitCodes.indeterminate);
    expect(json(result.stderr).code).toBe("vault_key_unavailable");
    expect(result.exitExplicitly).toBe(true);
    expect(readFileSync(join(directory, vaultFileName)).equals(before)).toBe(
      true,
    );
    expect(keychain.writeAttempts).toBe(writesBefore);
  });
});

describe("the interrupted-setup resume model", () => {
  async function interrupted(options: { withKey: boolean }) {
    const f = fresh();
    const session = acquireSetupSession(f.directory);
    const vaultId = crypto.randomUUID();
    session.recordVaultId(vaultId);
    if (options.withKey) {
      const key = new Uint8Array(32).fill(7);
      await f.keyProvider.create(vaultId, key);
    }
    session.release();
    return { ...f, vaultId };
  }

  test("journal with no key resumes the same id and creates the key", async () => {
    const { options, vaultId, keychain, directory } = await interrupted({
      withKey: false,
    });
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.success);
    expect((json(result.stdout).data as { vaultId: string }).vaultId).toBe(
      vaultId,
    );
    expect(keychain.writeAttempts).toBe(1);
    expect(existsSync(join(directory, setupJournalFileName))).toBe(false);
  });

  test("journal with a stored key resumes without writing a key", async () => {
    const { options, vaultId, keychain, directory } = await interrupted({
      withKey: true,
    });
    // The only write is the seeding one in interrupted().
    const writesBefore = keychain.writeAttempts;
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.success);
    expect((json(result.stdout).data as { vaultId: string }).vaultId).toBe(
      vaultId,
    );
    expect(keychain.writeAttempts).toBe(writesBefore);
    expect(existsSync(join(directory, setupJournalFileName))).toBe(false);
  });

  test("journal after a completed vault finishes the cleanup", async () => {
    const { options, directory, vaultId } = await interrupted({
      withKey: true,
    });
    expect((await setupViaRunWard(options())).exitCode).toBe(exitCodes.success);
    // Simulate the crash between the vault commit and the journal removal.
    const session = acquireSetupSession(directory);
    session.recordVaultId(vaultId);
    session.release();
    const rerun = await setupViaRunWard(options());
    expect(rerun.exitCode).toBe(exitCodes.success);
    expect((json(rerun.stdout).data as { resumed: boolean }).resumed).toBe(
      true,
    );
    expect(existsSync(join(directory, setupJournalFileName))).toBe(false);
  });

  test("a completed setup whose key no longer opens the vault is a recovery condition", async () => {
    const { directory, options, keychain, store } = fresh();
    expect((await setupViaRunWard(options())).exitCode).toBe(exitCodes.success);
    const id = store.header()?.vaultId ?? "";
    // Replace the stored key with a different, valid 32-byte key.
    keychain.items.set(
      `${TEST_SERVICE}\u0000vault-${id}`,
      Array.from(new Uint8Array(32).fill(9)),
    );
    const session = acquireSetupSession(directory);
    session.recordVaultId(id);
    session.release();
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(json(result.stderr).code).toBe("vault_authentication_failed");
    expect(existsSync(join(directory, setupJournalFileName))).toBe(true);
  });

  test("a deleted vault with a surviving journal resumes the same identity", async () => {
    // The documented limit (docs/adr/0001): deleting the vault is not a
    // fresh start while the journal and key survive; the old id and key
    // are resumed, and an older copy of the vault still authenticates.
    const { directory, options, keychain, store } = fresh();
    expect((await setupViaRunWard(options())).exitCode).toBe(exitCodes.success);
    const id = store.header()?.vaultId ?? "";
    const session = acquireSetupSession(directory);
    session.recordVaultId(id);
    session.release();
    rmSync(join(directory, vaultFileName));
    const writesBefore = keychain.writeAttempts;
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.success);
    expect((json(result.stdout).data as { vaultId: string }).vaultId).toBe(id);
    expect(keychain.writeAttempts).toBe(writesBefore);
  });

  test("a damaged journal beside a healthy vault is cleared, not refused", async () => {
    const { directory, options, store } = fresh();
    expect((await setupViaRunWard(options())).exitCode).toBe(exitCodes.success);
    writeFileSync(join(directory, setupJournalFileName), "{oops", {
      mode: 0o600,
    });
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.success);
    expect(existsSync(join(directory, setupJournalFileName))).toBe(false);
  });

  test("a damaged journal refuses and is not overwritten", async () => {
    const { options, directory } = await interrupted({ withKey: false });
    writeFileSync(join(directory, setupJournalFileName), "{not json", {
      mode: 0o600,
    });
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(json(result.stderr).code).toBe("setup_state_invalid");
    expect(readFileSync(join(directory, setupJournalFileName), "utf8")).toBe(
      "{not json",
    );
  });
});

describe("write-unconfirmed resolution", () => {
  test("a write that lands late is confirmed by load, never written again", async () => {
    const f = fresh({ timeoutMs: 50 });
    f.keychain.mode = "late-write";
    f.keychain.lateMs = 300;
    const result = await setupViaRunWard(f.options());
    expect(result.exitCode).toBe(exitCodes.success);
    expect(f.keychain.writeAttempts).toBe(1);
    expect(f.store.header()?.revision).toBe(1);
    // The confirmation call was abandoned at its bound even though the
    // write landed: a pending native call may still be running, so the
    // process must exit explicitly even on success.
    expect(result.exitExplicitly).toBe(true);
  });

  test("a hanging confirmation reports unconfirmed and demands an explicit exit", async () => {
    const f = fresh({ timeoutMs: 50 });
    // The check read succeeds and the write lands; the confirmation read
    // hangs, which is exactly the write-unconfirmed shape.
    f.keychain.mode = "hang-after-write";
    const result = await setupViaRunWard(f.options());
    expect(result.exitCode).toBe(exitCodes.indeterminate);
    expect(json(result.stderr).code).toBe("vault_key_write_unconfirmed");
    expect(result.exitExplicitly).toBe(true);
    expect(f.keychain.writeAttempts).toBe(1);
    expect(f.store.header()).toBeUndefined();
  });

  test("the journal survives, so a rerun after the store recovers completes", async () => {
    const f = fresh({ timeoutMs: 50 });
    f.keychain.mode = "hang-after-write";
    expect((await setupViaRunWard(f.options())).exitCode).toBe(
      exitCodes.indeterminate,
    );
    expect(existsSync(join(f.directory, setupJournalFileName))).toBe(true);
    f.keychain.mode = "normal";
    const rerun = await setupViaRunWard(f.options());
    expect(rerun.exitCode).toBe(exitCodes.success);
    expect((json(rerun.stdout).data as { resumed: boolean }).resumed).toBe(
      true,
    );
  });
});

describe("the setup lock", () => {
  test(
    "a live flock holder refuses a second setup, and release admits it",
    async () => {
      const { directory, options } = fresh();
      const worker = spawnProbe(STAGE_PROBE, [
        "lock-hold",
        "unused",
        directory,
      ]);
      await untilReady(worker);
      try {
        const result = await setupViaRunWard(options());
        expect(result.exitCode).toBe(exitCodes.conflict);
        expect(json(result.stderr).code).toBe("setup_in_progress");
        expect(existsSync(join(directory, vaultFileName))).toBe(false);
      } finally {
        worker.kill(9);
        await worker.exited;
      }
      // The kernel released the lock with the holder's death.
      expect((await setupViaRunWard(options())).exitCode).toBe(
        exitCodes.success,
      );
    },
    { timeout: 30_000 },
  );

  test("an unlocked lock file does not block setup", async () => {
    const { directory, options } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    // Content is advisory on macOS, where flock(2) arbitrates: a pid of a
    // dead process must not block a new setup.
    writeFileSync(join(directory, setupLockFileName), "999999\n", {
      mode: 0o600,
    });
    const result = await setupViaRunWard(options());
    expect(result.exitCode).toBe(exitCodes.success);
    expect(readFileSync(join(directory, setupLockFileName), "utf8")).toBe(
      `${process.pid}\n`,
    );
  });
});

describe("mutual exclusion under concurrency", () => {
  test(
    "concurrent setups serialize: one winner, one key ever written, one vault",
    async () => {
      const f = fresh();
      const storeDirectory = mkdtempSync(join(root, "keys-"));
      const workers = [1, 2, 3, 4].map(() =>
        spawnProbe(STAGE_PROBE, ["plain", storeDirectory, f.directory]),
      );
      const outcomes = await Promise.all(
        workers.map(async (worker) => {
          await new Response(worker.stdout).text();
          await new Response(worker.stderr).text();
          await worker.exited;
          return worker.exitCode;
        }),
      );
      expect(outcomes.filter((code) => code === exitCodes.success).length).toBe(
        1,
      );
      for (const code of outcomes)
        if (code !== exitCodes.success) expect(code).toBe(exitCodes.conflict);
      expect(readdirSync(storeDirectory).length).toBe(1);
      expect(f.store.header()?.revision).toBe(1);
    },
    { timeout: 60_000 },
  );
});

describe("interruption by kill", () => {
  test(
    "killed before the key write: rerun completes, one key total",
    async () => {
      const f = fresh();
      const storeDirectory = mkdtempSync(join(root, "keys-"));
      const worker = spawnProbe(STAGE_PROBE, [
        "before-write",
        storeDirectory,
        f.directory,
      ]);
      await untilReady(worker);
      worker.kill(9);
      await worker.exited;
      expect(existsSync(join(f.directory, setupJournalFileName))).toBe(true);
      expect(existsSync(join(f.directory, vaultFileName))).toBe(false);
      expect(readdirSync(storeDirectory)).toEqual([]);

      // Rerun against the same surviving store, so "one key total" is
      // measured on the store the interrupted run wrote to.
      const keyProvider = createKeychainKeyProvider({
        service: "opum.ward.stage",
        timeoutMs: 2_000,
        entry: new FileKeychain(storeDirectory).entry,
      });
      const rerun = await runWard(["setup", "--json"], {
        wardDirectory: f.directory,
        keyProvider,
      });
      expect(rerun.exitCode).toBe(exitCodes.success);
      expect(readdirSync(storeDirectory).length).toBe(1);
      expect(f.store.header()?.revision).toBe(1);
    },
    { timeout: 30_000 },
  );

  test(
    "killed after the key write: rerun reuses the key and never writes again",
    async () => {
      const f = fresh();
      const storeDirectory = mkdtempSync(join(root, "keys-"));
      const worker = spawnProbe(STAGE_PROBE, [
        "after-write",
        storeDirectory,
        f.directory,
      ]);
      await untilReady(worker);
      worker.kill(9);
      await worker.exited;
      expect(existsSync(join(f.directory, setupJournalFileName))).toBe(true);
      expect(existsSync(join(f.directory, vaultFileName))).toBe(false);
      expect(readdirSync(storeDirectory).length).toBe(1);
      const storedBefore = readFileSync(
        join(storeDirectory, readdirSync(storeDirectory)[0] ?? ""),
      );

      // Rerun against the same surviving store.
      const keyProvider = createKeychainKeyProvider({
        service: "opum.ward.stage",
        timeoutMs: 2_000,
        entry: new FileKeychain(storeDirectory).entry,
      });
      const rerun = await runWard(["setup", "--json"], {
        wardDirectory: f.directory,
        keyProvider,
      });
      expect(rerun.exitCode).toBe(exitCodes.success);
      expect((json(rerun.stdout).data as { resumed: boolean }).resumed).toBe(
        true,
      );
      const storedAfter = readFileSync(
        join(storeDirectory, readdirSync(storeDirectory)[0] ?? ""),
      );
      expect(storedAfter.equals(storedBefore)).toBe(true);
    },
    { timeout: 30_000 },
  );
});

describe("the bounded explicit exit, in a real process", () => {
  test(
    "a pending native call cannot keep setup alive past the bound",
    async () => {
      const worker = spawnProbe(EXIT_PROBE, []);
      const output = await new Response(worker.stdout).text();
      const error = await new Response(worker.stderr).text();
      const finished = await Promise.race([
        worker.exited.then(() => true),
        new Promise<false>((resolve) =>
          setTimeout(() => resolve(false), 10_000),
        ),
      ]);
      expect(finished).toBe(true);
      expect(worker.exitCode).toBe(exitCodes.indeterminate);
      expect(JSON.parse(error).code).toBe("vault_key_write_unconfirmed");
      expect(output).toBe("");
    },
    { timeout: 30_000 },
  );
});

describe("only setup ever creates a key", () => {
  test("no other source module calls the provider's create", () => {
    // Spec §6.4: "nothing else ever creates or regenerates a key". The
    // enforceable form is source-level: `create` bound to a vaultId
    // argument appears in the two port declarations, the two
    // implementations, and the one caller, setup. A new caller in any
    // spelling (dotted, destructured or subscript) shows up as an extra
    // module and fails this test.
    const callers: string[] = [];
    for (const layer of ["application", "adapters", "cli"]) {
      for (const name of readdirSync(
        join(import.meta.dir, "..", "src", layer),
      )) {
        if (!name.endsWith(".ts")) continue;
        const source = readFileSync(
          join(import.meta.dir, "..", "src", layer, name),
          "utf8",
        );
        if (/\bcreate\([^)]*vaultId/.test(source))
          callers.push(`${layer}/${name}`);
      }
    }
    expect(callers.sort()).toEqual([
      "adapters/keychain.ts",
      "adapters/sqlite-vault-store.ts",
      "application/key-provider.ts",
      "application/setup.ts",
      "application/vault-store.ts",
    ]);
  });
});
