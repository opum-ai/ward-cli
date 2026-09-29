// WCLI-6: the encrypted SQLite snapshot store. Every test uses its own
// temporary directory and a synthetic key; nothing touches ~/.ward or a
// credential store. Concurrency and crash cases run the real store in
// separate bun processes (fixtures/vault-store-worker.ts). Plaintext is
// compared as booleans or counts and disk scans report file names only, so
// a failure report never prints the synthetic sentinel.
//
// The mock is imported first, whatever the working directory: bunfig.toml's
// preload only applies from the repository root (test-isolation.test.ts).
import "./support/no-real-keychain.ts";
import { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createSqliteVaultStore,
  type EntryStats,
  isPrivateEntry,
  vaultFileName,
} from "../src/adapters/sqlite-vault-store.ts";
import { errorEnvelope, WardError } from "../src/contract/errors.ts";
import { envelopeLimits, generateVaultKey } from "../src/domain/envelope.ts";

const VAULT_ID = "3f1c2b7e-9a4d-4e6f-8b21-5c7d9e0a1b2c";
const SENTINEL = "ward-store-sentinel-7a3f";
const SECOND_SENTINEL = "ward-store-sentinel-c914";
const WORKER = join(import.meta.dir, "fixtures", "vault-store-worker.ts");

const root = mkdtempSync(join(tmpdir(), "ward-store-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;
function fresh(busyTimeoutMs?: number) {
  const home = join(root, `case-${++cases}`);
  mkdirSync(home);
  const directory = join(home, ".ward");
  return {
    home,
    directory,
    file: join(directory, vaultFileName),
    store: createSqliteVaultStore({ directory, busyTimeoutMs }),
  };
}

const bytes = (text: string) => new TextEncoder().encode(text);
const text = (value: Uint8Array) => new TextDecoder().decode(value);
const mode = (path: string) => statSync(path).mode & 0o777;

function thrown(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function codeOf(run: () => unknown): string | undefined {
  const error = thrown(run);
  return error instanceof WardError ? error.code : "not-a-ward-error";
}

// Raw, base64 and hex forms of the needle, in every file under the path.
function filesContaining(directory: string, needle: string): string[] {
  const forms = [
    needle,
    Buffer.from(needle).toString("base64"),
    Buffer.from(needle).toString("hex"),
  ].map((form) => Buffer.from(form));
  return readdirSync(directory, { recursive: true })
    .map(String)
    .filter((name) => statSync(join(directory, name)).isFile())
    .filter((name) => {
      const content = readFileSync(join(directory, name));
      return forms.some((form) => content.includes(form));
    });
}

// Raw SQL against a vault file, through a connection of its own.
//
// The helper asserts its own premise: the mutation must change the file. Every
// case that uses it then asserts about a vault that really was altered, and a
// mutation that changed nothing is a harness fault rather than a result about
// the code. That premise is not free (WCLI-59): a case that rewrote a one-byte
// ciphertext with randomblob(length(ciphertext)) left it identical 1 run in
// 256 - a one-byte randomblob reproduces the old byte that often - so the case
// read the OLD plaintext, the assertion failed as if the reader had missed a
// corrupt vault, and the same shape could as easily have passed while testing
// nothing. A no-op throws here, naming itself, instead of reaching an
// assertion.
function withRaw<T>(file: string, run: (db: Database) => T): T {
  // A missing file is not an empty one: some callers plant a foreign database
  // where none exists, and going from absent to present is a change.
  const before = existsSync(file) ? readFileSync(file) : undefined;
  const db = new Database(file);
  let result: T;
  try {
    result = run(db);
  } finally {
    db.close();
  }
  const after = existsSync(file) ? readFileSync(file) : undefined;
  if (before !== undefined && after?.equals(before))
    throw new Error(
      "ward test harness: the raw mutation changed nothing on disk, so the case that follows would assert about an unaltered file",
    );
  return result;
}

function spawnWorker(key: Uint8Array, args: string[]) {
  return Bun.spawn([process.execPath, WORKER, ...args], {
    cwd: root,
    env: {
      ...process.env,
      WARD_TEST_KEY_HEX: Buffer.from(key).toString("hex"),
      WARD_TEST_VAULT_ID: VAULT_ID,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function untilReady(worker: ReturnType<typeof spawnWorker>) {
  const reader = worker.stdout.getReader();
  let seen = "";
  while (!seen.includes("ready\n")) {
    const { value, done } = await reader.read();
    if (done) throw new Error("worker exited before it was ready");
    seen += new TextDecoder().decode(value);
  }
  reader.releaseLock();
}

async function killed(worker: ReturnType<typeof spawnWorker>) {
  worker.kill(9);
  await worker.exited;
}

describe("create, header and read", () => {
  test("nothing is created by header, read or mutate before setup", () => {
    const { directory, store } = fresh();
    const key = generateVaultKey();
    expect(store.header()).toBeUndefined();
    expect(codeOf(() => store.read(key))).toBe("vault_not_found");
    expect(codeOf(() => store.mutate(key, (p) => p))).toBe("vault_not_found");
    expect(existsSync(directory)).toBe(false);

    mkdirSync(directory, { mode: 0o700 });
    expect(store.header()).toBeUndefined();
    expect(codeOf(() => store.read(key))).toBe("vault_not_found");
    expect(readdirSync(directory)).toEqual([]);
  });

  test("create seals revision 1 in a 0700 directory and a 0600 file", () => {
    const { directory, file, store } = fresh();
    const key = generateVaultKey();
    expect(store.create(VAULT_ID, key, bytes(SENTINEL))).toEqual({
      vaultId: VAULT_ID,
      revision: 1,
      formatVersion: 1,
    });
    expect(mode(directory)).toBe(0o700);
    expect(mode(file)).toBe(0o600);
    expect(readdirSync(directory)).toEqual([vaultFileName]);
    expect(store.header()).toEqual({
      vaultId: VAULT_ID,
      revision: 1,
      formatVersion: 1,
    });
    const snapshot = store.read(key);
    expect(snapshot.revision).toBe(1);
    expect(snapshot.vaultId).toBe(VAULT_ID);
    expect(text(snapshot.plaintext) === SENTINEL).toBe(true);
  });

  test("a second create is refused and the first vault is untouched", () => {
    const { store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("first"));
    const otherId = "9b2e4c1a-7d3f-4a5b-9c8d-1e2f3a4b5c6d";
    expect(
      codeOf(() => store.create(otherId, generateVaultKey(), bytes("second"))),
    ).toBe("vault_exists");
    expect(store.header()).toEqual({
      vaultId: VAULT_ID,
      revision: 1,
      formatVersion: 1,
    });
    expect(text(store.read(key).plaintext) === "first").toBe(true);
  });

  test("a bad key, vault ID or plaintext is refused before anything is written", () => {
    const { directory, store } = fresh();
    expect(
      codeOf(() => store.create(VAULT_ID, new Uint8Array(31), bytes("x"))),
    ).toBe("vault_key_invalid");
    expect(
      codeOf(() => store.create("not-a-uuid", generateVaultKey(), bytes("x"))),
    ).toBe("vault_record_malformed");
    expect(
      codeOf(() =>
        store.create(
          VAULT_ID,
          generateVaultKey(),
          new Uint8Array(envelopeLimits.maxPlaintextBytes + 1),
        ),
      ),
    ).toBe("vault_record_too_large");
    expect(existsSync(directory)).toBe(false);
  });

  test("a wrong key fails authentication", () => {
    const { store } = fresh();
    store.create(VAULT_ID, generateVaultKey(), bytes("x"));
    expect(codeOf(() => store.read(generateVaultKey()))).toBe(
      "vault_authentication_failed",
    );
  });

  test("a vault whose creation was rolled back reads as absent and can be created", () => {
    const { directory, file, store } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    writeFileSync(file, "", { mode: 0o600 });
    expect(store.header()).toBeUndefined();
    expect(codeOf(() => store.read(generateVaultKey()))).toBe(
      "vault_not_found",
    );
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("x"));
    expect(store.read(key).revision).toBe(1);
  });
});

describe("mutate", () => {
  test("each mutation seals the next revision", () => {
    const { store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("a"));
    expect(store.mutate(key, (p) => Buffer.concat([p, bytes("b")]))).toEqual({
      vaultId: VAULT_ID,
      revision: 2,
      formatVersion: 1,
    });
    store.mutate(key, (p) => Buffer.concat([p, bytes("c")]));
    const snapshot = store.read(key);
    expect(snapshot.revision).toBe(3);
    expect(text(snapshot.plaintext) === "abc").toBe(true);
    expect(store.header()).toEqual({
      vaultId: VAULT_ID,
      revision: 3,
      formatVersion: 1,
    });
  });

  test("an error thrown by the change is rethrown as-is and rolls back", () => {
    const { store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("a"));
    const own = new Error("change refused");
    expect(
      thrown(() =>
        store.mutate(key, () => {
          throw own;
        }),
      ),
    ).toBe(own);
    // A WardError from the change keeps its code rather than becoming a
    // store failure.
    expect(
      codeOf(() =>
        store.mutate(key, () => {
          throw new WardError("vault_exists");
        }),
      ),
    ).toBe("vault_exists");
    expect(store.header()?.revision).toBe(1);
    expect(text(store.read(key).plaintext) === "a").toBe(true);
  });

  test("an oversized or asynchronous result is refused and rolls back", () => {
    const { store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("a"));
    expect(
      codeOf(() =>
        store.mutate(
          key,
          () => new Uint8Array(envelopeLimits.maxPlaintextBytes + 1),
        ),
      ),
    ).toBe("vault_record_too_large");
    expect(
      codeOf(() =>
        store.mutate(
          key,
          (async (p: Uint8Array) => p) as unknown as (
            p: Uint8Array,
          ) => Uint8Array,
        ),
      ),
    ).toBe("vault_record_malformed");
    expect(store.header()?.revision).toBe(1);
  });

  test("a wrong key never reaches the change and changes nothing", () => {
    const { store } = fresh();
    store.create(VAULT_ID, generateVaultKey(), bytes("a"));
    let called = false;
    expect(
      codeOf(() =>
        store.mutate(generateVaultKey(), (p) => {
          called = true;
          return p;
        }),
      ),
    ).toBe("vault_authentication_failed");
    expect(called).toBe(false);
    expect(store.header()?.revision).toBe(1);
  });

  test("the buffer passed to the change is zeroed once sealed", () => {
    const { store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes(SENTINEL));
    let seen: Uint8Array | undefined;
    store.mutate(key, (p) => {
      seen = p;
      return bytes("next");
    });
    expect(seen?.every((byte) => byte === 0)).toBe(true);
  });

  test("a modified ciphertext on disk fails authentication", () => {
    const { file, store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("a"));
    // Corrupted by construction, not by chance: this plaintext is one byte, so
    // the ciphertext is one byte, and randomblob(1) reproduced it 1 run in 256
    // - which left the case asserting about an uncorrupted vault (WCLI-59).
    // Flipping every bit of the first byte cannot equal what was there.
    withRaw(file, (db) => {
      const row = db
        .query("SELECT ciphertext FROM vault WHERE slot = 1")
        .get() as { ciphertext: Uint8Array };
      const corrupted = Uint8Array.from(row.ciphertext);
      corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;
      db.query("UPDATE vault SET ciphertext = ? WHERE slot = 1").run(corrupted);
    });
    expect(codeOf(() => store.read(key))).toBe("vault_authentication_failed");
    expect(codeOf(() => store.mutate(key, (p) => p))).toBe(
      "vault_authentication_failed",
    );
  });

  // The helper's own premise, proven rather than assumed: a mutation that
  // changes nothing is a harness fault and must not reach an assertion, where
  // it would be scored as a result about the reader.
  test("the raw helper refuses a mutation that changed nothing", () => {
    const { file, store } = fresh();
    store.create(VAULT_ID, generateVaultKey(), bytes("a"));
    expect(() => withRaw(file, (db) => db.exec("SELECT 1"))).toThrow(
      /changed nothing on disk/,
    );
  });

  // A stated limit of the format (spec §6.3, docs/adr/0001), pinned so that
  // no document can quietly start claiming otherwise.
  test("an older copy of the database still opens: rollback is not detected", () => {
    const { directory, file, store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("old"));
    const saved = join(directory, "..", "saved.db");
    copyFileSync(file, saved);
    store.mutate(key, () => bytes("new"));
    copyFileSync(saved, file);
    expect(store.read(key).revision).toBe(1);
  });
});

describe("T05: no synthetic plaintext on disk", () => {
  test("after create, update, delete and forced failures", () => {
    const { directory, store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes(`{"a":"${SENTINEL}"}`));
    store.mutate(key, () =>
      bytes(`{"a":"${SENTINEL}","b":"${SECOND_SENTINEL}"}`),
    );
    store.mutate(key, () => bytes(`{"a":"${SENTINEL}"}`));
    thrown(() =>
      store.mutate(key, (p) => {
        Buffer.concat([p, bytes(SECOND_SENTINEL)]);
        throw new Error("forced");
      }),
    );
    thrown(() =>
      store.mutate(key, () => {
        const large = new Uint8Array(envelopeLimits.maxPlaintextBytes + 1);
        large.set(bytes(SECOND_SENTINEL));
        return large;
      }),
    );
    thrown(() => store.read(generateVaultKey()));
    store.mutate(key, () => bytes("{}"));
    expect(filesContaining(directory, SENTINEL)).toEqual([]);
    expect(filesContaining(directory, SECOND_SENTINEL)).toEqual([]);
  });

  test("the scan finds the sentinel when it is on disk", () => {
    const { home } = fresh();
    writeFileSync(join(home, "planted"), `x${SENTINEL}x`);
    writeFileSync(
      join(home, "planted.b64"),
      Buffer.from(SENTINEL).toString("base64"),
    );
    expect(filesContaining(home, SENTINEL).sort()).toEqual([
      "planted",
      "planted.b64",
    ]);
  });
});

describe("T06: transactions", () => {
  test(
    "concurrent writers in separate processes lose no update",
    async () => {
      const { directory, store } = fresh();
      const key = generateVaultKey();
      store.create(VAULT_ID, key, new Uint8Array());
      const writers = 4;
      const each = 20;
      const workers = Array.from({ length: writers }, (_, w) =>
        spawnWorker(key, ["append", directory, `w${w}`, String(each)]),
      );
      const outcomes = await Promise.all(
        workers.map(async (worker) => {
          const output = await new Response(worker.stdout).text();
          await worker.exited;
          return JSON.parse(output) as {
            ok: number;
            busy: number;
            other: string[];
          };
        }),
      );
      const ok = outcomes.reduce((sum, o) => sum + o.ok, 0);
      const busy = outcomes.reduce((sum, o) => sum + o.busy, 0);
      expect(outcomes.flatMap((o) => o.other)).toEqual([]);
      expect(ok + busy).toBe(writers * each);
      // A store that only ever reported conflict would satisfy the count
      // assertions, so at least one update must actually land: writers queue
      // on the lock with a 5 s bound, so most of the quick appends succeed.
      expect(ok).toBeGreaterThan(0);
      const snapshot = store.read(key);
      const markers = text(snapshot.plaintext).split(";").filter(Boolean);
      expect(markers.length).toBe(ok);
      expect(new Set(markers).size).toBe(ok);
      expect(snapshot.revision).toBe(1 + ok);
    },
    { timeout: 60_000 },
  );

  test(
    "concurrent creates in separate processes serialize: one wins, one refuses",
    async () => {
      const { directory, store } = fresh();
      const key = generateVaultKey();
      const workers = [1, 2].map(() => spawnWorker(key, ["create", directory]));
      const outcomes = await Promise.all(
        workers.map(async (worker) => {
          const output = await new Response(worker.stdout).text();
          await worker.exited;
          return (JSON.parse(output) as { outcome: string }).outcome;
        }),
      );
      expect([...outcomes].sort()).toEqual(["created", "vault_exists"]);
      expect(store.header()).toEqual({
        vaultId: VAULT_ID,
        revision: 1,
        formatVersion: 1,
      });
      expect(text(store.read(key).plaintext) === "seed").toBe(true);
      // The contract pinned here is the outcome pair, not the lock timing:
      // whether the loser meets the winner's lock or an already committed
      // vault, exactly one create wins and the other refuses. A deferred
      // regression could pass this test; pinning the immediate begin
      // deterministically would need a hook inside create(), which the
      // port does not have, and create stays correct under deferred anyway
      // because the layout re-check runs inside the transaction.
    },
    { timeout: 30_000 },
  );

  // The premise WCLI-35's settledLayout rests on, pinned where it can be
  // observed directly: layoutOf is three reads, and three statements outside
  // a transaction can see the file at three different moments — a commit
  // landing between them hands back a state that never existed (the table
  // present, the header fields not yet). Inside one transaction the same
  // commit cannot land: the writer waits for the reader's snapshot to end, so
  // every read in the transaction is the same moment. If SQLite or the driver
  // ever stops honouring that, the store's one-snapshot read would silently
  // stop being one, and this case goes red.
  test("a commit can land between bare reads and cannot land inside a read transaction", () => {
    const { directory, file } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    const writer = new Database(file);
    try {
      writer.exec("PRAGMA journal_mode = DELETE");
      writer.exec("BEGIN IMMEDIATE");
      writer.exec("PRAGMA user_version = 1");
      writer.exec("CREATE TABLE vault (slot INTEGER PRIMARY KEY, body BLOB)");

      // Bare reads, one commit between them: the first sees the file before
      // the commit, the second after it.
      const bare = new Database(file);
      try {
        expect(bare.query("PRAGMA user_version").get()).toEqual({
          user_version: 0,
        });
        writer.exec("COMMIT");
        expect(bare.query("SELECT name FROM sqlite_schema").all()).toEqual([
          { name: "vault" },
        ]);
      } finally {
        bare.close();
      }

      // One transaction: the writer's next commit cannot land inside it, and
      // both reads answer from the same moment.
      writer.exec("BEGIN IMMEDIATE");
      writer.exec("PRAGMA user_version = 2");
      const reader = new Database(file);
      try {
        const seen = reader
          .transaction(() => {
            const first = reader.query("PRAGMA user_version").get();
            let refused: unknown;
            try {
              writer.exec("COMMIT");
            } catch (error) {
              refused = error;
            }
            const second = reader.query("PRAGMA user_version").get();
            return { first, second, refused };
          })
          .deferred();
        expect(seen.first).toEqual({ user_version: 1 });
        expect(seen.second).toEqual({ user_version: 1 });
        expect(seen.refused).toBeInstanceOf(Error);
        writer.exec("COMMIT");
      } finally {
        reader.close();
      }
    } finally {
      writer.close();
    }
  });

  // The store's use of that one-snapshot read cannot be observed
  // behaviourally: the mixed read needs a commit to land between two of
  // layoutOf's three statements, and there is no hook inside create() to
  // pause between them (see the note in the serialization case above). So it
  // is pinned at the source, the way the store layout contract is
  // (setup.test.ts, ADR 0001): a revert of the pre-lock checks to the bare
  // reads reddens here, instead of only resurfacing as a statistical CI
  // flake.
  test("the pre-lock layout reads go through the one-snapshot helper", () => {
    const source = readFileSync(
      join(import.meta.dir, "..", "src", "adapters", "sqlite-vault-store.ts"),
      "utf8",
    );
    // Each writer's pre-lock region is its own function up to its immediate
    // transaction; the in-transaction re-checks sit inside that transaction,
    // after it. The region must hold the settled read and no bare one, and
    // the bare reads are counted over the whole file as well, so a bare read
    // placed anywhere it could run — beside a settled check, after the
    // journal heal, or inside a helper the region cannot see — reddens the
    // pin instead of hiding behind it. This pin sees this file only, and it
    // matches the bare reads by their literal spelling: one moved to another
    // module, reached through an alias, or written with a different argument
    // name is outside what it can prove.
    const region = (start: string, end: string) => {
      const from = source.indexOf(start);
      const to = from === -1 ? -1 : source.indexOf(end, from);
      return from === -1 || to === -1 ? undefined : source.slice(from, to);
    };
    const createRegion = region("create(vaultId", ".transaction(");
    const mutateRegion = region("mutate(key", ".transaction(");
    const holds = (slice: string | undefined, settled: string, bare: string) =>
      slice !== undefined && slice.includes(settled) && !slice.includes(bare);
    const count = (pattern: RegExp) => (source.match(pattern) ?? []).length;
    const pins: Array<[string, boolean]> = [
      [
        "settledLayout is a deferred transaction over layoutOf",
        /function settledLayout\(db: Database\): "empty" \| "ward" \{\s*(?:\/\/[^\n]*\n\s*)*return db\.transaction\(\(\) => layoutOf\(db\)\)\.deferred\(\);\s*\}/.test(
          source,
        ),
      ],
      [
        "requireSettledVault takes its answer from settledLayout",
        /function requireSettledVault\(db: Database\): void \{\s*(?:\/\/[^\n]*\n\s*)*if \(settledLayout\(db\) !== "ward"\) throw new WardError\("vault_not_found"\);\s*\}/.test(
          source,
        ),
      ],
      [
        "create's pre-lock region reads the settled layout and no bare one",
        holds(createRegion, "settledLayout(db)", "layoutOf(db)"),
      ],
      [
        "mutate's pre-lock region reads the settled vault and no bare one",
        holds(mutateRegion, "requireSettledVault(db)", "requireVault(db)"),
      ],
      // The bare reads there should be, and no others: layoutOf's four are
      // requireVault's body, settledLayout's body, and the in-transaction
      // checks in create and header; requireVault's two callers are the
      // in-transaction checks in read and mutate. A new reader spelling them
      // the same way — or one moved into a helper that keeps the db
      // parameter name — moves these numbers and asks for this pin to be
      // read again.
      [
        "the file holds exactly the four known bare layoutOf reads",
        count(/layoutOf\(db\)/g) === 4,
      ],
      [
        "the file holds exactly the two known bare requireVault calls",
        count(/requireVault\(db\)/g) === 2,
      ],
    ];
    const missing = pins.filter(([, ok]) => !ok).map(([name]) => name);
    expect(missing).toEqual([]);
  });

  test("a writer that cannot get the lock within the bound reports vault_busy", () => {
    const { file, store } = fresh(50);
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("a"));
    const holder = new Database(file);
    try {
      holder.exec("BEGIN IMMEDIATE");
      const started = performance.now();
      // Under an immediate transaction the change never runs: the lock is
      // taken before it. Under a deferred one it would run before the
      // update hit the lock wall, so this pins the immediate-ness.
      let called = false;
      expect(
        codeOf(() =>
          store.mutate(key, () => {
            called = true;
            return bytes("b");
          }),
        ),
      ).toBe("vault_busy");
      expect(called).toBe(false);
      // Both bounds are measured for WCLI-53, idle and at 2x and 6x CPU
      // overcommit: the wait costs 67-76 ms against the 50 ms busy timeout.
      // The ceiling's only band is a wait between 2 s and the harness
      // timeout, which is where a lock wait that never returned would land;
      // 2 s is 26x the measured maximum, so contention cannot reach it. The
      // floor is the other half, and the shape the original flake could not
      // break — contention only ever lengthens this wait, so it fails only
      // when the busy timeout stopped being applied, which returns in
      // microseconds rather than waiting at all.
      const waited = performance.now() - started;
      expect(waited).toBeGreaterThanOrEqual(50);
      expect(waited).toBeLessThan(2_000);
    } finally {
      holder.exec("ROLLBACK");
      holder.close();
    }
    expect(store.header()?.revision).toBe(1);
  });

  test("a reader that blocks the commit makes the writer roll back", () => {
    const { file, store } = fresh(50);
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("a"));
    const reader = new Database(file);
    try {
      reader.exec("BEGIN");
      reader.query("SELECT revision FROM vault").get();
      expect(codeOf(() => store.mutate(key, () => bytes("b")))).toBe(
        "vault_busy",
      );
    } finally {
      reader.exec("ROLLBACK");
      reader.close();
    }
    expect(store.header()?.revision).toBe(1);
    expect(text(store.read(key).plaintext) === "a").toBe(true);
    expect(store.mutate(key, () => bytes("b")).revision).toBe(2);
  });

  test("a writer killed inside its change leaves the committed snapshot", async () => {
    const { directory, store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes(SENTINEL));
    const worker = spawnWorker(key, ["hold", directory]);
    await untilReady(worker);
    await killed(worker);
    expect(store.header()).toEqual({
      vaultId: VAULT_ID,
      revision: 1,
      formatVersion: 1,
    });
    expect(text(store.read(key).plaintext) === SENTINEL).toBe(true);
    expect(store.mutate(key, (p) => p).revision).toBe(2);
    expect(filesContaining(directory, SENTINEL)).toEqual([]);
  });

  test("a writer killed half way through writing the file is rolled back", async () => {
    const { directory, file, store } = fresh();
    const key = generateVaultKey();
    // Large enough that the half-done update spills to the file.
    const original = new Uint8Array(1024 * 1024);
    original.set(bytes(SENTINEL), 4096);
    store.create(VAULT_ID, key, original);
    const committed = readFileSync(file);

    const worker = spawnWorker(key, ["crash", directory]);
    await untilReady(worker);
    // The file really is half-written and the journal is hot, so the test
    // is exercising recovery rather than an untouched file.
    expect(readFileSync(file).equals(committed)).toBe(false);
    expect(existsSync(`${file}-journal`)).toBe(true);
    expect(mode(`${file}-journal`)).toBe(0o600);
    expect(filesContaining(directory, SENTINEL)).toEqual([]);
    await killed(worker);

    const snapshot = store.read(key);
    expect(snapshot.revision).toBe(1);
    expect(Buffer.from(snapshot.plaintext).equals(Buffer.from(original))).toBe(
      true,
    );
    expect(existsSync(`${file}-journal`)).toBe(false);
  });

  test("a create killed part way leaves no vault, and a rerun completes", async () => {
    const { directory, file, store } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    writeFileSync(file, "", { mode: 0o600 });
    const worker = spawnWorker(generateVaultKey(), ["crash-create", directory]);
    await untilReady(worker);
    expect(statSync(file).size).toBeGreaterThan(0);
    await killed(worker);

    expect(store.header()).toBeUndefined();
    const key = generateVaultKey();
    expect(store.create(VAULT_ID, key, bytes("x")).revision).toBe(1);
    expect(store.read(key).revision).toBe(1);
  });
});

describe("T07: permissions, links and untrusted files", () => {
  function allRefuse(
    store: ReturnType<typeof fresh>["store"],
    code: string,
  ): void {
    const key = generateVaultKey();
    expect(codeOf(() => store.header())).toBe(code);
    expect(codeOf(() => store.read(key))).toBe(code);
    expect(codeOf(() => store.mutate(key, (p) => p))).toBe(code);
    expect(codeOf(() => store.create(VAULT_ID, key, bytes("x")))).toBe(code);
  }

  test("a directory that is not 0700 is refused and nothing is created in it", () => {
    const { directory, file, store } = fresh();
    mkdirSync(directory);
    chmodSync(directory, 0o755);
    allRefuse(store, "vault_store_insecure");
    expect(existsSync(file)).toBe(false);
  });

  test("a database file that is not 0600 is refused and left as it was", () => {
    const { file, store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("x"));
    chmodSync(file, 0o644);
    const before = readFileSync(file);
    allRefuse(store, "vault_store_insecure");
    expect(readFileSync(file).equals(before)).toBe(true);
    chmodSync(file, 0o600);
    expect(store.read(key).revision).toBe(1);
  });

  test("a symbolic link for the directory is refused", () => {
    const { home, directory, store } = fresh();
    const real = join(home, "elsewhere");
    mkdirSync(real, { mode: 0o700 });
    symlinkSync(real, directory);
    allRefuse(store, "vault_store_insecure");
    expect(readdirSync(real)).toEqual([]);
  });

  test("a symbolic link for the database or a sidecar is refused", () => {
    const { home, directory, file, store } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    const target = join(home, "target");
    writeFileSync(target, "untouched", { mode: 0o600 });
    symlinkSync(target, file);
    allRefuse(store, "vault_store_insecure");
    expect(readFileSync(target, "utf8")).toBe("untouched");

    const other = fresh();
    other.store.create(VAULT_ID, generateVaultKey(), bytes("x"));
    symlinkSync(target, `${other.file}-journal`);
    allRefuse(other.store, "vault_store_insecure");
    expect(readFileSync(target, "utf8")).toBe("untouched");
  });

  test("a database path that is a directory is refused", () => {
    const { directory, file, store } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    mkdirSync(file, { mode: 0o600 });
    allRefuse(store, "vault_store_insecure");
  });

  test("a directory that is not absolute and canonical is refused", () => {
    for (const directory of [
      "ward-relative-probe",
      `${root}/a/../b`,
      `${root}/./b`,
      `${join(root, "trailing")}/`,
      join(root, "nul\u0000byte"),
    ]) {
      const store = createSqliteVaultStore({ directory });
      allRefuse(store, "vault_store_insecure");
    }
    expect(existsSync(join(root, "b"))).toBe(false);
    expect(existsSync("ward-relative-probe")).toBe(false);
  });

  test("ownership, links and exact modes decide a private entry", () => {
    const entry = (
      kind: "directory" | "file" | "symlink",
      mode: number,
      uid: number,
    ): EntryStats => ({
      mode,
      uid,
      isDirectory: () => kind === "directory",
      isFile: () => kind === "file",
      isSymbolicLink: () => kind === "symlink",
    });
    expect(
      isPrivateEntry(entry("directory", 0o40700, 501), "directory", 501),
    ).toBe(true);
    expect(isPrivateEntry(entry("file", 0o100600, 501), "file", 501)).toBe(
      true,
    );
    expect(
      isPrivateEntry(entry("directory", 0o40700, 502), "directory", 501),
    ).toBe(false);
    expect(isPrivateEntry(entry("file", 0o100600, 0), "file", 501)).toBe(false);
    expect(
      isPrivateEntry(entry("file", 0o100600, 501), "file", undefined),
    ).toBe(false);
    expect(isPrivateEntry(entry("symlink", 0o120600, 501), "file", 501)).toBe(
      false,
    );
    expect(
      isPrivateEntry(entry("directory", 0o40750, 501), "directory", 501),
    ).toBe(false);
    expect(isPrivateEntry(entry("file", 0o100400, 501), "file", 501)).toBe(
      false,
    );
    expect(isPrivateEntry(entry("file", 0o40700, 501), "directory", 501)).toBe(
      false,
    );
  });

  test("a missing parent directory is a store failure, not a created path", () => {
    const store = createSqliteVaultStore({
      directory: join(root, "no-such-home", ".ward"),
    });
    expect(
      codeOf(() => store.create(VAULT_ID, generateVaultKey(), bytes("x"))),
    ).toBe("vault_store_failed");
    expect(existsSync(join(root, "no-such-home"))).toBe(false);
  });

  test("a file that is not a Ward vault is refused and left as it was", () => {
    const plant = (write: (file: string) => void) => {
      const { directory, file, store } = fresh();
      mkdirSync(directory, { mode: 0o700 });
      write(file);
      chmodSync(file, 0o600);
      return { file, store };
    };
    const cases = [
      plant((file) => writeFileSync(file, "not a database at all, just text")),
      plant((file) =>
        withRaw(file, (db) => db.exec("CREATE TABLE notes (body TEXT)")),
      ),
    ];
    for (const { file, store } of cases) {
      const before = readFileSync(file);
      allRefuse(store, "vault_store_unrecognized");
      expect(readFileSync(file).equals(before)).toBe(true);
    }
  });

  test("a WAL-mode database is refused before SQLite opens it, untouched", () => {
    const { directory, file, store } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    withRaw(file, (db) => {
      db.exec("PRAGMA journal_mode = WAL");
      db.exec("CREATE TABLE notes (body TEXT)");
      db.exec("INSERT INTO notes VALUES ('foreign data')");
    });
    for (const path of [file, `${file}-wal`, `${file}-shm`])
      if (existsSync(path)) chmodSync(path, 0o600);
    const before = readFileSync(file);
    const listing = readdirSync(directory).sort();
    // A read-write open would checkpoint the WAL and create sidecars; the
    // refusal must come from the file's own header, so nothing moves.
    allRefuse(store, "vault_store_unrecognized");
    expect(readFileSync(file).equals(before)).toBe(true);
    expect(readdirSync(directory).sort()).toEqual(listing);
  });

  test(
    "a WAL-mode database with a hot transaction is refused untouched",
    async () => {
      const { directory, file, store } = fresh();
      mkdirSync(directory, { mode: 0o700 });
      const worker = spawnWorker(generateVaultKey(), ["wal-hold", directory]);
      await untilReady(worker);
      try {
        for (const path of [file, `${file}-wal`, `${file}-shm`])
          if (existsSync(path)) chmodSync(path, 0o600);
        const before = readFileSync(file);
        const listing = readdirSync(directory).sort();
        allRefuse(store, "vault_store_unrecognized");
        expect(readFileSync(file).equals(before)).toBe(true);
        expect(readdirSync(directory).sort()).toEqual(listing);
      } finally {
        await killed(worker);
      }
    },
    { timeout: 30_000 },
  );

  test(
    "a WAL database with committed but uncheckpointed frames is refused untouched",
    async () => {
      // This is the state the header refusal exists for: the frames are
      // committed, no lock is held, so a read-write open would replay them
      // into the database before the layout check could refuse the file.
      const { directory, file, store } = fresh();
      mkdirSync(directory, { mode: 0o700 });
      const worker = spawnWorker(generateVaultKey(), ["wal-commit", directory]);
      await untilReady(worker);
      await killed(worker);
      for (const path of [file, `${file}-wal`, `${file}-shm`])
        if (existsSync(path)) chmodSync(path, 0o600);
      const before = readFileSync(file);
      const walBefore = existsSync(`${file}-wal`)
        ? readFileSync(`${file}-wal`)
        : undefined;
      const listing = readdirSync(directory).sort();
      allRefuse(store, "vault_store_unrecognized");
      expect(readFileSync(file).equals(before)).toBe(true);
      if (walBefore !== undefined)
        expect(readFileSync(`${file}-wal`).equals(walBefore)).toBe(true);
      expect(readdirSync(directory).sort()).toEqual(listing);
    },
    { timeout: 30_000 },
  );

  test("a Ward vault converted to WAL mode is refused as a recovery condition", () => {
    const { file, store } = fresh();
    const key = generateVaultKey();
    store.create(VAULT_ID, key, bytes("x"));
    withRaw(file, (db) => db.exec("PRAGMA journal_mode = WAL"));
    for (const path of [`${file}-wal`, `${file}-shm`])
      if (existsSync(path)) chmodSync(path, 0o600);
    allRefuse(store, "vault_store_unrecognized");
  });

  test("a foreign rollback-journal database is refused without re-journaling it", () => {
    const { directory, file, store } = fresh();
    mkdirSync(directory, { mode: 0o700 });
    withRaw(file, (db) => {
      db.exec("PRAGMA journal_mode = PERSIST");
      db.exec("CREATE TABLE notes (body TEXT)");
      db.exec("INSERT INTO notes VALUES ('foreign data')");
    });
    for (const path of [file, `${file}-journal`])
      if (existsSync(path)) chmodSync(path, 0o600);
    const before = readFileSync(file);
    const listing = readdirSync(directory).sort();
    allRefuse(store, "vault_store_unrecognized");
    expect(readFileSync(file).equals(before)).toBe(true);
    expect(readdirSync(directory).sort()).toEqual(listing);
  });

  test("a Ward vault with an altered layout is refused", () => {
    const alterations = [
      "PRAGMA user_version = 2",
      "CREATE TRIGGER copy AFTER UPDATE ON vault BEGIN SELECT 1; END",
      "CREATE INDEX by_id ON vault (vault_id)",
    ];
    for (const alteration of alterations) {
      const { file, store } = fresh();
      const key = generateVaultKey();
      store.create(VAULT_ID, key, bytes("x"));
      withRaw(file, (db) => db.exec(alteration));
      expect(codeOf(() => store.read(key))).toBe("vault_store_unrecognized");
      expect(codeOf(() => store.header())).toBe("vault_store_unrecognized");
    }
  });

  test("oversized or malformed stored fields are refused before use", () => {
    const tamper = [
      {
        sql: `UPDATE vault SET ciphertext = zeroblob(${envelopeLimits.maxPlaintextBytes + 1})`,
        code: "vault_record_too_large",
      },
      {
        sql: "UPDATE vault SET nonce = zeroblob(11)",
        code: "vault_record_malformed",
      },
      {
        sql: "UPDATE vault SET tag = zeroblob(17)",
        code: "vault_record_malformed",
      },
      {
        sql: "UPDATE vault SET format_version = 2",
        code: "vault_format_unsupported",
      },
      {
        sql: "UPDATE vault SET vault_id = 'not-a-uuid'",
        code: "vault_record_malformed",
      },
      { sql: "UPDATE vault SET revision = 0", code: "vault_record_malformed" },
      { sql: "DELETE FROM vault", code: "vault_store_unrecognized" },
    ];
    for (const { sql, code } of tamper) {
      const { file, store } = fresh();
      const key = generateVaultKey();
      store.create(VAULT_ID, key, bytes("x"));
      withRaw(file, (db) => db.exec(sql));
      expect([sql, codeOf(() => store.read(key))]).toEqual([sql, code]);
    }
  });

  test("no store diagnostic names the vault's path", () => {
    const { directory, store } = fresh();
    mkdirSync(directory);
    chmodSync(directory, 0o755);
    const failures = [
      thrown(() => store.header()),
      thrown(() =>
        createSqliteVaultStore({
          directory: join(root, "no-such-home", ".ward"),
        }).create(VAULT_ID, generateVaultKey(), bytes("x")),
      ),
    ];
    for (const failure of failures) {
      expect(failure).toBeInstanceOf(WardError);
      const rendered = JSON.stringify(errorEnvelope(failure as WardError));
      expect(rendered.includes(root)).toBe(false);
    }
  });
});
