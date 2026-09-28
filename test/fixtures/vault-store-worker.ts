// A second Ward process for test/vault-store.test.ts (WCLI-6). It reaches
// the store only, never a credential store. The synthetic key arrives in
// WARD_TEST_KEY_HEX. Modes:
//
//   append <dir> <label> <count>  mutate count times, appending "<label>-<i>;"
//   hold <dir>                    mutate, report "ready", then block inside
//                                 the change until killed
//   crash <dir>                   overwrite the sealed row in a raw immediate
//                                 transaction with the store's journal mode,
//                                 spill it to the file, report "ready", then
//                                 block until killed
//   crash-create <dir>            the same against an empty ward.db, part way
//                                 through laying down a vault
//   create <dir>                  create the vault once and report the outcome
//   wal-hold <dir>                make ward.db a WAL database with a hot
//                                 transaction, report "ready", then block
//                                 until killed
import { Database } from "bun:sqlite";
import { writeSync } from "node:fs";
import { join } from "node:path";
import { createSqliteVaultStore } from "../../src/adapters/sqlite-vault-store.ts";
import { WardError } from "../../src/contract/errors.ts";

const [mode, directory, label, count] = process.argv.slice(2);
const key = new Uint8Array(
  Buffer.from(process.env.WARD_TEST_KEY_HEX ?? "", "hex"),
);

function blockForever(): never {
  const cell = new Int32Array(new SharedArrayBuffer(4));
  for (;;) Atomics.wait(cell, 0, 0);
}

if (directory === undefined) throw new Error("usage: <mode> <dir> ...");

if (mode === "append") {
  const store = createSqliteVaultStore({ directory });
  const outcome = { ok: 0, busy: 0, other: [] as string[] };
  for (let i = 0; i < Number(count); i++) {
    try {
      store.mutate(key, (plaintext) =>
        Buffer.concat([plaintext, Buffer.from(`${label}-${i};`)]),
      );
      outcome.ok++;
    } catch (error) {
      if (error instanceof WardError && error.code === "vault_busy")
        outcome.busy++;
      else
        outcome.other.push(
          error instanceof WardError ? error.code : "not-a-ward-error",
        );
    }
  }
  writeSync(1, `${JSON.stringify(outcome)}\n`);
} else if (mode === "hold") {
  createSqliteVaultStore({ directory }).mutate(key, () => {
    writeSync(1, "ready\n");
    blockForever();
  });
} else if (mode === "crash" || mode === "crash-create") {
  const db = new Database(join(directory, "ward.db"));
  db.exec("PRAGMA journal_mode = DELETE");
  db.exec("PRAGMA synchronous = FULL");
  // A tiny page cache and spill threshold force the half-done write out to
  // the database file before any commit, so the kill lands on a genuinely
  // half-written file.
  db.exec("PRAGMA cache_size = 2");
  db.exec("PRAGMA cache_spill = 2");
  db.exec("BEGIN IMMEDIATE");
  if (mode === "crash")
    db.exec(
      "UPDATE vault SET ciphertext = randomblob(length(ciphertext)), revision = revision + 1 WHERE slot = 1",
    );
  else {
    db.exec(`PRAGMA application_id = ${0x57415244}`);
    db.exec("PRAGMA user_version = 1");
    db.exec("CREATE TABLE vault (slot INTEGER PRIMARY KEY, body BLOB)");
    db.exec("INSERT INTO vault VALUES (1, randomblob(1048576))");
  }
  writeSync(1, "ready\n");
  blockForever();
} else if (mode === "create") {
  const store = createSqliteVaultStore({ directory });
  try {
    store.create(
      process.env.WARD_TEST_VAULT_ID ?? "",
      key,
      Buffer.from("seed"),
    );
    writeSync(1, `${JSON.stringify({ outcome: "created" })}\n`);
  } catch (error) {
    writeSync(
      1,
      `${JSON.stringify({
        outcome: error instanceof WardError ? error.code : "not-a-ward-error",
      })}\n`,
    );
  }
} else if (mode === "wal-hold") {
  const db = new Database(join(directory, "ward.db"));
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA wal_autocheckpoint = 0");
  db.exec("CREATE TABLE notes (body TEXT)");
  db.exec("BEGIN IMMEDIATE");
  db.exec("INSERT INTO notes VALUES ('foreign')");
  writeSync(1, "ready\n");
  blockForever();
} else {
  throw new Error("unknown mode");
}
