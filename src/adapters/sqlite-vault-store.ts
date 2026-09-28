import { Database, constants as sqlite } from "bun:sqlite";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  constants as fileConstants,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";
import type {
  VaultChange,
  VaultHeader,
  VaultSnapshot,
  VaultStore,
} from "../application/vault-store.ts";
import { WardError } from "../contract/errors.ts";
import {
  envelopeLimits,
  open,
  parseHeader,
  type SealedRecord,
  seal,
} from "../domain/envelope.ts";

// The vault as one sealed row in ward.db, inside a private directory
// (spec §6.1-6.3, docs/adr/0001). SQLite receives ciphertext and the opaque
// header fields only: no plaintext column, index or full-text table exists,
// and no SQL tracing is ever enabled.
//
// Every call opens its own connection and closes it before returning, so no
// lock or handle outlives the call. Mutations run in an immediate
// transaction, so concurrent Ward processes queue on SQLite's lock for at
// most the busy timeout and then report vault_busy; neither update is lost.
// The rollback journal and FULL synchronous commits mean a writer killed at
// any point leaves the last committed snapshot, which the next connection
// restores from the journal.
//
// Not claimed: rollback resistance (an older copy of ward.db still opens),
// forensic deletion (journals and freed pages can keep old ciphertext), or a
// boundary against code running as this user. The directory and file checks
// are made on the final path components before SQLite opens them; a
// same-user process could still race them, which the threat model already
// concedes (docs/adr/0002).

export const vaultFileName = "ward.db";
export const defaultBusyTimeoutMs = 5_000;

// SQLite creates these beside the database with the database's own mode.
// Ward uses only the rollback journal; the others are checked in case a
// foreign writer left them.
const sidecarSuffixes = ["-journal", "-wal", "-shm"] as const;

// "WARD" in ASCII. Together with the layout version and the exact schema it
// is how Ward recognizes its own file, and refuses to touch anyone else's.
const applicationId = 0x57415244;
const layoutVersion = 1;
const createTable =
  "CREATE TABLE vault (slot INTEGER PRIMARY KEY CHECK (slot = 1), format_version INTEGER NOT NULL, vault_id TEXT NOT NULL, revision INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, tag BLOB NOT NULL) STRICT";

export interface EntryStats {
  mode: number;
  uid: number;
  isDirectory(): boolean;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

// Exact modes rather than "no group or other bits": a looser mode is refused,
// never repaired, so Ward does not paper over something else touching it.
export function isPrivateEntry(
  stats: EntryStats,
  kind: "directory" | "file",
  uid: number | undefined,
): boolean {
  if (uid === undefined || stats.uid !== uid || stats.isSymbolicLink())
    return false;
  if (kind === "directory")
    return stats.isDirectory() && (stats.mode & 0o777) === 0o700;
  return stats.isFile() && (stats.mode & 0o777) === 0o600;
}

interface Location {
  directory: string;
  file: string;
}

function errnoCode(error: unknown): unknown {
  return typeof error === "object" && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

// The directory comes from the composition root, never from a vault ID or
// an alias. It must already be absolute and canonical, so nothing the caller
// passes is resolved relative to the working directory or through "..".
//
// Links above the vault directory are the user's own layout (a home reached
// through a link, or macOS's /var) and are resolved here, because SQLite's
// NOFOLLOW refuses a link anywhere in the path. The vault directory and its
// files must not themselves be links.
function locate(directory: string): Location {
  if (
    typeof directory !== "string" ||
    directory.includes("\0") ||
    !isAbsolute(directory) ||
    normalize(directory) !== directory ||
    directory.endsWith("/")
  )
    throw new WardError("vault_store_insecure");
  let parent: string;
  try {
    parent = realpathSync(dirname(directory));
  } catch (error) {
    // A missing parent is reported by the operation that needs it: absent
    // for a read, a store failure for create.
    if (errnoCode(error) !== "ENOENT")
      throw new WardError("vault_store_failed");
    parent = dirname(directory);
  }
  const resolved = join(parent, basename(directory));
  return { directory: resolved, file: join(resolved, vaultFileName) };
}

function lstatOrAbsent(path: string): EntryStats | undefined {
  try {
    return lstatSync(path);
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return undefined;
    throw new WardError("vault_store_failed");
  }
}

function inspect(
  location: Location,
  uid: number | undefined,
): "absent" | "directory" | "file" {
  const directory = lstatOrAbsent(location.directory);
  if (directory === undefined) return "absent";
  if (!isPrivateEntry(directory, "directory", uid))
    throw new WardError("vault_store_insecure");
  for (const suffix of sidecarSuffixes) {
    const sidecar = lstatOrAbsent(location.file + suffix);
    if (sidecar !== undefined && !isPrivateEntry(sidecar, "file", uid))
      throw new WardError("vault_store_insecure");
  }
  const file = lstatOrAbsent(location.file);
  if (file === undefined) return "directory";
  if (!isPrivateEntry(file, "file", uid))
    throw new WardError("vault_store_insecure");
  return "file";
}

// An inherited ACL (macOS) can grant access beyond the 0700/0600 modes, so
// entries Ward itself creates get their ACLs stripped. Detecting an ACL on
// an entry that already exists would need a subprocess read, so pre-existing
// entries are checked for mode, ownership and links only, and an ACL the
// user placed there stays (documented in docs/adr/0001). Off macOS this is a
// no-op: the Linux ACL story belongs to the Linux platform work (WCLI-21).
function stripInheritedAcl(path: string): void {
  if (process.platform !== "darwin") return;
  const result = spawnSync("/bin/chmod", ["-N", path]);
  if (result.error !== undefined || result.status !== 0)
    throw new WardError("vault_store_insecure");
}

// Created with its final mode, never chmod-ed into it afterwards. A umask
// that strips the owner's own bits leaves a mode that inspect() refuses.
function prepare(location: Location, uid: number | undefined): void {
  const state = inspect(location, uid);
  if (state === "absent") {
    try {
      mkdirSync(location.directory, { mode: 0o700 });
    } catch (error) {
      if (errnoCode(error) !== "EEXIST")
        throw new WardError("vault_store_failed");
    }
    stripInheritedAcl(location.directory);
  }
  if (state !== "file") {
    let created = false;
    try {
      closeSync(
        openSync(
          location.file,
          fileConstants.O_CREAT |
            fileConstants.O_EXCL |
            fileConstants.O_RDWR |
            fileConstants.O_NOFOLLOW,
          0o600,
        ),
      );
      created = true;
    } catch (error) {
      if (errnoCode(error) !== "EEXIST")
        throw new WardError("vault_store_failed");
    }
    if (created) stripInheritedAcl(location.file);
  }
  if (inspect(location, uid) !== "file")
    throw new WardError("vault_store_failed");
}

// SQLite's messages can carry paths, so only its result code is read.
function storeError(error: unknown): WardError {
  if (error instanceof WardError) return error;
  const code = errnoCode(error);
  if (typeof code === "string") {
    if (code.startsWith("SQLITE_BUSY") || code.startsWith("SQLITE_LOCKED"))
      return new WardError("vault_busy");
    if (code === "SQLITE_CANTOPEN_SYMLINK")
      return new WardError("vault_store_insecure");
    if (code.startsWith("SQLITE_NOTADB") || code.startsWith("SQLITE_CORRUPT"))
      return new WardError("vault_store_unrecognized");
  }
  return new WardError("vault_store_failed");
}

// What a VaultChange threw, carried past the SQLite error mapping unchanged.
class ChangeFailure {
  constructor(readonly error: unknown) {}
}

function connect(file: string, busyTimeoutMs: number): Database {
  let db: Database;
  try {
    // Never SQLITE_OPEN_CREATE: only prepare() makes the file. NOFOLLOW
    // refuses a symbolic link swapped in after inspect().
    db = new Database(
      file,
      sqlite.SQLITE_OPEN_READWRITE | sqlite.SQLITE_OPEN_NOFOLLOW,
    );
  } catch (error) {
    throw storeError(error);
  }
  try {
    db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
    // A schema read from a file is not trusted to run functions.
    db.exec("PRAGMA trusted_schema = OFF");
    db.exec("PRAGMA temp_store = MEMORY");
    db.exec("PRAGMA synchronous = FULL");
  } catch (error) {
    db.close();
    throw storeError(error);
  }
  return db;
}

// The rollback journal is part of Ward's layout: a Ward vault someone
// converted to WAL is healed back on the first writing connection. Called
// only after layoutOf() has accepted the file, so a foreign database is
// refused before any setting that writes is applied.
function healJournalMode(db: Database): void {
  const mode = db.query("PRAGMA journal_mode = DELETE").get() as {
    journal_mode?: unknown;
  } | null;
  if (mode?.journal_mode !== "delete")
    throw new WardError("vault_store_unrecognized");
}

function pragmaNumber(db: Database, name: string): unknown {
  const row = db.query(`PRAGMA ${name}`).get() as Record<
    string,
    unknown
  > | null;
  return row?.[name];
}

// "empty" is a file no vault was ever committed to, including one whose
// creation was interrupted and rolled back. Anything that is neither empty
// nor exactly Ward's layout is refused.
function layoutOf(db: Database): "empty" | "ward" {
  const id = pragmaNumber(db, "application_id");
  const version = pragmaNumber(db, "user_version");
  const schema = db
    .query("SELECT type, name, tbl_name, sql FROM sqlite_schema")
    .all() as Record<string, unknown>[];
  if (id === 0 && version === 0 && schema.length === 0) return "empty";
  const [entry] = schema;
  if (
    id === applicationId &&
    version === layoutVersion &&
    schema.length === 1 &&
    entry?.type === "table" &&
    entry.name === "vault" &&
    entry.tbl_name === "vault" &&
    entry.sql === createTable
  )
    return "ward";
  throw new WardError("vault_store_unrecognized");
}

function requireVault(db: Database): void {
  if (layoutOf(db) !== "ward") throw new WardError("vault_not_found");
}

function readHeader(db: Database): VaultHeader {
  const row = db
    .query(
      "SELECT format_version, vault_id, revision FROM vault WHERE slot = 1",
    )
    .get() as Record<string, unknown> | null;
  if (row === null) throw new WardError("vault_store_unrecognized");
  const header = parseHeader({
    formatVersion: row.format_version,
    vaultId: row.vault_id,
    revision: row.revision,
  });
  return { vaultId: header.vaultId, revision: header.revision };
}

// Lengths are read before the blobs, so an oversized value in a hostile file
// is refused without being loaded.
function readRecord(db: Database): SealedRecord {
  const sizes = db
    .query(
      "SELECT length(nonce) AS nonce, length(ciphertext) AS ciphertext, length(tag) AS tag FROM vault WHERE slot = 1",
    )
    .get() as Record<string, unknown> | null;
  if (sizes === null) throw new WardError("vault_store_unrecognized");
  if (
    sizes.nonce !== envelopeLimits.nonceBytes ||
    sizes.tag !== envelopeLimits.tagBytes ||
    typeof sizes.ciphertext !== "number"
  )
    throw new WardError("vault_record_malformed");
  if (sizes.ciphertext > envelopeLimits.maxPlaintextBytes)
    throw new WardError("vault_record_too_large");
  const row = db
    .query(
      "SELECT format_version, vault_id, revision, nonce, ciphertext, tag FROM vault WHERE slot = 1",
    )
    .get() as Record<string, unknown> | null;
  if (row === null) throw new WardError("vault_store_unrecognized");
  const header = parseHeader({
    formatVersion: row.format_version,
    vaultId: row.vault_id,
    revision: row.revision,
  });
  // open() checks that each is a Uint8Array of the right length.
  return {
    ...header,
    nonce: row.nonce as Uint8Array,
    ciphertext: row.ciphertext as Uint8Array,
    tag: row.tag as Uint8Array,
  };
}

function sealedValues(record: SealedRecord) {
  return [
    record.formatVersion,
    record.vaultId,
    record.revision,
    record.nonce,
    record.ciphertext,
    record.tag,
  ] as const;
}

export function createSqliteVaultStore(options: {
  directory: string;
  busyTimeoutMs?: number;
}): VaultStore {
  const busyTimeoutMs = options.busyTimeoutMs ?? defaultBusyTimeoutMs;
  if (
    !Number.isSafeInteger(busyTimeoutMs) ||
    busyTimeoutMs < 0 ||
    busyTimeoutMs > 60_000
  )
    throw new RangeError("busyTimeoutMs must be an integer from 0 to 60000");
  const uid = process.getuid?.();

  function withConnection<T>(location: Location, run: (db: Database) => T): T {
    const db = connect(location.file, busyTimeoutMs);
    try {
      return run(db);
    } catch (error) {
      if (error instanceof ChangeFailure) throw error.error;
      throw storeError(error);
    } finally {
      db.close();
    }
  }

  // An existing vault only: nothing here creates a directory or a file.
  function withVault<T>(run: (db: Database) => T): T {
    const location = locate(options.directory);
    if (inspect(location, uid) !== "file")
      throw new WardError("vault_not_found");
    return withConnection(location, run);
  }

  return {
    header() {
      const location = locate(options.directory);
      if (inspect(location, uid) !== "file") return undefined;
      return withConnection(location, (db) =>
        db
          .transaction(() =>
            layoutOf(db) === "ward" ? readHeader(db) : undefined,
          )
          .deferred(),
      );
    },

    create(vaultId, key, plaintext) {
      // Sealed first, so a bad key, ID or plaintext is refused before
      // anything is created on disk.
      const sealed = seal(key, { vaultId, revision: 1 }, plaintext);
      const location = locate(options.directory);
      prepare(location, uid);
      // The layout check runs before the journal heal, so a foreign database
      // is refused untouched. The schema, the row and the file's identity
      // commit together or not at all, and a second create waits on the lock
      // and then finds the vault.
      return withConnection(location, (db) => {
        if (layoutOf(db) === "ward") throw new WardError("vault_exists");
        healJournalMode(db);
        return db
          .transaction(() => {
            if (layoutOf(db) === "ward") throw new WardError("vault_exists");
            db.exec(`PRAGMA application_id = ${applicationId}`);
            db.exec(`PRAGMA user_version = ${layoutVersion}`);
            db.exec(createTable);
            db.query(
              "INSERT INTO vault (slot, format_version, vault_id, revision, nonce, ciphertext, tag) VALUES (1, ?, ?, ?, ?, ?, ?)",
            ).run(...sealedValues(sealed));
            return { vaultId: sealed.vaultId, revision: sealed.revision };
          })
          .immediate();
      });
    },

    read(key) {
      const record = withVault((db) =>
        db
          .transaction(() => {
            requireVault(db);
            return readRecord(db);
          })
          .deferred(),
      );
      const plaintext = open(key, record);
      return {
        vaultId: record.vaultId,
        revision: record.revision,
        plaintext,
      } satisfies VaultSnapshot;
    },

    mutate(key, change: VaultChange) {
      // The layout check and the journal heal run before the immediate
      // transaction; the transaction itself re-checks the layout.
      return withVault((db) => {
        requireVault(db);
        healJournalMode(db);
        return db
          .transaction(() => {
            requireVault(db);
            const current = readRecord(db);
            const plaintext = open(key, current);
            let sealed: SealedRecord;
            try {
              let next: unknown;
              try {
                next = change(plaintext);
              } catch (error) {
                throw new ChangeFailure(error);
              }
              // A change that returns a promise is refused by seal() as a
              // malformed record: nothing can be awaited in here.
              sealed = seal(
                key,
                { vaultId: current.vaultId, revision: current.revision + 1 },
                next as Uint8Array,
              );
            } finally {
              plaintext.fill(0);
            }
            const result = db
              .query(
                "UPDATE vault SET format_version = ?, vault_id = ?, revision = ?, nonce = ?, ciphertext = ?, tag = ? WHERE slot = 1 AND revision = ?",
              )
              .run(...sealedValues(sealed), current.revision);
            if (result.changes !== 1) throw new WardError("vault_store_failed");
            return { vaultId: sealed.vaultId, revision: sealed.revision };
          })
          .immediate();
      });
    },
  };
}
