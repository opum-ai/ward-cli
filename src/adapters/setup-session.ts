// The serialization and resume record for `ward setup` (WCLI-20). The
// KeyProvider's create is check-then-write and not atomic in the credential
// store (docs/adr/0001), so setup takes an exclusive lock in the vault
// directory before touching the key, and records the pending vault id in a
// journal before the key is created. An interrupted setup then resumes with
// the same vault id and the same key account instead of orphaning a
// keychain item, and a rerun at any point either completes the same setup
// or reports the state it finds.
//
// The lock is flock(2) on a persistent lock file, through libc on macOS
// and on Linux (WCLI-152): the kernel arbitrates it and releases it when
// the holding process dies, so a crash needs no reaping and two setups can
// never both hold it. The file is never unlinked while held (unlinking a
// flock file re-opens the two-file race); its content is advisory, the last
// holder's pid. Any other platform fails closed: no platform but these two
// is qualified, and the O_EXCL file with dead-pid reaping that used to cover
// them had a measured check-then-delete race (WCLI-20 review: 12 overlapping
// holder pairs in 20 rounds).
//
// The journal is removed only when the vault exists, so it survives every
// failure short of success.
import { dlopen } from "bun:ffi";
import {
  closeSync,
  constants as fileConstants,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readFileSync,
  rmSync,
  type Stats,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { WardError } from "../contract/errors.ts";
import { isVaultId } from "../domain/envelope.ts";
import { isPrivateEntry, prepareVaultDirectory } from "./sqlite-vault-store.ts";

export const setupLockFileName = "setup.lock";
export const setupJournalFileName = "setup.json";
// A hostile journal cannot make Ward read past this.
const maxJournalBytes = 1024;

// flock(2) operation bits from <sys/file.h>.
const LOCK_EX = 2;
const LOCK_NB = 4;

function errnoCode(error: unknown): unknown {
  return typeof error === "object" && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

// fsync on a directory persists the entry changes inside it, so a power
// loss cannot drop a journal whose bytes were fsynced (the journal's
// purpose is exactly to survive the key write that follows it).
function fsyncDirectory(path: string): void {
  let fd: number;
  try {
    fd = openSync(path, fileConstants.O_RDONLY);
  } catch {
    throw new WardError("vault_store_failed");
  }
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

// The C library that exports flock(2), by platform. Unsupported platforms
// have none and fail closed.
function libcPath(): string {
  if (process.platform === "darwin") return "/usr/lib/libSystem.B.dylib";
  if (process.platform === "linux") return "libc.so.6";
  throw new WardError("vault_key_store_unsupported");
}

// Takes the lock and returns the held-open fd, whose close releases it. The
// lock file is never unlinked.
function acquireFlock(lockPath: string, uid: number | undefined): number {
  const library = libcPath();
  let existing: Stats | undefined;
  try {
    existing = lstatSync(lockPath);
  } catch (error) {
    if (errnoCode(error) !== "ENOENT")
      throw new WardError("vault_store_failed");
  }
  if (existing !== undefined && !isPrivateEntry(existing, "file", uid))
    throw new WardError("vault_store_insecure");
  let fd: number;
  try {
    fd = openSync(
      lockPath,
      fileConstants.O_CREAT | fileConstants.O_RDWR | fileConstants.O_NOFOLLOW,
      0o600,
    );
  } catch {
    throw new WardError("vault_store_failed");
  }
  let flock: (fd: number, operation: number) => number;
  try {
    flock = dlopen(library, {
      flock: { args: ["int", "int"], returns: "int" },
    }).symbols.flock as (fd: number, operation: number) => number;
  } catch {
    // No usable C library to ask the kernel through: fail closed, never
    // fall back to a lock the kernel does not arbitrate.
    closeSync(fd);
    throw new WardError("vault_store_failed");
  }
  // A non-contention flock failure is indistinguishable here and reports
  // setup_in_progress too; fail-closed either way.
  if (flock(fd, LOCK_EX | LOCK_NB) !== 0) {
    closeSync(fd);
    throw new WardError("setup_in_progress");
  }
  try {
    const written = writeSync(fd, `${process.pid}\n`);
    ftruncateSync(fd, written);
    fsyncSync(fd);
  } catch {
    // Advisory content only; the lock itself is already held.
  }
  return fd;
}

export interface SetupSession {
  // The vault id an interrupted setup recorded, if any. A present but
  // unreadable journal is refused, never overwritten.
  journalVaultId(): string | undefined;
  // Durably records the vault id, before any key write.
  recordVaultId(vaultId: string): void;
  // Releases the lock, keeping the journal for a rerun.
  release(): void;
  // Removes the journal and releases the lock: the vault exists.
  complete(): void;
}

export function acquireSetupSession(directory: string): SetupSession {
  // The vault directory is created here, so a setup that fails before any
  // key action still leaves a private, empty directory and nothing else.
  prepareVaultDirectory(directory, process.getuid?.());
  const uid = process.getuid?.();
  const lockPath = join(directory, setupLockFileName);
  const journalPath = join(directory, setupJournalFileName);
  let released = false;
  const lockFd = acquireFlock(lockPath, uid);

  function remove(path: string): void {
    try {
      rmSync(path);
    } catch (error) {
      if (errnoCode(error) !== "ENOENT")
        throw new WardError("vault_store_failed");
    }
  }

  function releaseLock(): void {
    if (released) return;
    released = true;
    closeSync(lockFd);
  }

  return {
    journalVaultId() {
      let stats: Stats;
      try {
        stats = lstatSync(journalPath);
      } catch (error) {
        if (errnoCode(error) === "ENOENT") return undefined;
        throw new WardError("vault_store_failed");
      }
      if (!isPrivateEntry(stats, "file", uid))
        throw new WardError("vault_store_insecure");
      if (stats.size > maxJournalBytes)
        throw new WardError("setup_state_invalid");
      try {
        const parsed = JSON.parse(readFileSync(journalPath, "utf8")) as {
          vaultId?: unknown;
        };
        if (
          typeof parsed === "object" &&
          parsed !== null &&
          typeof parsed.vaultId === "string" &&
          isVaultId(parsed.vaultId)
        )
          return parsed.vaultId;
      } catch {
        // Fall through: a present but unreadable journal is refused.
      }
      throw new WardError("setup_state_invalid");
    },

    recordVaultId(vaultId) {
      if (!isVaultId(vaultId)) throw new WardError("vault_record_malformed");
      let fd: number;
      try {
        fd = openSync(
          journalPath,
          fileConstants.O_CREAT |
            fileConstants.O_TRUNC |
            fileConstants.O_RDWR |
            fileConstants.O_NOFOLLOW,
          0o600,
        );
      } catch {
        throw new WardError("vault_store_failed");
      }
      try {
        try {
          writeSync(fd, JSON.stringify({ schemaVersion: 1, vaultId }));
          fsyncSync(fd);
        } catch {
          throw new WardError("vault_store_failed");
        }
      } finally {
        closeSync(fd);
      }
      fsyncDirectory(directory);
    },

    release() {
      releaseLock();
    },

    complete() {
      remove(journalPath);
      releaseLock();
      fsyncDirectory(directory);
    },
  };
}
