// The serialization and resume record for `ward setup` (WCLI-20). The
// KeyProvider's create is check-then-write and not atomic in the credential
// store (docs/adr/0001), so setup takes an exclusive lock file in the vault
// directory before touching the key, and records the pending vault id in a
// journal before the key is created. An interrupted setup then resumes with
// the same vault id and the same key account instead of orphaning a
// keychain item, and a rerun at any point either completes the same setup
// or reports the state it finds.
//
// The lock is the file's existence, taken with O_EXCL. A crash leaves the
// file behind; the next setup removes it when the recorded pid is dead and
// reports setup_in_progress otherwise. The journal is removed only when the
// vault exists, so it survives every failure short of success.
import {
  closeSync,
  constants as fileConstants,
  fsyncSync,
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

function errnoCode(error: unknown): unknown {
  return typeof error === "object" && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errnoCode(error) !== "ESRCH";
  }
}

// Removes a lock whose holder is gone: the recorded pid is dead, or the
// content is unreadable (a crash between creating the file and writing it).
// A readable pid that is alive, or a lock that fails the privacy checks, is
// never touched.
function clearStaleLock(lockPath: string, uid: number | undefined): void {
  let stats: Stats;
  try {
    stats = lstatSync(lockPath);
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return;
    throw new WardError("vault_store_failed");
  }
  if (!isPrivateEntry(stats, "file", uid))
    throw new WardError("vault_store_insecure");
  if (stats.size > maxJournalBytes) throw new WardError("setup_in_progress");
  const content = readFileSync(lockPath, "utf8").trim();
  const pid = /^\d+$/.test(content) ? Number(content) : undefined;
  if (pid !== undefined && isAlive(pid))
    throw new WardError("setup_in_progress");
  try {
    rmSync(lockPath);
  } catch (error) {
    if (errnoCode(error) !== "ENOENT")
      throw new WardError("vault_store_failed");
  }
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
  let held = true;

  function remove(path: string): void {
    try {
      rmSync(path);
    } catch (error) {
      if (errnoCode(error) !== "ENOENT")
        throw new WardError("vault_store_failed");
    }
  }

  for (let attempt = 0; held; attempt++) {
    let fd: number;
    try {
      fd = openSync(
        lockPath,
        fileConstants.O_CREAT |
          fileConstants.O_EXCL |
          fileConstants.O_RDWR |
          fileConstants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (errnoCode(error) !== "EEXIST")
        throw new WardError("vault_store_failed");
      clearStaleLock(lockPath, uid);
      if (attempt > 0) throw new WardError("setup_in_progress");
      continue;
    }
    try {
      writeSync(fd, `${process.pid}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    break;
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
        writeSync(fd, JSON.stringify({ schemaVersion: 1, vaultId }));
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    },

    release() {
      held = false;
      remove(lockPath);
    },

    complete() {
      held = false;
      remove(journalPath);
      remove(lockPath);
    },
  };
}
