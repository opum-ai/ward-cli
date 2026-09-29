// The backup file on disk (spec §10, docs/adr/0006).
//
// Created in one step with owner-only mode and never replaced: the file is
// opened with O_CREAT|O_EXCL|O_NOFOLLOW at mode 0600, so an existing path, a
// symbolic link and a directory are each refused rather than written
// through, and only the container's ciphertext is ever written — no
// plaintext copy exists at any point. A write that fails partway removes the
// file it created, best effort, so the path never holds half a backup for
// someone to trust.
//
// Reads are bounded before the bytes are loaded: the file's size is checked
// from its stats, and again from the open descriptor because the path can be
// replaced between the two, and the read is capped at the bound. Ward reads
// only a regular file, and only one it can open without following a link.
import {
  closeSync,
  constants as fileConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import type { BackupFiles } from "../application/backup.ts";
import { WardError } from "../contract/errors.ts";
import { stripInheritedAcl } from "./inherited-acl.ts";

function errnoCode(error: unknown): unknown {
  return typeof error === "object" && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

function isLink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

export function createBackupFiles(): BackupFiles {
  return {
    create(path, bytes) {
      let fd: number;
      try {
        fd = openSync(
          path,
          fileConstants.O_CREAT |
            fileConstants.O_EXCL |
            fileConstants.O_WRONLY |
            fileConstants.O_NOFOLLOW,
          0o600,
        );
      } catch (error) {
        if (errnoCode(error) === "EEXIST") {
          // O_EXCL reports a symlink at the path the same way it reports a
          // file or a directory. They are different facts, and the catalog
          // says which one the caller is dealing with: a link is a path Ward
          // will not write through, while anything else is simply occupied.
          throw new WardError(
            isLink(path) ? "backup_file_unwritable" : "backup_file_exists",
          );
        }
        throw new WardError("backup_file_unwritable");
      }
      // The file inherits its directory's ACL on macOS, and 0600 does not
      // stop an inherited grant; the same strip the vault store applies.
      if (!stripInheritedAcl(path)) {
        try {
          closeSync(fd);
        } catch {
          // The failure that matters is the ACL's.
        }
        try {
          unlinkSync(path);
        } catch {
          // Best effort, as below.
        }
        throw new WardError("backup_file_unwritable");
      }
      try {
        let written = 0;
        while (written < bytes.length) {
          written += writeSync(fd, bytes, written, bytes.length - written);
        }
        // A backup is worth flushing before its path is reported as written.
        fsyncSync(fd);
      } catch {
        try {
          closeSync(fd);
        } catch {
          // The failure that matters is the write's.
        }
        try {
          unlinkSync(path);
        } catch {
          // Best effort: a partial file that cannot be removed still fails
          // the backup it belonged to.
        }
        throw new WardError("backup_file_unwritable");
      }
      closeSync(fd);
    },

    read(path, maxBytes) {
      let size: number;
      try {
        const stats = lstatSync(path);
        if (!stats.isFile() || stats.isSymbolicLink())
          throw new WardError("backup_file_unreadable");
        size = stats.size;
      } catch (error) {
        if (error instanceof WardError) throw error;
        if (errnoCode(error) === "ENOENT")
          throw new WardError("backup_not_found");
        throw new WardError("backup_file_unreadable");
      }
      if (size > maxBytes) throw new WardError("backup_too_large");

      let fd: number;
      try {
        // O_NONBLOCK is not about regular files, which ignore it: a FIFO
        // swapped in between the lstat above and this open would otherwise
        // block forever with no writer, where a refusal is the answer Ward
        // owes the caller.
        fd = openSync(
          path,
          fileConstants.O_RDONLY |
            fileConstants.O_NOFOLLOW |
            fileConstants.O_NONBLOCK,
        );
      } catch (error) {
        if (errnoCode(error) === "ENOENT")
          throw new WardError("backup_not_found");
        throw new WardError("backup_file_unreadable");
      }
      try {
        const opened = fstatSync(fd);
        if (!opened.isFile()) throw new WardError("backup_file_unreadable");
        if (opened.size > maxBytes) throw new WardError("backup_too_large");
        const contents = new Uint8Array(opened.size);
        let read = 0;
        while (read < contents.length) {
          const count = readSync(
            fd,
            contents,
            read,
            contents.length - read,
            read,
          );
          if (count === 0) break;
          read += count;
        }
        if (read !== contents.length)
          throw new WardError("backup_file_unreadable");
        return contents;
      } finally {
        closeSync(fd);
      }
    },
  };
}
