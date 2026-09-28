// Reads and writes the files Ward manages inside one checkout (spec §6.1,
// §11.2). Every path comes from the fixed table in
// application/project-files.ts, joined to the canonical root this adapter
// was built with, so no command argument can become a path Ward writes to.
//
// Two rules decide every refusal here. A link is resolved and its target
// must stay inside the root; a target that leaves the root, or that cannot
// be resolved at all, is refused rather than followed — spec §11.2's
// "never follow an instruction-file symlink into an unrelated location".
// And a write replaces its target atomically: a temp file is created beside
// it (O_EXCL, O_NOFOLLOW, the target's own mode) and renamed over it, so a
// crash leaves either the old file or the new one, never a truncated one.
//
// These are pathname checks inside a single OS user's account: they are
// guardrails against accident and against a repository Ward is pointed at,
// not a boundary against a process running as that user (spec §4.2), and a
// same-user process can still race a check between the lstat and the rename.
import {
  closeSync,
  constants as fileConstants,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import { WardError } from "../contract/errors.ts";
import {
  type ProjectDocument,
  type ProjectFiles,
  projectDocumentPaths,
} from "../application/project-files.ts";

function errnoCode(error: unknown): unknown {
  return typeof error === "object" && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

function lstatOrAbsent(path: string) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return undefined;
    throw new WardError("project_file_unwritable");
  }
}

export function createProjectFiles(root: string): ProjectFiles {
  const prefix = root.endsWith("/") ? root : `${root}/`;

  function contained(path: string): boolean {
    return path.startsWith(prefix);
  }

  // The file a document write would land in: the document's own path, or the
  // file a link at that path points to. Returns undefined when the document
  // does not exist yet.
  function resolve(document: ProjectDocument): string | undefined {
    const path = join(root, projectDocumentPaths[document]);
    const stats = lstatOrAbsent(path);
    if (stats === undefined) return undefined;
    if (!stats.isSymbolicLink()) {
      if (!stats.isFile()) throw new WardError("project_path_unsafe");
      return path;
    }
    let target: string;
    try {
      // A link whose target does not exist (or that loops) resolves to
      // nothing, and a location Ward cannot verify is not one it writes
      // through.
      target = realpathSync(path);
    } catch {
      throw new WardError("project_path_unsafe");
    }
    if (!contained(target)) throw new WardError("project_path_unsafe");
    const targetStats = lstatOrAbsent(target);
    if (targetStats === undefined || !targetStats.isFile())
      throw new WardError("project_path_unsafe");
    return target;
  }

  function ensureDirectory(path: string): void {
    const stats = lstatOrAbsent(path);
    if (stats === undefined) {
      try {
        mkdirSync(path, { mode: 0o755 });
        return;
      } catch (error) {
        if (errnoCode(error) === "EEXIST") return;
        throw new WardError("project_file_unwritable");
      }
    }
    if (!stats.isDirectory() || stats.isSymbolicLink())
      throw new WardError("project_path_unsafe");
  }

  function atomicWrite(path: string, content: string): void {
    const mode = modeOf(path);
    const temp = join(
      dirname(path),
      `.${basename(path)}.ward-tmp-${randomUUID()}`,
    );
    let created = false;
    try {
      const fd = openSync(
        temp,
        fileConstants.O_CREAT |
          fileConstants.O_EXCL |
          fileConstants.O_WRONLY |
          fileConstants.O_NOFOLLOW,
        mode,
      );
      created = true;
      try {
        writeSync(fd, content);
      } finally {
        closeSync(fd);
      }
      renameSync(temp, path);
      created = false;
    } catch (error) {
      if (error instanceof WardError) throw error;
      throw new WardError("project_file_unwritable");
    } finally {
      if (created) {
        try {
          unlinkSync(temp);
        } catch {
          // Best effort: a temp file that cannot be removed fails the write
          // it belonged to, not the caller's next command.
        }
      }
    }
  }

  // A rewrite keeps the target's own mode: a repository file that was
  // deliberately 0644 must not become 0600 (or the reverse) because Ward
  // replaced it.
  function modeOf(path: string): number {
    const stats = lstatOrAbsent(path);
    if (stats === undefined) return 0o644;
    return stats.mode & 0o777;
  }

  return {
    read(document) {
      const path = resolve(document);
      if (path === undefined) return undefined;
      try {
        return readFileSync(path, "utf8");
      } catch {
        throw new WardError("project_file_unwritable");
      }
    },

    write(document, content) {
      const path =
        resolve(document) ?? join(root, projectDocumentPaths[document]);
      ensureDirectory(dirname(path));
      atomicWrite(path, content);
    },
  };
}
