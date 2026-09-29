// Reads and writes the files Ward manages inside one checkout (spec §6.1,
// §11.2). Every path comes from the fixed table in
// application/project-files.ts, joined to the canonical root this adapter
// was built with, so no command argument can become a path Ward writes to.
//
// Two rules decide every refusal here. Every component of a path is
// resolved, and a link at any level — the document itself or a directory
// above it — must resolve to a target inside the root; a target that leaves
// the root, or that cannot be resolved at all, is refused rather than
// followed — spec §11.2's "never follow an instruction-file symlink into an
// unrelated location". Checking only the document's own component is not
// enough, because lstat resolves the links above the name it is handed, so
// a `.ward` directory that is a link out of the repository was followed on
// read. Whether a link is followed is decided by where it lands, never by
// which component it is. And a write replaces its target atomically: a temp
// file is created beside it (O_EXCL, O_NOFOLLOW, the target's own mode) and
// renamed over it, so a crash leaves either the old file or the new one,
// never a truncated one.
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
  readlinkSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join, resolve as resolvePath } from "node:path";
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

// How many link hops a path may take before Ward refuses it: a link that
// loops resolves forever otherwise. The number matches the limit realpath
// uses on the platforms Ward targets.
const linkHops = 40;

export function createProjectFiles(root: string): ProjectFiles {
  const prefix = root.endsWith("/") ? root : `${root}/`;

  function contained(path: string): boolean {
    return path.startsWith(prefix);
  }

  // The canonical name of the part of a path that exists, and the names
  // below it that do not exist yet. A link's target text may spell a
  // location that exists by another name — a temporary directory reached
  // through /var and /private/var on macOS — so the answer for the existing
  // part comes from the filesystem rather than from the string.
  function canonical(path: string): { base: string; rest: readonly string[] } {
    const rest: string[] = [];
    let current = path;
    for (;;) {
      if (lstatOrAbsent(current) !== undefined) {
        try {
          return { base: realpathSync(current), rest: rest.reverse() };
        } catch {
          throw new WardError("project_path_unsafe");
        }
      }
      const parent = dirname(current);
      if (parent === current) throw new WardError("project_path_unsafe");
      rest.push(basename(current));
      current = parent;
    }
  }

  // Walks plain path segments from a directory already known to be inside
  // the root, following a link at any position and pushing its target's own
  // segments back through the same walk. Every component is therefore
  // checked the same way, and a link above a component is checked before
  // anything is written through it — which a check of the last component
  // alone cannot do, because lstat resolves the links above the name it is
  // handed. `steps` bounds the number of link hops, so a link that loops is
  // refused rather than followed.
  function walk(
    directory: string,
    segments: readonly string[],
    steps: number,
  ): { path: string; exists: boolean } {
    for (const [index, segment] of segments.entries()) {
      const last = index === segments.length - 1;
      const rest = segments.slice(index + 1);
      const candidate = join(directory, segment);
      const stats = lstatOrAbsent(candidate);
      if (stats === undefined)
        return { path: join(candidate, ...rest), exists: false };
      if (!stats.isSymbolicLink()) {
        if (last ? !stats.isFile() : !stats.isDirectory())
          throw new WardError("project_path_unsafe");
        directory = candidate;
        continue;
      }
      if (steps === 0) throw new WardError("project_path_unsafe");
      let target: string;
      try {
        target = readlinkSync(candidate);
      } catch {
        throw new WardError("project_path_unsafe");
      }
      // Normalized before it is compared, so `..` in a link's own text
      // cannot walk out of the root past this check, then canonicalized, so
      // the same place named two ways is not mistaken for two places.
      const following = canonical(resolvePath(dirname(candidate), target));
      if (following.base !== root && !contained(following.base))
        throw new WardError("project_path_unsafe");
      // A target that does not exist yet is still followed to its path: a
      // repository may hold AGENTS.md -> CLAUDE.md before Ward has created
      // CLAUDE.md, and refusing it would make the outcome depend on the
      // order the targets happen to be written in. What is never followed
      // is a target outside the root, which the check above has refused.
      const followed = walk(
        following.base,
        [...following.rest, ...rest],
        steps - 1,
      );
      // A link standing where a file is required must land on one, including
      // when it points straight at its own final name.
      if (
        rest.length === 0 &&
        followed.exists &&
        !lstatOrAbsent(followed.path)?.isFile()
      )
        throw new WardError("project_path_unsafe");
      return followed;
    }
    return { path: directory, exists: true };
  }

  // The file a document read or write lands in, with every component of the
  // path checked. `exists` is false when some component does not exist yet;
  // the path returned is still the contained path a write would create, so
  // a link above the missing component is what the missing file would be
  // written through.
  function resolve(document: ProjectDocument): {
    path: string;
    exists: boolean;
  } {
    return walk(root, projectDocumentPaths[document].split("/"), linkHops);
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
    // resolve() hands this function only a directory it has already walked,
    // so a link should not reach here; refusing one is a backstop rather
    // than the enforcement point, which is the containment check above.
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
      const target = resolve(document);
      if (!target.exists) return undefined;
      try {
        return readFileSync(target.path, "utf8");
      } catch {
        throw new WardError("project_file_unwritable");
      }
    },

    write(document, content) {
      const target = resolve(document);
      ensureDirectory(dirname(target.path));
      atomicWrite(target.path, content);
    },

    remove(document) {
      const target = resolve(document);
      if (!target.exists) return false;
      try {
        unlinkSync(target.path);
        return true;
      } catch {
        throw new WardError("project_file_unwritable");
      }
    },
  };
}
