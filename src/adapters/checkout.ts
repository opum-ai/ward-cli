// Resolves the canonical Git worktree root of a directory, and that
// directory's own identity (spec §7.1).
//
// The walk itself is deliberately dumb (the one bounded exception is the
// checkout nonce below, ADR 0026): from the canonical starting directory,
// upward, the first directory holding a `.git` entry is the root. No Git
// command runs, and nothing in the repository is read — not `.git`'s
// contents, not a remote, not a config value — because a repository's own
// strings are not authorization (spec §7.1). A `.git` file (a linked
// worktree, a submodule) and a `.git` directory (an ordinary checkout) both
// mark a boundary, and both end the walk, which is what keeps a nested
// repository from reaching its parent's authority.
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fileConstants,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type { ProbedCheckout } from "../application/reporting.ts";
import { createProjectFiles } from "./project-files.ts";
import { WardError } from "../contract/errors.ts";
import { type CheckoutIdentity, isCheckoutId } from "../domain/vault-state.ts";

function errnoCode(error: unknown): unknown {
  return typeof error === "object" && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

function hasGitEntry(directory: string): boolean {
  try {
    lstatSync(join(directory, ".git"));
    return true;
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return false;
    // An unreadable directory means the boundary cannot be established, and
    // an unestablished boundary is not a root to bind.
    throw new WardError("worktree_not_found");
  }
}

// The same path with its parent resolved through links, which is how the
// vault store names its own directory. Comparisons between a checkout root
// (always canonical) and the vault directory (whatever the caller passed)
// use this, so a home directory reached through a link cannot make two names
// for one location look like two locations. Best effort: a path whose parent
// cannot be resolved is returned unchanged, and the comparison it feeds
// degrades to the literal one rather than failing the command.
export function canonicalDirectory(directory: string): string {
  try {
    return join(realpathSync(dirname(directory)), basename(directory));
  } catch {
    return directory;
  }
}

// The checkout nonce (DEC-255 a2 clause 4, a6 Q2; ADR 0026): a random id kept
// in the clone's own git directory at ward/checkout-id, never in a tracked
// file. (root, device, inode) alone cannot tell a deleted clone from a new one
// at the same path on a filesystem that reuses a freed inode; a fresh clone has
// a fresh git directory, and so no nonce, until it is registered.
//
// This is the one named, bounded exception to the rule above that nothing in
// `.git` is read. Ward looks at the `.git` entry its own walk found and nowhere
// else, and never at the GIT_DIR environment variable. An ordinary checkout's
// entry is the git directory. A linked worktree's or a submodule's is a file
// holding one `gitdir: <path>` line, which is read as at most 4 KiB, a relative
// path resolved against the directory holding the file (git writes relative
// paths for submodules), canonicalised with realpath and required to be an
// existing directory. Nothing else in the repository is read.
const GITDIR_FILE_MAX_BYTES = 4096;
const CHECKOUT_ID_FILE_MAX_BYTES = 64;

// One bounded read of a regular file opened without following a link; the
// file may be one byte over the bound to prove it is over.
function readBoundedFile(path: string, maxBytes: number): string | undefined {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      path,
      fileConstants.O_RDONLY | fileConstants.O_NOFOLLOW,
    );
    const buffer = Buffer.alloc(maxBytes + 1);
    const read = readSync(descriptor, buffer, 0, buffer.length, 0);
    if (read > maxBytes) return undefined;
    return buffer.toString("utf8", 0, read);
  } catch {
    return undefined;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function gitDirectoryOf(root: string): string | undefined {
  const entry = join(root, ".git");
  try {
    const stats = lstatSync(entry);
    if (stats.isDirectory()) return entry;
    if (!stats.isFile()) return undefined;
    const text = readBoundedFile(entry, GITDIR_FILE_MAX_BYTES);
    if (text === undefined) return undefined;
    const line = text.endsWith("\r\n")
      ? text.slice(0, -2)
      : text.endsWith("\n")
        ? text.slice(0, -1)
        : text;
    if (!line.startsWith("gitdir: ") || /[\r\n\0]/.test(line)) return undefined;
    const pointed = line.slice("gitdir: ".length);
    if (pointed.length === 0) return undefined;
    const target = realpathSync(
      isAbsolute(pointed) ? pointed : resolve(root, pointed),
    );
    return lstatSync(target).isDirectory() ? target : undefined;
  } catch {
    return undefined;
  }
}

function checkoutIdPath(gitDirectory: string): {
  directory: string;
  file: string;
} {
  const directory = join(gitDirectory, "ward");
  return { directory, file: join(directory, "checkout-id") };
}

function readCheckoutId(gitDirectory: string): string | undefined {
  const { directory, file } = checkoutIdPath(gitDirectory);
  try {
    if (!lstatSync(directory).isDirectory()) return undefined;
    if (!lstatSync(file).isFile()) return undefined;
  } catch {
    return undefined;
  }
  const text = readBoundedFile(file, CHECKOUT_ID_FILE_MAX_BYTES);
  if (text === undefined) return undefined;
  const id = text.endsWith("\n") ? text.slice(0, -1) : text;
  return isCheckoutId(id) ? id : undefined;
}

// The checkout's identity nonce, creating it on first use: exclusive create,
// mode 0600, refusing a link at the `ward` directory and at the file, so a
// repository cannot make Ward write through a link it planted. An existing
// valid nonce is kept, since it already names this clone. Called only after a
// registration is approved.
export function bindCheckoutIdentity(
  identity: CheckoutIdentity,
): CheckoutIdentity {
  const gitDirectory = gitDirectoryOf(identity.root);
  if (gitDirectory === undefined)
    throw new WardError("checkout_identity_unavailable");
  let id = readCheckoutId(gitDirectory);
  if (id === undefined) {
    const { directory, file } = checkoutIdPath(gitDirectory);
    try {
      try {
        mkdirSync(directory, { mode: 0o700 });
      } catch (error) {
        if (errnoCode(error) !== "EEXIST") throw error;
      }
      // Opened as a directory without following a link, so a link planted at
      // the `ward` entry fails here (ELOOP or ENOTDIR). Node has no openat, so
      // the file below is still created by name; ADR 0026 names that residual.
      closeSync(
        openSync(
          directory,
          fileConstants.O_RDONLY |
            fileConstants.O_DIRECTORY |
            fileConstants.O_NOFOLLOW,
        ),
      );
      const fresh = randomBytes(16).toString("hex");
      let descriptor: number | undefined;
      try {
        descriptor = openSync(
          file,
          fileConstants.O_WRONLY |
            fileConstants.O_CREAT |
            fileConstants.O_EXCL |
            fileConstants.O_NOFOLLOW,
          0o600,
        );
        writeSync(descriptor, `${fresh}\n`);
        id = fresh;
      } catch (error) {
        // A concurrent registration may have created it first; take theirs.
        if (errnoCode(error) !== "EEXIST") throw error;
        id = readCheckoutId(gitDirectory);
      } finally {
        if (descriptor !== undefined) closeSync(descriptor);
      }
    } catch (error) {
      if (error instanceof WardError) throw error;
      throw new WardError("checkout_identity_unavailable");
    }
  }
  if (id === undefined) throw new WardError("checkout_identity_unavailable");
  return { ...identity, checkoutId: id };
}

export function locateCheckout(startDirectory: string): CheckoutIdentity {
  let current: string;
  try {
    current = realpathSync(startDirectory);
  } catch {
    throw new WardError("worktree_not_found");
  }
  while (true) {
    if (hasGitEntry(current)) {
      const stats = lstatSync(current, { bigint: true });
      const gitDirectory = gitDirectoryOf(current);
      const checkoutId =
        gitDirectory === undefined ? undefined : readCheckoutId(gitDirectory);
      return {
        root: current,
        device: stats.dev.toString(),
        inode: stats.ino.toString(),
        ...(checkoutId === undefined ? {} : { checkoutId }),
      };
    }
    const parent = dirname(current);
    if (parent === current) throw new WardError("worktree_not_found");
    current = parent;
  }
}

// A checkout a stored record names, seen from here (DEC-246 a3 Q2). The
// question is always about an absolute root that is usually not the one being
// reported, and the answer decides whether a stale approval can still be
// cleared: a directory that is gone, or that is now a different directory at
// the same path, cannot be re-approved, and neither can one whose manifest no
// longer declares the profile.
//
// It resolves through locateCheckout, the same walk `ward profile approve`
// uses, rather than lstat-ing the stored path. The two disagree in exactly the
// cases that matter: a directory that survived without its `.git` resolves to
// an ancestor, and an ancestor reached through a link resolves to the same
// place by a different name. Answering "clearable" there would make doctor fail
// on a step that cannot replace the record, which is the dead end Q2 removed.
// The caller compares the resolved root against the record's, so a resolution
// that lands elsewhere reads as inert.
//
// The manifest goes through the same port every other read of it uses, so a
// link leaving the checkout is refused here exactly as it is elsewhere.
// Whether bindCheckoutIdentity could give this checkout an identity: its git
// directory resolves, and it either holds a valid nonce already or has no
// `ward` entry in the way (no directory, or a real one with no file in it). A
// pruned linked-worktree gitdir, an invalid nonce file and a link or file where
// the `ward` directory belongs all make `ward init` throw
// checkout_identity_unavailable, so a report must not tell the developer to run
// it there.
function identityBindable(root: string): boolean {
  const gitDirectory = gitDirectoryOf(root);
  if (gitDirectory === undefined) return false;
  if (readCheckoutId(gitDirectory) !== undefined) return true;
  const { directory, file } = checkoutIdPath(gitDirectory);
  try {
    if (!lstatSync(directory).isDirectory()) return false;
  } catch (error) {
    return errnoCode(error) === "ENOENT";
  }
  try {
    lstatSync(file);
    return false;
  } catch (error) {
    return errnoCode(error) === "ENOENT";
  }
}

export function probeCheckout(root: string): ProbedCheckout | undefined {
  let identity: CheckoutIdentity;
  try {
    identity = locateCheckout(root);
  } catch {
    return undefined;
  }
  let manifest: string | undefined;
  try {
    manifest = createProjectFiles(identity.root).read("manifest");
  } catch {
    manifest = undefined;
  }
  return {
    root: identity.root,
    device: identity.device,
    inode: identity.inode,
    ...(identity.checkoutId === undefined
      ? {}
      : { checkoutId: identity.checkoutId }),
    registrable: identityBindable(identity.root),
    manifest,
  };
}
