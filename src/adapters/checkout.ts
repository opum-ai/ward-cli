// Resolves the canonical Git worktree root of a directory, and that
// directory's own identity (spec §7.1).
//
// The walk is deliberately dumb: from the canonical starting directory,
// upward, the first directory holding a `.git` entry is the root. No Git
// command runs, and nothing in the repository is read — not `.git`'s
// contents, not a remote, not a config value — because a repository's own
// strings are not authorization (spec §7.1). A `.git` file (a linked
// worktree, a submodule) and a `.git` directory (an ordinary checkout) both
// mark a boundary, and both end the walk, which is what keeps a nested
// repository from reaching its parent's authority.
import { lstatSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import type { ProbedCheckout } from "../application/reporting.ts";
import { createProjectFiles } from "./project-files.ts";
import { WardError } from "../contract/errors.ts";
import type { CheckoutIdentity } from "../domain/vault-state.ts";

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
      return {
        root: current,
        device: stats.dev.toString(),
        inode: stats.ino.toString(),
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
    manifest,
  };
}
