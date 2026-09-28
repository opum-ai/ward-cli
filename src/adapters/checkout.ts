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
