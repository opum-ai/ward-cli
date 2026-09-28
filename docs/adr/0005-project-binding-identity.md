---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Project binding identity
tags:
  - security
  - binding
  - projects
status: stable
summary: A binding lives in the encrypted vault and names both a canonical worktree root and that directory's identity, so a checkout must be registered explicitly and nothing inherits one.
generated:
  by: lore/0.11.0
  at: 2026-09-28T22:37:08.702Z
---

# Project binding identity

## Status

Accepted. It implements spec §7.1 and §11.2 for WCLI-7, and records the two
points the spec leaves to the implementation: what a binding names beyond the
path, and how a registration is obtained. It rules nothing in the spec's place,
and no opum-doc record is claimed for it — the orchestrator is told of both
points in the WCLI-7 landing report, and a ruling there supersedes this file.
The threat model it sits inside is [P0 threat model and non-guarantees](0002-p0-threat-model-and-non-guarantees.md);
the authority it feeds is [Profile approval authority](0003-profile-approval-authority.md).

## Context

Spec §7.1 requires that a project's secrets be reachable only from a checkout
the developer approved, that a copied project id grant nothing, and that a
nested repository, a worktree, a moved path and a new clone "must be handled
explicitly; do not silently add them to an existing binding". The project id
lives in a tracked file (`.ward/project.json`), which anyone who can edit the
repository can copy, so the id cannot be the thing that grants access.

What the spec leaves open is what makes two checkouts "the same" for that
purpose, and the answer decides every one of those cases. A path alone cannot
tell a fresh clone from the checkout it replaced when the clone lands on the
same path; an identity alone cannot tell a moved directory from a new one.

## Decision

**The binding lives in the encrypted vault, names a canonical worktree root
and that directory's own identity, and is created only by an explicit
registration the developer confirms.**

- **What a binding names.** `localBindings` records, for each approved
  checkout: the project id, the canonical worktree root, the root's device and
  inode (from a bigint stat, kept as decimal strings), and when it was
  registered. A checkout resolves only when all three of path, device and
  inode match — so a moved path, a new clone at another path, and a directory
  removed and re-created at the same path are each a different checkout. The
  vault, not the repository, holds this; `.ward/project.json` carries the
  opaque project id and nothing that grants access.
- **What ends the walk.** The root is the nearest ancestor holding a `.git`
  entry, whether that is a directory or a worktree file. Repositories are
  never read — not `.git`'s contents, not remotes, not config — because a
  repository's own strings are not authorization. Project discovery is
  anchored at that root and never walks above it, so a nested repository has
  its own root and cannot reach a parent's manifest or binding.
- **How a registration is obtained.** Interactively, and only that way. The
  developer is shown the project id and the canonical root and answers a
  prompt on an interactive terminal; nothing else creates a binding, and there
  is no non-interactive flag that does. A caller with no terminal is refused
  before the vault key is read — so a non-interactive run never reaches the
  credential store, including one whose checkout happens to be registered
  already. `ward init --no-register` prepares the project files and grants
  nothing.
- **One project, several approved roots.** Registering a worktree adds a
  second approved root for the same project rather than replacing the first,
  so a developer works in a worktree without giving up the main checkout. Each
  root is approved on its own; none is inferred from another.
- **A bound path, another project, is a conflict.** A directory already bound
  to a different project is never silently rebound. The command refuses and
  the resolution is the developer's: restore that project's manifest, or have
  the binding reviewed.
- **Instruction files are managed, not owned.** Ward rewrites only the bytes
  between `<!-- ward:begin -->` and `<!-- ward:end -->` in CLAUDE.md and
  AGENTS.md, preserving every other byte, including the blocks Lore and Quest
  manage. A missing half-pair, a duplicate, or a pair in the wrong order is a
  conflict that changes nothing; a link whose target leaves the repository, or
  that cannot be resolved at all, is refused rather than followed.

## Consequences

- **An explicit registration is a mistake-reducer, not authentication.** The
  terminal prompt is checked for, never trusted as proof of a person (spec
  §4.3), and every check here is a pathname and stat check inside one OS
  account: guardrails against accident and against a repository Ward is
  pointed at, not a boundary against a process running as that user (spec
  §4.2). A same-user process can still race a check between the stat and the
  rename.
- **Measured 2026-09-28, agent-side:** `process.stdin.isTTY` is `undefined`
  in this fleet's agent shell, so a session cannot answer a registration
  prompt, and `ward init` from one exits 4 with `binding_requires_terminal`.
  That is the intended shape rather than a defect. It is a dated measurement
  of one environment, not a claim about every non-interactive caller.
- **Identity is per-directory, so some routine events need re-registration:**
  cloning a repository fresh (even onto the same path), restoring a checkout
  from an archive, and a filesystem whose device or inode numbers changed
  (a remount, a migration) all resolve as unregistered. Each is one confirmed
  prompt, and the safe direction.
- **P0 has no unregister or rebind command.** A binding cannot be removed from
  the vault by any command; the conflict above is resolved from the repository
  side (restore or remove the manifest). Tracked as a gap rather than left
  implicit; it is a decision for the orchestrator when a command is added.
- **The block is text, not a contract with a host.** Ward writes the same
  block to CLAUDE.md and AGENTS.md and never checks whether the host read it.
  The per-host skill files and the `ward agents --check/--update-instructions`
  surface are WCLI-14's, and reuse this block and its markers.
