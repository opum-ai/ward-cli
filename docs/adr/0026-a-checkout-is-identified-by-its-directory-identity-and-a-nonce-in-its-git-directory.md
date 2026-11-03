---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: A checkout is identified by its directory identity and a nonce in its git directory
tags:
  - security
  - binding
  - vault-format
summary: A checkout matches a binding or approval on (root, device, inode) and a nonce in its git dir, so a re-clone at a reused inode is new (DEC-255 a2 (4), a6).
generated:
  by: lore/0.14.1
  at: 2026-11-03T14:09:07.671Z
---

# A checkout is identified by its directory identity and a nonce in its git directory

## Status

Accepted, 2026-11-03, under **DEC-255 (a2) clause (4)**, **DEC-255 (a6)** and **DEC-255 (a7)**,
recorded by opum-doc in its tracker (opum-ai/opum-doc#1597 for (a6),
opum-ai/opum-doc#1601 for (a7)) and carried here from their text as relayed to
this repository. The record binds, not this
document's copy of it; the decisions' text is DEC-255 (a2)(4), (a6) and (a7) in
opum-doc. Implemented by WCLI-125. It supersedes the identity part of
[ADR 0005](0005-project-binding-identity.md), the part that names a binding by
root, device and inode alone, and it amends
[ADR 0023](0023-keep-the-vault-state-reader-s-exact-key-set-comparison-at-the-first-release.md)
by naming one exception to its exact key-set comparison.

## Context

A checkout was identified by (root, device, inode). The Opus review of
opum-ai/ward-cli#237 (WCLI-99, finding 1) showed that a filesystem which reuses
a freed inode hands the same triple to a clone made at the same path after an
`rm -rf`, so the new clone silently inherited the old binding and every profile
approval. Spec section 7.1 requires a new clone to be handled explicitly. The
hosted ext4 runner reproduced it; APFS rarely reuses inode numbers.

## Decision

1. **A per-checkout nonce.** A random 128-bit value, written as 32 lowercase hex
   digits, stored in the clone's own git directory at `ward/checkout-id`, never
   in a tracked `.ward` file, and written when the checkout is bound (after the
   registration is approved). A binding and a profile approval each match a
   checkout only on (root, device, inode) **and** the nonce. A missing or
   mismatched nonce reads unbound and requires re-approval. Each worktree binds
   separately. A creation time is rejected as an identifier (DEC-255 (a2)(4)).
2. **`checkoutId` is the one optional key** on binding and profile-approval
   records (DEC-255 (a6) Q1). A record without it parses and reads as unbound,
   so the developer registers and approves again; `vaultStateFormatVersion` stays
   1. Every other missing or unknown key, and a `checkoutId` that is not 32
   lowercase hex digits, still refuses the whole document. Version 2 with a
   refusal of version-1 vaults was rejected: it refuses where the ruling says
   "reads unbound", and needs a migration the ruling never asked for.
3. **Finding the git directory** (DEC-255 (a6) Q2). Ward follows the `gitdir:`
   pointer only in the `.git` entry its own root walk found, and never reads the
   GIT_DIR environment variable. It reads that file as one bounded line (refused
   over 4 KiB, or anything other than a single `gitdir: <path>` line) and reads
   nothing else in the repository. A relative path is resolved against the
   directory holding the `.git` file, because git writes relative paths for
   submodules by default; the result is canonicalised with realpath and must be
   an existing directory. `ward/checkout-id` is created with exclusive create,
   mode 0600, refusing a symlink at the `ward` directory and at the file. This is
   a named, bounded exception to the rule in `src/adapters/checkout.ts` that
   nothing in `.git` is read (spec section 7.1). A checkout whose git directory
   cannot be resolved or written this way is refused at registration with
   `checkout_identity_unavailable` and binds nothing.

## Consequences

- **A re-clone is a new checkout whatever the filesystem does.** The tests do
  not depend on inode reuse: they pin an identical (root, device, inode) with a
  different nonce, and an `rm -rf` and re-clone at the same path. On APFS the
  re-clone gets a new inode, so that end-to-end case cannot prove reuse there;
  the domain cases carry the guarantee and real reuse is first measured on Linux
  T26 (DEC-255 (a7)).
- **Existing 0.1.1 vaults still open, and their records never match.** A binding
  or approval with no `checkoutId` authorizes nothing; the developer registers
  and approves again. A legacy record is removed on unregister or re-approval and
  at no other time (DEC-255 (a7)): `ward unregister`, run in a checkout, also
  removes a legacy binding of the same project at the same (root, device,
  inode) with that binding's legacy approvals, under the same questions (not another
  project's); approving a profile
  removes a legacy approval for the same project, profile and directory. Both are
  removals only, and removing a record grants nothing. No cleanup command is
  filed. `ward doctor` reports only stale-version approvals, and names one with no
  nonce as legacy (register and approve again); it does not report any other
  legacy record. (a7) accepts `checkout_identity_unavailable` as the refusal
  name when the git directory cannot be resolved or written.
- **Downgrade is unsupported.** A vault written by this version carries the key,
  so a 0.1.1 binary refuses it as malformed. The release notes of the next
  release say so in one line.
- **Residual.** The nonce is a file the developer's own account can read and
  copy; a `cp -r` of a checkout copies it, but the copy has another root and
  inode, so it still matches nothing. This guards against an inherited binding,
  not against a hostile local account (ADR 0002).
- **Residual: a link swapped under the write.** Node has no `openat`, so the
  `ward` directory is checked with `O_DIRECTORY|O_NOFOLLOW` and the file is then
  created by name; a process under the same account that swaps the directory for
  a link between the two can redirect a create that writes only a random nonce
  (outside ADR 0002).
- **Residual: a surviving git directory.** A submodule's or linked worktree's git
  directory survives an `rm -rf` of its working tree, so restoring the tree from
  it keeps the nonce; that is still "the clone's git dir" and complies.
- **Revisit** if the nonce proves unwritable on a supported platform
  (Linux T26 is the first measurement) or a way appears to carry it across a
  re-clone; either would be a new decision.
