---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Install and upgrade Ward from a release
tags:
  - release
  - install
summary: Install a released Ward binary from the private GitHub Release, verify it, and upgrade; the keychain and profile re-approval a first install or an upgrade raises.
generated:
  by: lore/0.14.1
  at: 2026-10-26T17:17:40.899Z
---

# Install and upgrade Ward from a release

## Purpose

This is how a developer gets a released Ward onto a Mac and keeps it current,
and what they must do afterwards (WCLI-82, ODOC-542). The installed `ward` is a
regular file copied from a release artifact, never a symlink into a working
tree: a rebuild in a checkout changes the executable's code signature, and the
macOS keychain's trust in the vault-key item follows that signature, so a
symlinked build asks for approval again after every rebuild.

Status: this describes the cut 0.1.0 release, whose attached files are
`ward-darwin-arm64` and `ward-darwin-arm64.sha256` — the names below. That
v0.1.0 asset fails step 3 until republished.

## Prerequisites

- macOS on Apple silicon. The only artifact built is `darwin-arm64`; there is no
  Intel or Linux build.
- The GitHub CLI, signed in to an account that can read `opum-ai/ward-cli`
  (the repository is private).
- `~/.local/bin` on `PATH`.
- Your developer vault is yours: no step here opens, rewrites or deletes
  `~/.ward`.

## Steps

### First install

1. Download the artifact and its checksum into an empty directory:
   `gh release download v0.1.0 -R opum-ai/ward-cli -p 'ward-darwin-arm64*'`
2. Verify the checksum: `shasum -a 256 -c ward-darwin-arm64.sha256`. Stop on any
   mismatch; do not run the file.
3. Verify the signature: `codesign --verify --strict --verbose=2
   ward-darwin-arm64`. It must exit 0. Stop on any other exit. Then compare
   its CDHash with the release notes: `codesign -dvvv ward-darwin-arm64 2>&1 |
   grep '^CDHash='` must equal the `cdhash` line of `gh release view v0.1.0 -R opum-ai/ward-cli
   --json body`. On a mismatch, do not install it.
4. Install it as a regular file, not a link:
   `install -m 0755 ward-darwin-arm64 ~/.local/bin/ward`. If `~/.local/bin/ward`
   is a symlink into a checkout, remove the link first (`rm ~/.local/bin/ward`),
   then install. The checkout's `dist/ward` is left as it was.
5. Check the version: `ward --version` prints `0.1.0`.
6. Install the agent skill from the private marketplace, which pins `opum-ward`
   to the same tag (opum-fleet owns that entry): `claude plugin install
   opum-ward@opum-fleet` in a fresh session. The plugin and the CLI are cut from
   one tag, so the skill never describes a contract the installed CLI lacks.

### Approve the keychain item, once

7. The first command that needs the vault key (`ward status` is the cheapest)
   may raise a macOS keychain dialog naming `ward` and the `opum.ward` item.
   Approve it with the choice that remembers the decision. The approval is
   bound to this exact binary, so it holds until the next upgrade. Over SSH the
   dialog cannot appear and the command fails with `vault_key_unavailable`:
   approve it once at the Mac itself.

### Re-approve profiles

8. Release 0.1.0 raises the profile snapshot version from 1 to 2
   ([ADR 0018](../adr/0018-profilesnapshotversion-bumps-at-the-first-release.md)).
   A vault whose profile approvals a pre-release build wrote does not treat
   them as approval: each one authorises nothing, and `ward status` and
   `ward doctor` name it with its checkout and its snapshot version (the
   `stale_approvals` check). Nothing is migrated or edited. Approve each named
   profile again in a trusted terminal with `ward profile approve <name>`,
   which replaces the stale record. Run it from the checkout the report named:
   the replacement matches on profile, project and checkout root, so the same
   command run somewhere else records a second approval and leaves the stale
   one exactly where it was. Projects, secrets and bindings that hold
   no approval are read as before.

   Two kinds of record appear here, and only one of them needs you. A record
   whose checkout still exists and still declares the profile is the one step
   8 is about: re-approve it and it is replaced. A record whose checkout is
   gone, or whose profile is no longer declared, can never be cleared — and
   Ward names it as inert and unreachable without failing `ward doctor`, so a
   deleted worktree cannot pin the exit code at 6 forever. 0.1.0 offers no way
   to remove such a record; it stays in the vault, authorising nothing, and a
   later release is expected to add the cleanup command. Only this project's
   records are named: `ward doctor` reports records belonging to other
   projects as a bare count, and running Ward in that project names them.

### Upgrade

9. Repeat steps 1 to 5 with the new tag. `install` replaces the file in place.
10. Expect the keychain dialog of step 7 again: a new binary is a new code
    signature, and the release is signed ad hoc, with no stable identity across
    releases. Approve it at the Mac.
11. Read the release notes for a snapshot version bump. A bump means every
    profile must be approved again (step 8); a release that does not bump leaves
    approvals as they were.

## Rollback

Keep the previous artifact and install it the same way (`install -m 0755`),
after steps 2 and 3 pass on it.
The vault itself is not altered by an install, an upgrade or a rollback.

Rolling back is only as safe as the older build's ability to read what the
newer one wrote. From 0.1.0 the only rollback target is a pre-release build,
and those refuse the whole vault once it holds an approval written by 0.1.0:
they predate the versioned approval record, answer
`vault_format_unsupported`, and stop at the door on `ward status`, `ward
doctor` and every other read rather than letting the newer approvals go inert.
There is no migration back. The remedy is to reinstall 0.1.0 — or, under 0.1.0
before downgrading, to revoke the approvals that would be left behind.

If a download fails its checksum, nothing was installed; retry the download,
and report a repeat failure rather than installing the file.
