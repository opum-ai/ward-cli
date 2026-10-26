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

Status: this describes the 0.1.0 release as it will be cut. The artifact name
below is the one the release workflow must produce; check it against the
release's attached files, and treat a mismatch as a defect in this page.

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
3. Install it as a regular file, not a link:
   `install -m 0755 ward-darwin-arm64 ~/.local/bin/ward`. If `~/.local/bin/ward`
   is a symlink into a checkout, remove the link first (`rm ~/.local/bin/ward`),
   then install. The checkout's `dist/ward` is left as it was.
4. Check the version: `ward --version` prints `0.1.0`.
5. Install the agent skill from the private marketplace, which pins `opum-ward`
   to the same tag (opum-fleet owns that entry): `claude plugin install
   opum-ward@opum-fleet` in a fresh session. The plugin and the CLI are cut from
   one tag, so the skill never describes a contract the installed CLI lacks.

### Approve the keychain item, once

6. The first command that needs the vault key (`ward status` is the cheapest)
   may raise a macOS keychain dialog naming `ward` and the `opum.ward` item.
   Approve it with the choice that remembers the decision. The approval is
   bound to this exact binary, so it holds until the next upgrade. Over SSH the
   dialog cannot appear and the command fails with `vault_key_unavailable`:
   approve it once at the Mac itself.

### Re-approve profiles

7. Release 0.1.0 raises the profile snapshot version from 1 to 2
   ([ADR 0018](../adr/0018-profilesnapshotversion-bumps-at-the-first-release.md)).
   A vault whose profile approvals a pre-release build wrote refuses them as
   written by another build, and nothing is migrated or edited: approve each
   profile again in a trusted terminal. Projects, secrets and bindings that
   hold no approval are read as before.

### Upgrade

8. Repeat steps 1 to 4 with the new tag. `install` replaces the file in place.
9. Expect the keychain dialog of step 6 again: a new binary is a new code
   signature, and the release is signed ad hoc, with no stable identity across
   releases. Approve it at the Mac.
10. Read the release notes for a snapshot version bump. A bump means every
    profile must be approved again (step 7); a release that does not bump leaves
    approvals as they were.

## Rollback

Keep the previous artifact and install it the same way (`install -m 0755`).
Rolling back across a snapshot-version bump refuses the approvals the newer
build wrote, exactly as step 7 describes in the other direction: approve the
profiles again. The vault itself is not altered by an install, an upgrade or a
rollback. If a download fails its checksum, nothing was installed; retry the
download, and report a repeat failure rather than installing the file.
