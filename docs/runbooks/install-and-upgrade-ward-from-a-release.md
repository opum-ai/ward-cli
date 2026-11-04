---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Install and upgrade Ward from a release
tags:
  - release
  - install
summary: Install a released Ward binary from a GitHub Release over HTTPS, verify it, and upgrade; the keychain and profile re-approval a first install or an upgrade raises.
generated:
  by: lore/0.14.1
  at: 2026-10-26T17:17:40.899Z
---

# Install and upgrade Ward from a release

## Purpose

This is how a developer gets a released Ward onto a Mac and keeps it current,
and what they must do afterwards. The installed `ward` is a
regular file copied from a release artifact, never a symlink into a working
tree: a rebuild changes the executable's code signature, and the macOS
keychain's trust in the vault-key item follows that signature, so a symlinked
build asks for approval again after every rebuild.

Status: the v0.1.0 asset fails step 3; install v0.1.1 or later.

## Prerequisites

- macOS on Apple silicon. The only artifact built is `darwin-arm64`; there is no
  Intel or Linux build.
- A way to download from GitHub: HTTPS with no account, or the GitHub CLI
  signed in to an account that can read the repository.
- `~/.local/bin` on `PATH`.
- Your developer vault is yours: no install, upgrade or rollback step opens,
  rewrites or deletes `~/.ward`.

## Steps

### First install

1. Download the artifact and its checksum into an empty directory:
   `curl -fLO https://github.com/opum-ai/ward-cli/releases/download/v0.1.1/ward-darwin-arm64`
   and the same URL with `.sha256` appended. Or with the GitHub CLI:
   `gh release download v0.1.1 -R opum-ai/ward-cli -p 'ward-darwin-arm64*'`.
2. Verify the checksum: `shasum -a 256 -c ward-darwin-arm64.sha256`. Stop on any
   mismatch; do not run the file.
3. Verify the signature: `codesign --verify --strict --verbose=2
   ward-darwin-arm64`. It must exit 0. Stop on any other exit. Then compare
   its CDHash with the `cdhash` line in the release notes: `codesign -dvvv
   ward-darwin-arm64 2>&1 | grep '^CDHash='`. The notes are on the Release page
   (`https://github.com/opum-ai/ward-cli/releases/tag/v0.1.1`). On a mismatch,
   do not install it.
4. Install it as a regular file, not a link:
   `install -m 0755 ward-darwin-arm64 ~/.local/bin/ward`. If that path is a
   symlink into a checkout, remove the link first (`rm ~/.local/bin/ward`), then
   install; the checkout's `dist/ward` is left as it was.
5. Check the version: `ward --version` prints `0.1.1`.
6. Install the agent skill (optional). It ships as the `opum-ward` Claude Code
   plugin. No public marketplace listing exists yet: read the skill at the same
   tag as the binary (`plugin/skills/ward/SKILL.md` at v0.1.1). A mismatch with
   `ward --version` is untested.

### Approve the keychain item, once

7. On a new machine run `ward setup` first. A build that created the vault key
   (a fresh `ward setup`) reads it back with no prompt; any other build (an
   upgrade, or a checkout build you are replacing) is expected to prompt. The first command that needs the vault key (`ward status` is the
   cheapest) may raise a macOS keychain dialog. It should appear right after
   you ran `~/.local/bin/ward`; if it appears when you ran nothing, stop and do
   not approve it. The dialog is not yet measured or recorded from a released
   build. The approval is bound to this build's cdhash and does not carry over
   to the next one. Over SSH the dialog cannot appear and the command fails with
   `vault_key_unavailable`: approve it once at the Mac itself.

### Re-approve profiles

8. Release 0.1.0 raised the profile snapshot version from 1 to 2
   (ADR 0018)
   and 0.1.1 raised it from 2 to 3
   (ADR 0024).
   A vault whose profile approvals an earlier build wrote does not treat
   them as approval: each one authorises nothing, and `ward status` and
   `ward doctor` name it with its checkout and its snapshot version (the
   `stale_approvals` check). Nothing is migrated or edited. Approve each named
   profile again in a trusted terminal with `ward profile approve <name>`,
   which replaces the stale record. Run it from the checkout the report named:
   elsewhere it records a second approval and leaves the stale one.
   Projects, secrets and bindings that hold no approval are read as before.

   Only a record whose checkout still exists, still declares the profile and is
   registered needs you: re-approve it. A record whose checkout is gone, or
   whose profile is no longer declared, is named as inert and unreachable
   without failing `ward doctor`. No command removes it; it stays, authorising
   nothing. Only this project's records are named; `ward doctor` counts other
   projects' records, and running Ward there names them.

   From the release after 0.1.1, a 0.1.1 record and its binding have no
   checkout identity: until registered, its checkout reads as unregistered and
   `ward profile approve` is refused there. To replace it, and only if that checkout should have the project's
   secrets, run `ward init` from it, then `ward profile approve`. If init
   cannot give it an identity, it stays inert, with no hint.

### Upgrade

9. Repeat steps 1 to 5 with the new tag. `install` replaces the file in place.
10. Expect step 7's keychain dialog again: the new binary has a different
    cdhash, so the old approval does not cover it. It should appear right
    after you ran the new `~/.local/bin/ward`; then approve at the Mac.
11. Read the release notes for a snapshot version bump. A bump means every
    profile must be approved again (step 8); a release that does not bump leaves
    approvals as they were.

## Rollback

Keep the previous artifact and install it the same way (`install -m 0755`),
after steps 2 and 3 pass on it. There is no rollback to 0.1.0: its asset fails
step 3.
The vault itself is unchanged by an install, upgrade or rollback.

A rollback is only as safe as the older build's ability to read what the newer
one wrote. There is no migration back: reinstall the newest release, or revoke
the approvals before downgrading.

If a download fails its checksum, nothing was installed; retry the download,
and report a repeat failure rather than installing the file.
