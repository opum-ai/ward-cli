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
and what they must do afterwards (WCLI-82, ODOC-542). The installed `ward` is a
regular file copied from a release artifact, never a symlink into a working
tree: a rebuild changes the executable's code signature, and the macOS
keychain's trust in the vault-key item follows that signature, so a symlinked
build asks for approval again after every rebuild.

Status: the cut 0.1.0 asset fails step 3 until republished.

## Prerequisites

- macOS on Apple silicon. The only artifact built is `darwin-arm64`; there is no
  Intel or Linux build.
- A way to download from GitHub: HTTPS with no account once public, or the
  GitHub CLI signed in while it is private.
- `~/.local/bin` on `PATH`.
- Your developer vault is yours: no step here opens, rewrites or deletes
  `~/.ward`.

## Steps

### First install

1. Download the artifact and its checksum into an empty directory; no account
   is needed once public:
   `curl -fLO https://github.com/opum-ai/ward-cli/releases/download/v0.1.0/ward-darwin-arm64`
   and the same URL with `.sha256` appended. Until then:
   `gh release download v0.1.0 -R opum-ai/ward-cli -p 'ward-darwin-arm64*'`.
2. Verify the checksum: `shasum -a 256 -c ward-darwin-arm64.sha256`. Stop on any
   mismatch; do not run the file.
3. Verify the signature: `codesign --verify --strict --verbose=2
   ward-darwin-arm64`. It must exit 0. Stop on any other exit. Then compare
   its CDHash with the `cdhash` line in the release notes: `codesign -dvvv
   ward-darwin-arm64 2>&1 | grep '^CDHash='`. On a mismatch, do not install it.
4. Install it as a regular file, not a link:
   `install -m 0755 ward-darwin-arm64 ~/.local/bin/ward`. If that path is a
   symlink into a checkout, remove the link first (`rm ~/.local/bin/ward`), then
   install; the checkout's `dist/ward` is left as it was.
5. Check the version: `ward --version` prints `0.1.0`.
6. Install the agent skill (optional). It ships as the `opum-ward` Claude Code
   plugin; use its marketplace listing for the marketplace and version, rather
   than a tag fixed here. The plugin and CLI are cut separately, so compare
   versions with `ward --version`.

### Approve the keychain item, once

7. The first command that needs the vault key (`ward status` is the cheapest)
   may raise a macOS keychain dialog for the `opum.ward` item. Before choosing
   the remembering option, check that the dialog names the binary you installed
   (`~/.local/bin/ward`); if it names anything else, stop and do not approve
   it. The approval is bound to this exact build: Ward is ad-hoc signed, so
   each build has a different cdhash and the trust does not carry over to the
   next one. Over SSH the dialog cannot appear and the command fails with
   `vault_key_unavailable`: approve it once at the Mac itself.

### Re-approve profiles

8. Release 0.1.0 raises the profile snapshot version from 1 to 2
   ([ADR 0018](../adr/0018-profilesnapshotversion-bumps-at-the-first-release.md)).
   A vault whose profile approvals a pre-release build wrote does not treat
   them as approval: each one authorises nothing, and `ward status` and
   `ward doctor` name it with its checkout and its snapshot version (the
   `stale_approvals` check). Nothing is migrated or edited. Approve each named
   profile again in a trusted terminal with `ward profile approve <name>`,
   which replaces the stale record. Run it from the checkout the report named:
   the replacement matches profile, project and checkout root, so running it
   elsewhere records a second approval and leaves the stale one in place.
   Projects, secrets and bindings that hold no approval are read as before.

   Two kinds of record appear, and only one needs you. A record whose checkout
   still exists and still declares the profile is the one this step is about:
   re-approve it and it is replaced. A record whose checkout is gone, or whose
   profile is no longer declared, can never be cleared: Ward names it as inert
   and unreachable without failing `ward doctor`, so a deleted worktree cannot
   pin the exit code at 6 forever. 0.1.0 has no command to remove such a
   record; it stays in the vault, authorising nothing, and a later release is
   expected to add one. Only this project's records are named; `ward doctor`
   reports other projects' records as a bare count, and running Ward there
   names them.

### Upgrade

9. Repeat steps 1 to 5 with the new tag. `install` replaces the file in place.
10. Expect step 7's keychain dialog again: the new binary has a different
    cdhash, so the old approval does not cover it. Check it names the newly
    installed binary, then approve at the Mac.
11. Read the release notes for a snapshot version bump. A bump means every
    profile must be approved again (step 8); a release that does not bump leaves
    approvals as they were.

## Rollback

Keep the previous artifact and install it the same way (`install -m 0755`),
after steps 2 and 3 pass on it.
The vault itself is unchanged by an install, upgrade or rollback.

Rolling back is only as safe as the older build's ability to read what the
newer one wrote. From 0.1.0 the only rollback target is a pre-release build,
and those refuse the whole vault once it holds an approval written by 0.1.0:
they predate the versioned approval record, answer `vault_format_unsupported`,
and stop at the door on every read rather than letting the newer approvals go
inert. There is no migration back. The remedy is to reinstall 0.1.0 — or,
under 0.1.0 before downgrading, revoke the approvals that would be left
behind.

If a download fails its checksum, nothing was installed; retry the download,
and report a repeat failure rather than installing the file.
