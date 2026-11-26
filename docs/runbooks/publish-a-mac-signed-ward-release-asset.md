---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Publish a Mac-signed Ward release asset
tags:
  - release
  - install
summary: After a tag run check the billing and verify the published asset; replacing it by hand is the fallback.
generated:
  by: lore/0.14.1
  at: 2026-11-01T15:33:40.421Z
---

# Publish a Mac-signed Ward release asset

## Purpose

A tag push signs and verifies the asset on a hosted macOS runner (DEC-253
(a4)). Prerequisites and Steps are the fallback sitting route (DEC-255 (1)).

## After a tag run

TAG is the tag and DIR an empty scratch directory.

1. Find the tag run: `gh run list --workflow release.yml --event push --json
   databaseId,headBranch,headSha`. RUN is the databaseId of the row whose
   headBranch is TAG.
2. `gh api repos/opum-ai/ward-cli/actions/runs/RUN/timing --jq
   .billable.MACOS.total_ms` must print `0`; otherwise stop and report.
3. `gh run download RUN -n ward-darwin-arm64 -D DIR`, then
   `scripts/verify-published-release.sh TAG DIR/ward-darwin-arm64`. It compares
   the uploaded artifact with the published asset; it must print PASS before
   any new tag.

The first tag run is the first CI use of `sha256sum --check` on a macOS `shasum`
file; step 3's `shasum -c` catches a bad one. Step 6 below was v0.1.0's only.

## Prerequisites

- The tag's run has published its Release; `gh` is signed in as the operator.
- The signed file `ward-darwin-arm64`: a detached checkout of the tag's commit,
  `bun install --frozen-lockfile --os=darwin --cpu=arm64` and `bun
  scripts/build.ts --target bun-darwin-arm64 --outfile out/ward`, copied to
  that name and signed with `codesign -s - --force`.

## Steps

TAG is the release tag and DIR an empty scratch directory.

1. `codesign --verify --strict --verbose=2 ward-darwin-arm64`; stop on failure.
2. `gh release view TAG --json body -q .body > notes.md`.
3. `node scripts/regenerate-release-metadata.mjs ward-darwin-arm64 notes.md DIR`
   rewrites the notes' sha256 and cdhash lines and the `.sha256`.
4. `gh release upload TAG ward-darwin-arm64 DIR/ward-darwin-arm64.sha256
   --clobber`, then `gh release edit TAG --notes-file DIR/release-notes.md`.
5. Verify what is PUBLISHED: `scripts/verify-published-release.sh TAG
   ward-darwin-arm64`. PASS only if the checksum, the strict `codesign`, the
   sha256 against the local file and the notes, and the CDHash all hold.

6. Mark v0.1.0 superseded: `gh release view v0.1.0 --json body -q .body >
   old.md`. If `grep -qxF 'Superseded by v0.1.1: install that release.' old.md`
   fails, append that line. Then `gh release edit v0.1.0 --notes-file old.md
   --latest=false`.

**Do not tag again until step 5 prints PASS.**

## Rollback

Steps 1 to 3 change nothing on GitHub. After a failed step 4 or 5, fix the cause
and rerun from step 1: `--clobber` converges on the signed file's bytes.

**Immutable releases remove this route (WCLI-103).** If the operator enables them
([protect the release path](protect-the-release-path.md), step 4), a published
release's assets and tag are locked, so step 4's `gh release upload --clobber`
is refused and a wrong asset cannot be repaired in place: supersede it with a new
version instead. GitHub's documentation says the title and notes stay editable
after publish, so `gh release edit --notes-file` (steps 4 and 6) should still
work. That was read from GitHub's documentation, not measured on this
repository's release; confirm it on the first immutable release before relying
on it.

## Developer ID signing and the rehearsal (WCLI-185)

The release workflow's `sign` job re-signs the build job's ad-hoc artifact with the
Developer ID identity (identifier `ai.opum.ward`), notarizes it and uploads
`ward-darwin-arm64-signed`; verify, attest and release act on that artifact. It
needs the operator's steps first (the certificate, the notarization key, the
`release` environment and its secrets: the signing-path reference lists all nine).

- **Rehearsal:** `gh workflow run release.yml --ref main`, then approve the
  `release` deployment when the reviewer prompt appears. It signs and notarizes,
  uploads the signed binary as a public run artifact, and publishes nothing.
  Read the run before any tag: notarization `Accepted`, the designated
  requirement names the team and `ai.opum.ward`, and the smoke step in the
  `verify` job (the signed binary prints a version) passed without entitlements.
  A dispatch from any other branch builds only: signing is main-only.
  A passing `--version` is necessary but not sufficient: it never reaches JIT
  tier-up, so a binary can pass it without `allow-jit` and still crash on a real
  command under the hardened runtime. The operator's Mac run exercises real
  commands (a synthetic vault, `ward --help` and an actual operation) before the
  first tag.
- **Certificate expiry date:** not recorded yet. The operator adds it here when
  the certificate exists (operator step 2); a renewal is expected to keep the
  team id and identifier, unmeasured.
- **Release notes wording:** the notes' cdhash line and closing sentence still
  say ad hoc. That is deliberately unchanged until the operator's Mac shows the
  Keychain behaviour of a Developer ID build, and must be reworded (the notes
  template, `scripts/release-metadata.mjs` and its tests) before the first
  Developer ID release is described to users.
  **Blocker on the first Developer ID tag:** nothing yet stops a tag from
  publishing notes that say "ad-hoc signature" for a Developer ID binary (the
  `CDHASH_LINE` pattern in `scripts/release-metadata.mjs` ties the wording). Do
  not cut that tag until the wording is changed.
