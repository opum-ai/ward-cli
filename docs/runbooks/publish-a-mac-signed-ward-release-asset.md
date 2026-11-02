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
