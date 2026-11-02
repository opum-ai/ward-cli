---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Publish a Mac-signed Ward release asset
tags:
  - release
  - install
summary: After a tag run check the macOS billing is zero and verify the download; replacing the asset by hand is the fallback.
generated:
  by: lore/0.14.1
  at: 2026-11-01T15:33:40.421Z
---

# Publish a Mac-signed Ward release asset

## Purpose

A tag push signs and verifies the asset on a hosted macOS runner (DEC-253
(a4)). Prerequisites and Steps below are the fallback sitting route (DEC-255 (1)).

## After a tag run

1. `gh api repos/opum-ai/ward-cli/actions/runs/RUN/timing --jq
   .billable.MACOS.total_ms` must print `0`; otherwise stop and report.
2. Run step 5 below.

## Prerequisites

- The tag's run has published its Release; `gh` is signed in as the operator.
- The signed file `ward-darwin-arm64`, built from a detached checkout of the
  tag's commit as the cutting runbook's step 6 builds (`bun install
  --frozen-lockfile --os=darwin --cpu=arm64`, `bun scripts/build.ts --target
  bun-darwin-arm64 --outfile out/ward`), copied to `ward-darwin-arm64` and
  signed with `codesign -s - --force`.

## Steps

TAG is the release tag and DIR an empty scratch directory.

1. Verify the signed file: `codesign --verify --strict --verbose=2
   ward-darwin-arm64`. Stop on any non-zero exit.
2. Save the published notes: `gh release view TAG --json body -q .body >
   notes.md`.
3. Regenerate from the signed file: `node scripts/regenerate-release-metadata.mjs
   ward-darwin-arm64 notes.md DIR`. It rewrites the notes' sha256 and cdhash
   lines and the `.sha256`.
4. Replace the asset and checksum: `gh release upload TAG ward-darwin-arm64
   DIR/ward-darwin-arm64.sha256 --clobber`, then `gh release edit TAG
   --notes-file DIR/release-notes.md`.
5. Verify what is PUBLISHED: `scripts/verify-published-release.sh TAG
   ward-darwin-arm64`. It re-reads the published notes, downloads into a new
   empty directory, and stops on the first mismatch: the checksum file, `codesign
   --verify --strict`, the sha256 against the LOCAL file and the notes line, and
   `codesign -dvvv` CDHash against the notes line. PASS only if all hold.

6. Mark v0.1.0 superseded (not republished): `gh release view v0.1.0 --json
   body -q .body > old.md`. If `grep -qxF 'Superseded by v0.1.1: install that
   release.' old.md` fails, append that line. Then `gh release edit v0.1.0
   --notes-file old.md --latest=false`.

**Do not flip the repository to public, and do not tag again, until step 5
prints PASS and step 6 is done.**

## Rollback

Steps 1 to 3 change nothing on GitHub. A step 4 failure can leave the new
asset with the old notes, or no asset or checksum; a step 5 failure leaves both
published and names the comparison. Fix the cause and rerun from step 1:
`--clobber` and `gh release edit` converge on the signed file's bytes.
