---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Publish a Mac-signed Ward release asset
tags:
  - release
  - install
summary: Replace the Linux-built darwin asset with the Mac-signed one, regenerate the notes and checksum from its bytes, and verify the published download (DEC-255).
generated:
  by: lore/0.14.1
  at: 2026-11-01T15:33:40.421Z
---

# Publish a Mac-signed Ward release asset

## Purpose

The tag push publishes a Linux-built darwin asset that fails `codesign --verify
--strict`. For 0.1.1 the operator replaces it with a Mac-signed one (DEC-255,
WCLI-96). The Release's sha256, cdhash and checksum file must then name the
Mac-signed bytes, or install step 3 refuses on a cdhash mismatch. This
supersedes the cutting runbook's runner-vs-Mac byte comparison.

## Prerequisites

- The tag's workflow run has published its Release, and `gh` is signed in as
  the operator.
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
   lines and the `.sha256`, and prints both values.
4. Replace the asset and checksum: `gh release upload TAG ward-darwin-arm64
   DIR/ward-darwin-arm64.sha256 --clobber`, then `gh release edit TAG
   --notes-file DIR/release-notes.md`.
5. Verify what is PUBLISHED, not what you wrote: `scripts/verify-published-release.sh
   TAG ward-darwin-arm64`. It re-reads the published notes body, downloads the
   asset and checksum into a new empty directory, and stops on the first
   mismatch: `shasum -a 256 -c`, `codesign --verify --strict`, the downloaded
   sha256 against both the LOCAL signed file and the published notes line, and
   `codesign -dvvv` CDHash against the published notes line. It exits non-zero
   on any failure and prints PASS only when every comparison holds.

**Do not flip the repository to public, and do not tag again, until step 5
prints PASS.**

## Rollback

Steps 1 to 3 change nothing on GitHub. A failure between the upload and the
edit in step 4 leaves the new asset with the old notes; a failure in step 5
leaves both published and names the comparison that failed. Fix the cause and
rerun from step 1: `--clobber` and `gh release edit` converge on the signed
file's bytes.
