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
- The signed file `ward-darwin-arm64`, built on the Mac from the tagged commit
  and ad-hoc signed with `codesign -s - --force`.

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
5. Re-download the published asset into an empty directory. Require
   `codesign --verify --strict` to pass on it, its sha256 to equal the LOCAL
   signed file's, and its cdhash to equal the notes'.

## Rollback

A step that fails leaves the Release as the tag run published it. Fix the cause
and rerun from step 1; `--clobber` makes steps 4 and 5 repeatable.
