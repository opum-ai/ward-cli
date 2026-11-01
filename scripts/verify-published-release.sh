#!/usr/bin/env bash
# Fails closed on the published Release's darwin asset (WCLI-96, DEC-255).
# Run it after `gh release upload` and `gh release edit`, and do not flip the
# repository to public until it prints PASS.
#
# Usage: scripts/verify-published-release.sh <tag> <local-signed-file>
#   Set GH_REPO=owner/name to name the repository outside its checkout.
#
# It re-reads the PUBLISHED notes body (never the file the regeneration script
# wrote, which would be a self-compare), downloads the published asset and
# checksum into a new empty directory, and stops on the first mismatch:
#   1. shasum -a 256 -c on the downloaded checksum file
#   2. codesign --verify --strict on the downloaded asset
#   3. downloaded sha256 == the local signed file's == the published body's line
#   4. codesign -dvvv CDHash= on the download == the published body's line
set -euo pipefail

die() {
  echo "verify-published-release: FAIL: $*" >&2
  exit 1
}

[ "$#" -eq 2 ] || die "usage: verify-published-release.sh <tag> <local-signed-file>"
tag="$1"
local_file="$2"
[ -f "$local_file" ] || die "local signed file not found: $local_file"
[ "$(basename "$local_file")" = "ward-darwin-arm64" ] ||
  die "the local file must be named ward-darwin-arm64"

body="$(gh release view "$tag" --json body -q .body)" ||
  die "could not read the published notes for $tag"
[ -n "$body" ] || die "the published notes for $tag are empty"

# Exactly one line of each, with the exact prefix and hex length the workflow
# writes. Anything else, including a CRLF or stray space, refuses.
sha_pattern='^- sha256 ward-darwin-arm64: [0-9a-f]{64}$'
cdhash_pattern='^- cdhash \(ad-hoc signature, macOS keychain trust follows it\): [0-9a-f]{40}$'
[ "$(printf '%s\n' "$body" | grep -cE "$sha_pattern")" = "1" ] ||
  die "the published notes do not carry exactly one sha256 line"
[ "$(printf '%s\n' "$body" | grep -cE "$cdhash_pattern")" = "1" ] ||
  die "the published notes do not carry exactly one cdhash line"
body_sha="$(printf '%s\n' "$body" | grep -E "$sha_pattern" | sed 's/^.*: //')"
body_cdhash="$(printf '%s\n' "$body" | grep -E "$cdhash_pattern" | sed 's/^.*: //')"

dir="$(mktemp -d)"
[ -z "$(ls -A "$dir")" ] || die "scratch directory is not empty: $dir"
gh release download "$tag" -p 'ward-darwin-arm64*' -D "$dir" ||
  die "could not download the published assets for $tag"
[ -f "$dir/ward-darwin-arm64" ] || die "the Release has no ward-darwin-arm64 asset"
[ -f "$dir/ward-darwin-arm64.sha256" ] ||
  die "the Release has no ward-darwin-arm64.sha256 asset"

(cd "$dir" && shasum -a 256 -c ward-darwin-arm64.sha256) ||
  die "the published checksum file does not match the published asset"

codesign --verify --strict --verbose=2 "$dir/ward-darwin-arm64" ||
  die "codesign --verify --strict failed on the published asset"

downloaded_sha="$(shasum -a 256 "$dir/ward-darwin-arm64" | awk '{print $1}')"
local_sha="$(shasum -a 256 "$local_file" | awk '{print $1}')"
[ "$downloaded_sha" = "$local_sha" ] ||
  die "downloaded sha256 $downloaded_sha is not the local signed file's $local_sha"
[ "$downloaded_sha" = "$body_sha" ] ||
  die "downloaded sha256 $downloaded_sha is not the published notes' $body_sha"

signature="$(codesign -dvvv "$dir/ward-darwin-arm64" 2>&1)" ||
  die "codesign -dvvv failed on the published asset"
downloaded_cdhash="$(printf '%s\n' "$signature" | sed -n 's/^CDHash=//p')"
[ -n "$downloaded_cdhash" ] || die "codesign -dvvv printed no CDHash"
[ "$downloaded_cdhash" = "$body_cdhash" ] ||
  die "downloaded CDHash $downloaded_cdhash is not the published notes' $body_cdhash"

echo "verify-published-release: PASS tag=$tag sha256=$downloaded_sha cdhash=$downloaded_cdhash"
