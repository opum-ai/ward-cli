// Regenerates the release notes' sha256 and cdhash lines and the checksum file
// from the Mac-signed asset the operator is about to upload (WCLI-96, DEC-255).
// It reads and writes local files only: it never calls GitHub.
//
// Usage: node scripts/regenerate-release-metadata.mjs <asset> <notes-in> <out-dir>
//   <asset>     the Mac-signed ward-darwin-arm64 (after codesign --verify --strict)
//   <notes-in>  the published notes body, e.g. from `gh release view <tag> --json body -q .body`
//   <out-dir>   must exist; receives release-notes.md and ward-darwin-arm64.sha256
// Exit 0 printing the two new values; exit 1 naming what was wrong.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checksumFile, rewriteNotes } from "./release-metadata.mjs";

function fail(message) {
  console.error(`regenerate-release-metadata: ${message}`);
  process.exit(1);
}

const [asset, notesIn, outDir] = process.argv.slice(2);
if (asset === undefined || notesIn === undefined || outDir === undefined)
  fail("usage: regenerate-release-metadata.mjs <asset> <notes-in> <out-dir>");

// The notes regex and install step 2 both name this exact file, so a renamed
// signed file would write a checksum that cannot be checked against the asset.
if (basename(asset) !== "ward-darwin-arm64")
  fail("the asset must be named ward-darwin-arm64");

const sha256 = createHash("sha256").update(readFileSync(asset)).digest("hex");
const here = dirname(fileURLToPath(import.meta.url));
const cdhash = spawnSync("node", [join(here, "macho-cdhash.mjs"), asset], {
  encoding: "utf8",
});
if (cdhash.status !== 0) fail(`macho-cdhash failed: ${cdhash.stderr.trim()}`);

let notes;
try {
  notes = rewriteNotes(
    readFileSync(notesIn, "utf8"),
    sha256,
    cdhash.stdout.trim(),
  );
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
writeFileSync(join(outDir, "release-notes.md"), notes);
writeFileSync(
  join(outDir, `${basename(asset)}.sha256`),
  checksumFile(sha256, basename(asset)),
);
console.log(`sha256 ${sha256}`);
console.log(`cdhash ${cdhash.stdout.trim()}`);
