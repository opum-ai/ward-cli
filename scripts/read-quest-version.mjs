// Prints the Quest CLI version CLAUDE.md's managed Quest block declares, and
// nothing else. CI hands the result to `npm install`, so it must be exactly
// MAJOR.MINOR.PATCH: a partial version, a prerelease, a range or a tag would
// reach npm as something other than the one release the block names.
//
// The version is read only from between the block's markers. A "Quest CLI x"
// line anywhere else in the file (a profile paragraph, a quoted example) is not
// the declaration and is never consulted (DEC-240 item 3).
//
// Usage: node scripts/read-quest-version.mjs [path-to-CLAUDE.md]
// Exit 0 with the version on stdout, or exit 1 with a ::error:: line naming
// which assertion failed: markers, declaration, or format.
import { readFileSync } from "node:fs";

const BEGIN = "<!-- quest:agent-instructions:begin -->";
const END = "<!-- quest:agent-instructions:end -->";
const EXACT = /^[0-9]+\.[0-9]+\.[0-9]+$/;

const file = process.argv[2] ?? "CLAUDE.md";

function fail(message) {
  console.error(`::error file=${file}::${message}`);
  process.exit(1);
}

const text = readFileSync(file, "utf8");
const begin = text.indexOf(BEGIN);
const end = text.indexOf(END, begin + 1);
if (begin === -1 || end === -1) {
  fail(`The managed Quest block markers were not found in ${file}.`);
}

const block = text.slice(begin + BEGIN.length, end);
const declaration = /Quest CLI (\S+)/.exec(block);
if (!declaration) {
  fail("No 'Quest CLI <version>' line found inside the managed Quest block.");
}

const version = declaration[1];
if (!EXACT.test(version)) {
  fail(
    `The managed Quest block declares Quest CLI '${version}', which is not an exact MAJOR.MINOR.PATCH version.`,
  );
}

console.log(version);
