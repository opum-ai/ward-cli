// Reclaims stale `ward-*` roots that killed test runs left in this machine's
// TMPDIR (WCLI-46, DEC-49).
//
// Why this is a command a person runs rather than something a test run does:
// the roots live in a shared directory, and a sweep at the start of every run
// is a destructive delete of directories the running process did not create.
// The permission layer refused exactly that capability when a test helper
// first exercised it, and an age filter cannot tell residue from a live long
// run - measured 2026-09-29, of 869 ward-* roots in one TMPDIR, 158 were under
// two hours old. So cleanup inside a run is teardown-scoped only
// (test/support/temp-root.ts removes its own root in the importing file's
// afterAll), and reclaiming what earlier killed runs left behind is this
// explicit command, run deliberately and never by a test run.
//
// The filter is the one the rejected sweep would have used: direct children of
// os.tmpdir(), named with the `ward-` prefix, that are real directories (a
// symlink is neither followed nor removed), whose own modification time is
// older than the threshold. A live run's root keeps a fresh mtime because the
// run keeps writing inside it, which is the best signal available and why the
// default threshold is hours rather than minutes.
import { readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const prefix = "ward-";
const defaultAgeMinutes = 120;

const usage = `usage: node scripts/clean-temp.mjs [--dry-run] [--older-than-minutes <n>]

Removes ward-* directories older than the threshold (default ${defaultAgeMinutes}
minutes) from ${tmpdir()}. Runs deliberately; never invoked by a test run.`;

function fail(message) {
  console.error(message);
  console.error(usage);
  process.exit(2);
}

const options = { dryRun: false, ageMinutes: defaultAgeMinutes };
for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--dry-run") {
    options.dryRun = true;
  } else if (argument === "--older-than-minutes") {
    const value = Number(process.argv[index + 1]);
    if (!Number.isFinite(value) || value < 0)
      fail(
        `--older-than-minutes needs a number of minutes, got ${process.argv[index + 1]}`,
      );
    options.ageMinutes = value;
    index += 1;
  } else {
    fail(`unrecognized argument: ${argument}`);
  }
}

// Best effort: a size that cannot be read is not a reason to leave the
// directory behind, and the number is a report rather than a decision.
function directoryBytes(path) {
  let total = 0;
  const stack = [path];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const child = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(child);
      } else if (entry.isFile()) {
        try {
          total += statSync(child).size;
        } catch {
          // The file vanished under us; the directory is still reclaimed.
        }
      }
    }
  }
  return total;
}

function formatBytes(bytes) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

const root = tmpdir();
const cutoff = Date.now() - options.ageMinutes * 60 * 1000;

let entries;
try {
  entries = readdirSync(root, { withFileTypes: true });
} catch (error) {
  console.error(`cannot read ${root}: ${error.message}`);
  process.exit(1);
}

// The positive control: the summary below reports how much was read, not only
// what was found, so an empty scan and a broken scan cannot print alike.
const wardDirectories = entries.filter(
  (entry) => entry.isDirectory() && entry.name.startsWith(prefix),
);
const stale = [];
for (const entry of wardDirectories) {
  const path = join(root, entry.name);
  let stats;
  try {
    stats = statSync(path);
  } catch {
    continue; // A live run reclaimed it between the listing and the stat.
  }
  if (stats.mtimeMs < cutoff) stale.push(path);
}

let removed = 0;
let reclaimed = 0;
const failures = [];
for (const path of stale) {
  if (options.dryRun) {
    console.log(`would remove ${path}`);
    continue;
  }
  const bytes = directoryBytes(path);
  try {
    rmSync(path, { recursive: true, force: true });
    removed += 1;
    reclaimed += bytes;
    console.log(`removed ${path}`);
  } catch (error) {
    failures.push(`${path}: ${error.message}`);
    console.error(`could not remove ${path}: ${error.message}`);
  }
}

const summary = [
  `scanned ${entries.length} entries in ${root}`,
  `${wardDirectories.length} ${prefix}* directories`,
  `${stale.length} older than ${options.ageMinutes} minutes`,
  options.dryRun
    ? `${stale.length} would be removed (dry run)`
    : `${removed} removed, ${formatBytes(reclaimed)} reclaimed`,
];
console.log(summary.join("; "));

if (failures.length > 0) {
  console.error(`${failures.length} could not be removed.`);
  process.exit(1);
}
