// scripts/clean-temp.mjs is the explicit reclamation DEC-49 chose over a
// start-of-run sweep (WCLI-46, ADR 0016), and `bun run clean:temp` is its
// documented entry point. These tests stand a fixture directory in for
// TMPDIR and pin the filter's two halves as a pair in every case: a stale
// ward- directory goes, and the fresh one beside it stays. A blanket delete
// would pass the first assertion alone and fail the second, which is the
// point of asserting both. The summary is read too, because it reports how
// much was scanned, not only what was found.
import { expect, test } from "bun:test";
import { mkdirSync, readdirSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createTempRoot } from "./support/temp-root.ts";

const script = join(import.meta.dir, "..", "scripts", "clean-temp.mjs");
const repoRoot = join(import.meta.dir, "..");
const hour = 60 * 60 * 1000;

interface Fixture {
  readonly root: string;
  readonly stale: string;
  readonly fresh: string;
  readonly recent: string;
  readonly foreign: string;
  readonly file: string;
}

// One fixture per test, under the shared helper so its holder is reclaimed by
// this file's own teardown. The `tmp` directory stands in for os.tmpdir():
// the child only ever sees it through TMPDIR/TEMP.
function fixture(): Fixture {
  const holder = createTempRoot("ward-clean-temp-test-");
  const root = join(holder, "tmp");
  mkdirSync(root);
  const stale = join(root, "ward-packaged-stale");
  const fresh = join(root, "ward-packaged-fresh");
  const recent = join(root, "ward-packaged-recent");
  const foreign = join(root, "other-stale");
  const file = join(root, "ward-file");
  mkdirSync(stale);
  mkdirSync(fresh);
  mkdirSync(recent);
  mkdirSync(foreign);
  writeFileSync(file, "not a directory\n");
  const fourHoursAgo = new Date(Date.now() - 4 * hour);
  const halfAnHourAgo = new Date(Date.now() - 0.5 * hour);
  utimesSync(stale, fourHoursAgo, fourHoursAgo);
  utimesSync(foreign, fourHoursAgo, fourHoursAgo);
  utimesSync(file, fourHoursAgo, fourHoursAgo);
  utimesSync(recent, halfAnHourAgo, halfAnHourAgo);
  return { root, stale, fresh, recent, foreign, file };
}

function run(
  root: string,
  ...args: string[]
): { code: number | undefined; output: string } {
  const result = Bun.spawnSync([process.execPath, script, ...args], {
    env: { ...process.env, TMPDIR: root, TEMP: root, TMP: root },
    stdout: "pipe",
    stderr: "pipe",
  });
  return {
    code: result.exitCode,
    output: `${result.stdout.toString()}${result.stderr.toString()}`,
  };
}

function listing(root: string): string[] {
  return readdirSync(root).sort();
}

test("a stale ward- directory is removed and the fresh one beside it stays", () => {
  const f = fixture();
  const before = listing(f.root);
  const { code, output } = run(f.root);
  expect(code).toBe(0);
  const after = listing(f.root);
  expect(before).toContain("ward-packaged-stale");
  expect(after).not.toContain("ward-packaged-stale");
  expect(after).toContain("ward-packaged-fresh");
  // The scan reports what it read, not only what it found.
  expect(output).toContain(`scanned ${before.length} entries`);
  expect(output).toContain("3 ward-* directories");
  expect(output).toContain("1 older than 120 minutes");
  expect(output).toContain("1 removed");
});

test("the prefix filter keeps a stale directory whose name is not ward-", () => {
  const f = fixture();
  const { code } = run(f.root);
  expect(code).toBe(0);
  expect(listing(f.root)).toContain("other-stale");
});

test("a file carrying the prefix is not a directory and is kept", () => {
  const f = fixture();
  const { code } = run(f.root);
  expect(code).toBe(0);
  expect(listing(f.root)).toContain("ward-file");
});

test("--dry-run reports the stale directory and removes nothing", () => {
  const f = fixture();
  const { code, output } = run(f.root, "--dry-run");
  expect(code).toBe(0);
  expect(output).toContain(`would remove ${f.stale}`);
  expect(output).toContain("dry run");
  expect(listing(f.root)).toContain("ward-packaged-stale");
});

test("--older-than-minutes moves the threshold", () => {
  const f = fixture();
  // The half-hour-old root is inside the default two hours and outside a
  // ten-minute one: the same fixture, two verdicts, so the threshold is
  // shown to be the variable rather than the fixture.
  const kept = run(f.root);
  expect(kept.code).toBe(0);
  expect(kept.output).toContain("1 older than 120 minutes");
  expect(listing(f.root)).toContain("ward-packaged-recent");
  // The first run already reclaimed the four-hour-old root, so this pass
  // reads two ward-* directories and moves only the half-hour-old one.
  const removed = run(f.root, "--older-than-minutes", "10");
  expect(removed.code).toBe(0);
  expect(removed.output).toContain("1 older than 10 minutes");
  expect(listing(f.root)).not.toContain("ward-packaged-recent");
});

test("an unrecognized argument is refused rather than ignored", () => {
  const f = fixture();
  const { code, output } = run(f.root, "--oops");
  expect(code).toBe(2);
  expect(output).toContain("unrecognized argument");
  expect(listing(f.root)).toContain("ward-packaged-stale");
});

test("`bun run clean:temp` is the entry point that reaches the script", () => {
  const f = fixture();
  const result = Bun.spawnSync([process.execPath, "run", "clean:temp"], {
    cwd: repoRoot,
    env: { ...process.env, TMPDIR: f.root, TEMP: f.root, TMP: f.root },
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(result.exitCode).toBe(0);
  const after = listing(f.root);
  expect(after).not.toContain("ward-packaged-stale");
  expect(after).toContain("ward-packaged-fresh");
});
