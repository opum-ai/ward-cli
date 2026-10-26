// The release workflow and what it runs (WCLI-82, DEC-246). The workflow cannot
// be exercised here, so these pin its shape as committed: every action pinned
// by SHA, no persisted checkout credential, contents: write on exactly one job,
// no step output interpolated into a shell, and a Release only from a tag. The
// two scripts it runs are measured directly, including a refusal each, so a
// check that had quietly become always-green fails here.
import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildCommand } from "../scripts/build.ts";
import { createTempRoot } from "./support/temp-root.ts";

const root = join(import.meta.dir, "..");
const workflow = readFileSync(
  join(root, ".github", "workflows", "release.yml"),
  "utf8",
);
const dir = createTempRoot("ward-release-");

test("every action is pinned to a full commit SHA", () => {
  const uses = [...workflow.matchAll(/^\s*- uses: (\S+)/gm)].map((m) => m[1]);
  expect(uses.length).toBe(5);
  for (const use of uses) expect(use).toMatch(/@[0-9a-f]{40}$/);
});

test("the checkout does not persist its credential", () => {
  expect(workflow.match(/actions\/checkout@/g)?.length).toBe(2);
  expect(workflow.match(/persist-credentials: false/g)?.length).toBe(2);
});

test("contents: write sits on the release job only, with no id-token", () => {
  const writes = [...workflow.matchAll(/^\s+contents: write$/gm)];
  expect(writes.length).toBe(1);
  const at = workflow.search(/^\s+contents: write$/m);
  expect(workflow.indexOf("  release:")).toBeLessThan(at);
  expect(workflow).toMatch(/^permissions:\n {2}contents: read$/m);
  expect(workflow).not.toContain("id-token");
});

test("it triggers on a v* tag and a manual dry run, and nothing else", () => {
  const on = workflow.slice(
    workflow.indexOf("\non:"),
    workflow.indexOf("\npermissions:"),
  );
  expect(on).toContain('- "v*"');
  expect(on).toContain("workflow_dispatch:");
  expect(on).not.toContain("pull_request");
  // F3 (rv330): a manual dry run must not publish a Release, so the job needs
  // both the push event and a tag ref, not the ref alone.
  expect(workflow).toMatch(
    /release:[\s\S]*?if: github\.event_name == 'push' && github\.ref_type == 'tag'/,
  );
});

test("a tag is checked as annotated and at main's tip, without fetching", () => {
  // F2 and F7 (rv330): fetch-depth: 0 already carries origin/main, so the tag
  // step fetches nothing; and AC1's main == dev makes the tag commit main's
  // tip, which is stricter than the ancestry check it replaces.
  expect(workflow).not.toMatch(/git\s+fetch/);
  expect(workflow).toContain('git cat-file -t "refs/tags/${TAG}"');
  expect(workflow).toContain('git rev-parse "refs/tags/${TAG}^{commit}"');
  expect(workflow).toContain(
    'git merge-base --is-ancestor "$tag_commit" origin/main',
  );
  expect(workflow).toContain('"$tag_commit" != "$(git rev-parse origin/main)"');
});

test("the snapshot-bump note is emitted only for a release that raises it", () => {
  // F5 (rv330): the line is computed against the previous v* tag and the
  // pre-release baseline of 1, never echoed for every release.
  const sentence =
    "This release raises the profile snapshot version: approve your profiles again after installing.";
  expect(workflow.split(sentence).length - 1).toBe(1);
  expect(workflow).toContain(
    'if [ "$snapshot_version_now" -gt "$snapshot_version_before" ]',
  );
  expect(workflow).toContain('snapshot_bump="This release raises');
  expect(workflow).toContain('if [ -n "$snapshot_bump" ]; then');
});

test("the notes say why the release is not a GitHub pre-release", () => {
  // INFO 11 (rv330): prerelease: false stays, and the reason travels with the
  // release rather than living only in a session's memory.
  expect(workflow).toContain("not a GitHub pre-release");
  const publish = readFileSync(
    join(root, "scripts", "publish-release.mjs"),
    "utf8",
  );
  expect(publish).toContain("prerelease: false");
});

test("no expression is interpolated inside a run: body", () => {
  let inRun = false;
  let indent = 0;
  for (const line of workflow.split("\n")) {
    const start = /^(\s*)(- )?run: [|>]/.exec(line);
    if (start) {
      inRun = true;
      indent = (start[1] ?? "").length;
      continue;
    }
    if (inRun) {
      const lead = line.length - line.trimStart().length;
      if (line.trim() !== "" && lead <= indent) inRun = false;
      else expect(line).not.toContain("${{");
    }
    expect(/^\s*(- )?run: .*\$\{\{/.test(line)).toBe(false);
  }
});

test("the build is for darwin-arm64 under the fixed name ward", () => {
  expect(workflow).toContain(
    "bun scripts/build.ts --target bun-darwin-arm64 --outfile out/ward",
  );
});

const base = { entry: "e.ts", outfile: "out/ward" };

test("the build command takes a bun- target and refuses anything else", () => {
  const command = buildCommand({ ...base, target: "bun-darwin-arm64" });
  expect(command).toContain("--target");
  expect(command[command.indexOf("--target") + 1]).toBe("bun-darwin-arm64");
  expect(buildCommand(base)).not.toContain("--target");
  for (const bad of ["darwin", "bun-darwin arm64", "bun-x;rm", "--compile"])
    expect(() => buildCommand({ ...base, target: bad })).toThrow();
});

const cdhash = join(root, "scripts", "macho-cdhash.mjs");
function run(file: string) {
  return spawnSync("node", [cdhash, file], { encoding: "utf8" });
}

test("the cdhash script refuses a file that is not a Mach-O executable", () => {
  const file = join(dir, "not-macho");
  writeFileSync(file, "#!/bin/sh\necho hi\n".repeat(10));
  const r = run(file);
  expect(r.status).toBe(1);
  expect(r.stdout).toBe("");
  expect(r.stderr).toContain("not a thin 64-bit little-endian Mach-O");
});

test.skipIf(process.platform !== "darwin")(
  "the cdhash script agrees with codesign on a compiled executable",
  () => {
    const entry = join(dir, "hello.ts");
    const out = join(dir, "hello");
    writeFileSync(entry, "console.log('hello');\n");
    const build = spawnSync("bun", [
      "build",
      "--compile",
      entry,
      "--outfile",
      out,
    ]);
    expect(build.status).toBe(0);
    const sign = spawnSync("codesign", ["-dvvv", out], { encoding: "utf8" });
    const reported = /^CDHash=([0-9a-f]{40})$/m.exec(sign.stderr)?.[1];
    expect(reported).toMatch(/^[0-9a-f]{40}$/);
    const r = run(out);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe(reported as string);
  },
);
