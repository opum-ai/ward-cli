// DEC-240 hardening of .github/workflows/ci.yml (WCLI-80). The Tracker job's
// version read is a script so both verdicts can be exercised here: a
// declaration that is not an exact MAJOR.MINOR.PATCH version must fail by
// name, and this repository's real declaration must still pass. The workflow
// assertions pin the other items against the file as committed, so a later
// edit that drops a flag turns this red rather than leaving CI quietly softer.
import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createTempRoot } from "./support/temp-root.ts";

const root = join(import.meta.dir, "..");
const script = join(root, "scripts", "read-quest-version.mjs");
const dir = createTempRoot("ward-ci-hardening-");

function read(claudeMd: string) {
  const file = join(dir, "CLAUDE.md");
  writeFileSync(file, claudeMd);
  const run = spawnSync("node", [script, file], { encoding: "utf8" });
  return { status: run.status, out: run.stdout, err: run.stderr };
}

const block = (line: string) =>
  `<!-- quest:agent-instructions:begin -->\n${line}\n<!-- quest:agent-instructions:end -->\n`;

test("reads an exact version from inside the block", () => {
  const r = read(block("This project uses Quest CLI 0.14.1 for tracker."));
  expect(r.status).toBe(0);
  expect(r.out).toBe("0.14.1\n");
});

test("this repository's own declaration passes", () => {
  const run = spawnSync("node", [script, join(root, "CLAUDE.md")], {
    encoding: "utf8",
  });
  expect(run.status).toBe(0);
  expect(run.stdout).toMatch(/^[0-9]+\.[0-9]+\.[0-9]+\n$/);
});

for (const bad of [
  "0.14",
  "0.14.",
  "0.14.1-beta.1",
  "^0.14.1",
  "latest",
  "0.14.1.2",
]) {
  test(`rejects '${bad}' by name and prints no version`, () => {
    const r = read(block(`This project uses Quest CLI ${bad} for tracker.`));
    expect(r.status).toBe(1);
    expect(r.out).toBe("");
    expect(r.err).toContain("::error");
    expect(r.err).toContain(`'${bad}'`);
  });
}

test("a declaration outside the block is not consulted", () => {
  const r = read(
    `Quest CLI 9.9.9 appears here first.\n${block("no declaration in here")}`,
  );
  expect(r.status).toBe(1);
  expect(r.err).toContain("No 'Quest CLI <version>' line");
});

test("missing markers fail by name", () => {
  const r = read("This project uses Quest CLI 0.14.1 for tracker.\n");
  expect(r.status).toBe(1);
  expect(r.err).toContain("markers were not found");
});

const ci = readFileSync(join(root, ".github", "workflows", "ci.yml"), "utf8");

test("every checkout sets persist-credentials: false", () => {
  const checkouts = [...ci.matchAll(/uses: actions\/checkout@/g)];
  const disabled = [...ci.matchAll(/persist-credentials: false/g)];
  expect(checkouts.length).toBe(3);
  expect(disabled.length).toBe(checkouts.length);
});

test("every global npm install skips dependency lifecycle scripts", () => {
  const installs = ci
    .split("\n")
    .filter(
      (line) => /npm install\b/.test(line) && !line.trim().startsWith("#"),
    );
  expect(installs.length).toBe(2);
  for (const line of installs) {
    expect(line).toContain("--ignore-scripts");
    expect(line).toContain("--global");
  }
});

test("no step output is interpolated inside a run: body", () => {
  const lines = ci.split("\n");
  let inRun = false;
  let indent = 0;
  for (const line of lines) {
    const run = /^(\s*)(- )?run: [|>]/.exec(line);
    if (run) {
      inRun = true;
      indent = (run[1] ?? "").length;
      continue;
    }
    if (inRun) {
      const lead = line.length - line.trimStart().length;
      if (line.trim() !== "" && lead <= indent) inRun = false;
      else expect(line).not.toContain("${{");
    }
    if (/^\s*(- )?run: .*\$\{\{/.test(line)) throw new Error(line);
  }
});
