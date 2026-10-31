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
  expect(uses.length).toBe(6);
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
  // Finding 3 (rv331): annotated-ness is read from the stored ref over REST,
  // never from what actions/checkout left at refs/tags/<tag>. The command
  // form is what is banned — the workflow names it in a comment explaining
  // why it went.
  expect(workflow).not.toContain('git cat-file -t "refs/tags/');
  expect(workflow).toContain("run: node scripts/check-release-tag.mjs");
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
  // Finding 11 (rv331) and new finding 1 (rv331b): the previous tag comes from
  // `git tag --merged`, never from `git describe`. describe dies whenever the
  // baseline has no matching tag, so its failure has to be read as a result —
  // and on the v0.1.0 tag push its baseline is that tag's own parent, which
  // v0.1.0 can never describe, so the old form would have failed the release
  // right after the tag was pushed. `git tag` separates the cases by exit code
  // instead of by message: nothing reachable lists nothing and exits 0, and a
  // real failure exits non-zero. Measured in a scratch clone in all four
  // states, recorded on WCLI-82.
  // The command form is what is banned; the step's own comment names `git
  // describe` to explain why it went, and that explanation is worth keeping.
  expect(workflow).not.toMatch(/git describe\s+--/);
  expect(workflow).toContain(
    `git tag --list 'v*' --merged "$baseline" --sort=-v:refname`,
  );
  expect(workflow).toContain("previous_tag=\"${tags%%$'\\n'*}\"");
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
const tagCheck = join(root, "scripts", "check-release-tag.mjs");
const tagObjectSha = "a".repeat(40);
const commitSha = "b".repeat(40);

// The script runs as a child process against a local server, so the server has
// to be able to answer while the parent waits: spawnSync would block the only
// listener and deadlock. `repo` selects the fixture the server returns.
async function runTagCheck(
  repo: "annotated" | "lightweight" | "missing",
): Promise<{ code: number; stdout: string; stderr: string }> {
  const server = Bun.serve({
    port: 0,
    fetch(request) {
      if (request.headers.get("authorization") !== "Bearer test-token")
        return new Response("bad credentials", { status: 401 });
      const owner = new URL(request.url).pathname.split("/")[2];
      if (owner === "missing")
        return new Response('{"message":"Not Found"}', { status: 404 });
      const type = owner === "lightweight" ? "commit" : "tag";
      return Response.json({
        ref: "refs/tags/v0.1.0",
        object: { type, sha: type === "tag" ? tagObjectSha : commitSha },
      });
    },
  });
  const proc = Bun.spawn(["node", tagCheck], {
    env: {
      ...process.env,
      GH_TOKEN: "test-token",
      REPO: `${repo}/ward-cli`,
      TAG: "v0.1.0",
      GITHUB_API_URL: `http://127.0.0.1:${server.port}`,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  server.stop(true);
  return { code, stdout, stderr };
}

test("the annotated-tag check accepts a tag object and refuses the rest", async () => {
  // Finding 3 (rv331), both ways: the check is the whole gate, so a version
  // that only ever refused, or only ever accepted, would pass a string match
  // and still block or wave through a release.
  const annotated = await runTagCheck("annotated");
  expect(annotated.code).toBe(0);
  expect(annotated.stdout).toContain(
    `is an annotated tag object ${tagObjectSha}`,
  );

  const lightweight = await runTagCheck("lightweight");
  expect(lightweight.code).toBe(1);
  expect(lightweight.stderr).toContain("is not an annotated tag");
  expect(lightweight.stderr).toContain("commit");

  const missing = await runTagCheck("missing");
  expect(missing.code).toBe(1);
  expect(missing.stderr).toContain("HTTP 404");
});

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

test("the notes link the install runbook by full URL at the tag", () => {
  // Read from the notes step alone: REPO is also set in other steps, so a
  // whole-file match would stay green with this step's REPO deleted.
  const start = workflow.indexOf("- name: Hash it and write the release notes");
  expect(start).toBeGreaterThan(-1);
  const end = workflow.indexOf("- uses:", start);
  expect(end).toBeGreaterThan(start);
  const step = workflow.slice(start, end);
  expect(step).toMatch(/^\s+REPO: \$\{\{ github\.repository \}\}$/m);
  const notes = step.slice(
    step.indexOf("{\n", step.indexOf("run: |")),
    step.indexOf("} > release-notes.md"),
  );
  const line = notes
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.startsWith('echo "Install and upgrade: '));
  expect(line).toBe(
    'echo "Install and upgrade: https://github.com/${REPO}/blob/${REF_NAME}/docs/runbooks/install-and-upgrade-ward-from-a-release.md"',
  );
});

// WCLI-96 (W-1, DEC-253): the release is gated on codesign's verdict, not on a
// displayed cdhash. Each assertion reads one job's own text, so deleting the
// step, the dependency or the runner from that job turns exactly one red.
function jobText(name: string): string {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  expect(start).toBeGreaterThan(-1);
  const rest = workflow.slice(start + 1);
  const next = rest.slice(1).search(/^ {2}[a-z][a-z-]*:\n/m);
  return next === -1 ? rest : rest.slice(0, next + 1);
}

test("a verify job runs codesign --verify --strict on the artifact the release would publish", () => {
  const verify = jobText("verify");
  expect(verify).toMatch(/^\s+needs: build$/m);
  expect(verify).toMatch(
    /^\s+if: github\.event_name == 'push' && github\.ref_type == 'tag'$/m,
  );
  expect(verify).toContain("actions/download-artifact@");
  expect(verify).toMatch(/^\s+name: ward-darwin-arm64$/m);
  expect(verify).toMatch(
    /^\s+run: codesign --verify --strict --verbose=2 out\/ward-darwin-arm64$/m,
  );
});

test("the verify job runs on a GitHub-hosted macOS runner, never a self-hosted one", () => {
  const verify = jobText("verify");
  expect(verify).toMatch(/^\s+runs-on: macos-14$/m);
  expect(verify).not.toContain("self-hosted");
  expect(verify).not.toContain("contents: write");
});

test("the release job needs the verify job, so an unverified artifact cannot publish", () => {
  expect(jobText("release")).toMatch(/^\s+needs: \[build, verify\]$/m);
});

test("the install runbook verifies the signature and stops on a failure, not only compares a cdhash", () => {
  const runbook = readFileSync(
    join(
      root,
      "docs",
      "runbooks",
      "install-and-upgrade-ward-from-a-release.md",
    ),
    "utf8",
  ).replace(/\s+/g, " ");
  expect(runbook).toContain(
    "codesign --verify --strict --verbose=2 ward-darwin-arm64",
  );
  expect(runbook).toContain("It must exit 0. Stop on any other exit");
  expect(runbook.indexOf("codesign --verify --strict")).toBeLessThan(
    runbook.indexOf("codesign -dvvv"),
  );
});
