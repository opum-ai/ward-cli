// The release workflow and what it runs (WCLI-82, DEC-246). The workflow cannot
// be exercised here, so these pin its shape as committed: every action pinned
// by SHA, no persisted checkout credential, contents: write on exactly one job,
// no step output interpolated into a shell, and a Release only from a tag. The
// two scripts it runs are measured directly, including a refusal each, so a
// check that had quietly become always-green fails here.
import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildCommand } from "../scripts/build.ts";
import { createTempRoot } from "./support/temp-root.ts";

const root = join(import.meta.dir, "..");
const workflow = readFileSync(
  join(root, ".github", "workflows", "release.yml"),
  "utf8",
);
const dir = createTempRoot("ward-release-");

// A step's `uses` is read from parsed YAML, not from a line pattern: flow style
// (`- {uses: x@main}`), a quoted `"uses":`, extra spaces after the colon and a
// value on the next line all spell the same property, and a text match sees
// none of them. The presence check is deliberate, so a runtime without the API
// fails loudly instead of falling back to a text match that would pass.
type ParsedJob = Record<string, unknown> & {
  steps?: Record<string, unknown>[];
};
type ParsedWorkflow = Record<string, unknown> & {
  jobs: Record<string, ParsedJob>;
};
function parseWorkflow(): ParsedWorkflow {
  const yaml = Bun.YAML as unknown as
    | { parse?: (input: string) => unknown }
    | undefined;
  if (typeof yaml?.parse !== "function")
    throw new Error(
      "Bun.YAML.parse is required (Bun >= 1.3.14); refusing to fall back to a text match",
    );
  return yaml.parse(workflow) as ParsedWorkflow;
}

test("every action is pinned to a full commit SHA", () => {
  // Every job's every step, whatever spelling the key uses.
  const steps = Object.values(parseWorkflow().jobs).flatMap(
    (job) => job.steps ?? [],
  );
  // Positive control: a parse that read nothing must fail here, not pass.
  expect(steps.length).toBeGreaterThan(0);
  const withUses = steps.filter((step) => "uses" in step);
  expect(withUses).toHaveLength(11);
  for (const step of withUses) {
    expect(typeof step.uses).toBe("string");
    expect(step.uses as string).toMatch(/@[0-9a-f]{40}$/);
  }
});

test("the checkout does not persist its credential", () => {
  expect(workflow.match(/actions\/checkout@/g)?.length).toBe(3);
  expect(workflow.match(/persist-credentials: false/g)?.length).toBe(3);
});

test("contents: write sits on the release job only, and id-token on the attest job only", () => {
  const writes = [...workflow.matchAll(/^\s+contents: write$/gm)];
  expect(writes.length).toBe(1);
  const at = workflow.search(/^\s+contents: write$/m);
  expect(workflow.indexOf("  release:")).toBeLessThan(at);
  expect(workflow).toMatch(/^permissions:\n {2}contents: read$/m);
  // WCLI-109: the one job that can mint an attestation is not the one that
  // can write the Release, and neither permission is anywhere else.
  expect(workflow.match(/^\s+id-token: write$/gm)?.length).toBe(1);
  // The workflow-level default is pinned by parse: a job that omitted its own
  // permissions block (a future sign job) would inherit exactly this, so
  // neither id-token nor attestations may ever appear here.
  expect(parseWorkflow().permissions).toEqual({ contents: "read" });
  const attest = parseWorkflow().jobs.attest ?? {};
  expect(attest.permissions).toEqual({
    contents: "read",
    "id-token": "write",
    attestations: "write",
  });
  expect(parseWorkflow().jobs.release?.permissions).toEqual({
    contents: "write",
  });
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
  expect(verify).toMatch(/^\s+needs: \[build, sign\]$/m);
  expect(verify).toMatch(
    /^\s+if: github\.event_name == 'workflow_dispatch' \|\| \(github\.event_name == 'push' && github\.ref_type == 'tag'\)$/m,
  );
  expect(verify).toContain("actions/download-artifact@");
  expect(verify).toMatch(/^\s+name: ward-darwin-arm64-signed$/m);
  expect(verify).toMatch(
    /^\s+run: codesign --verify --strict --verbose=2 out\/ward-darwin-arm64$/m,
  );
});

test("a manual dry run exercises the gate but release still cannot run on it", () => {
  const release = jobText("release");
  expect(release).not.toContain("workflow_dispatch");
  expect(release).toMatch(
    /^\s+if: github\.event_name == 'push' && github\.ref_type == 'tag'$/m,
  );
  expect(jobText("verify")).toContain(
    "github.event_name == 'workflow_dispatch'",
  );
  expect(jobText("build")).not.toMatch(/^\s+if: github\.event_name/m);
});

// WCLI-120 (DEC-253 (a2)): while the repository is private the verify job takes
// no hosted macOS runner and its verifying steps are skipped; once it is public
// the same text resolves to macos-15 and the steps run. The conditions are
// read from the workflow's own text and evaluated, so the proof is of what the
// workflow says, not of a copy. The forms in use are `== true`, `!= true`, `&&`,
// `||` and fromJSON, which mean the same in JavaScript. A guard against false
// would not: GitHub coerces null and false alike, so `null == false` is true
// there and false here. Add that form only with its own evaluator.
function evaluate(expression: string, repository: object | undefined): unknown {
  // An absent property is null in a workflow expression, where a bare property
  // access in JavaScript throws; `at` walks the path and yields null instead.
  const root = { event: { repository } };
  const at = (path: string): unknown =>
    path
      .split(".")
      .reduce<unknown>(
        (node, key) =>
          node === null || node === undefined
            ? null
            : ((node as Record<string, unknown>)[key] ?? null),
        root,
      );
  const translated = expression.replace(
    /github\.([A-Za-z_.]+)/g,
    (_, path: string) => `at("${path}")`,
  );
  return new Function("at", "fromJSON", `return (${translated});`)(
    at,
    JSON.parse,
  );
}

function expressionAfter(text: string, key: string): string {
  const line = new RegExp(`^\\s+${key}: \\$\\{\\{ (.*) \\}\\}$`, "m").exec(
    text,
  );
  expect(line).not.toBeNull();
  return line?.[1] ?? "";
}

// The verify job's steps, split at their list markers. Pinned below to exactly
// the notice, the download and the codesign step, so a step added anywhere in
// the job, guarded or not, is a red test.
function verifySteps(): string[] {
  const verify = jobText("verify");
  const start = verify.indexOf("\n    steps:\n");
  expect(start).toBeGreaterThan(-1);
  return verify
    .slice(start + "\n    steps:\n".length)
    .split(/^(?= {6}-(?: |$))/m)
    .filter((step) => step.trim() !== "");
}

function stepIfs(): string[] {
  return verifySteps().map((step) => {
    const guards = [...step.matchAll(/^ {8}if: (.*)$/gm)];
    expect(guards).toHaveLength(1);
    return guards[0]?.[1] ?? "";
  });
}

test("while private the verify job takes no hosted macOS runner; once public it takes macos-15", () => {
  const runsOn = expressionAfter(jobText("verify"), "runs-on");
  expect(evaluate(runsOn, { private: true })).toEqual([
    "self-hosted",
    "Linux",
    "ARM64",
  ]);
  expect(evaluate(runsOn, { private: false })).toBe("macos-15");
});

test("a repository payload without its visibility fails closed to the verifying path", () => {
  const runsOn = expressionAfter(jobText("verify"), "runs-on");
  expect(evaluate(runsOn, {})).toBe("macos-15");
  expect(evaluate(runsOn, { private: "true" })).toBe("macos-15");
  expect(evaluate(runsOn, { private: null })).toBe("macos-15");
});

test("the verify job has exactly the notice, the download, the codesign step and the smoke test, in that order", () => {
  const steps = verifySteps();
  expect(steps).toHaveLength(4);
  // Each step is one full shape anchored at both ends, so a key inserted
  // between its own lines (a `shell:` between the name and the if, say) is red,
  // and so is a tab after the dash that merges it into a neighbour.
  expect(steps[0]).toMatch(
    /^ {6}- name: The hosted macOS check is skipped while the repository is private\n {8}if: github\.event\.repository\.private == true\n {8}run: \|\n {10}echo "::notice::codesign --verify --strict is skipped here[^\n"]*"\n*$/,
  );
  expect(steps[1]).toMatch(
    /^ {6}- uses: actions\/download-artifact@[0-9a-f]{40} # v8\.0\.2\n {8}if: github\.event\.repository\.private != true\n {8}with:\n {10}name: ward-darwin-arm64-signed\n {10}path: out\n*$/,
  );
  // The job has exactly one action, whatever its indent or list form.
  expect(jobText("verify").match(/^\s+(?:- )?uses:/gm)).toHaveLength(1);
  expect(steps[2]).toMatch(
    /^ {6}- name: codesign verifies the signature strictly\n {8}if: github\.event\.repository\.private != true\n {8}run: codesign --verify --strict --verbose=2 out\/ward-darwin-arm64\n*$/,
  );
  // The smoke test of the signed binary (WCLI-185) runs here, in the job with no
  // environment and no secrets, and only after the strict signature check.
  expect(steps[3]).toContain(
    "- name: The signed binary starts and reports a version",
  );
  expect(steps[3]).toContain("if: github.event.repository.private != true");
  expect(steps[3]).toContain('version="$(out/ward-darwin-arm64 --version)"');
  expect(steps[3]).not.toMatch(/codesign|--force|secrets\./);
  // One command per step: nothing re-signs or rewrites the artifact before the
  // check, and only the smoke step runs the binary.
  expect(steps.join("").match(/\brun:/g)).toHaveLength(3);
});

// The text helpers above (jobText) take the first `verify:` they find, so a
// decoy copy of the job inside a top-level block scalar would be read by every
// text assertion while the YAML parser resolves the real, neutered job. This
// case reads the PARSED job and compares it in full, so the decoy cannot help:
// the real codesign step must be the command, and nothing else may be there.
test("the parsed verify job is exactly the known job, with the real codesign command", () => {
  const parsed = parseWorkflow();
  expect(parsed.name).toBe("Release");
  expect(Object.keys(parsed.jobs).sort()).toEqual([
    "attest",
    "build",
    "release",
    "sign",
    "verify",
  ]);
  const verify = parsed.jobs.verify as ParsedJob;
  const steps = verify.steps as Record<string, unknown>[];
  expect(steps).toHaveLength(4);
  const [notice, download, codesign, smoke] = steps as [
    Record<string, unknown>,
    Record<string, unknown>,
    Record<string, unknown>,
    Record<string, unknown>,
  ];
  expect(Object.keys(smoke ?? {}).sort()).toEqual(["if", "name", "run"]);
  expect(smoke?.if).toBe("github.event.repository.private != true");
  expect(notice?.run as string).toMatch(
    /^echo "::notice::codesign --verify --strict is skipped here[^\n"]*"\n$/,
  );
  expect(download?.uses as string).toMatch(
    /^actions\/download-artifact@[0-9a-f]{40}$/,
  );
  const { steps: _steps, ...verifyRest } = verify;
  const runsOn = verifyRest["runs-on"] as string;
  expect(runsOn).toMatch(
    /^\$\{\{ github\.event\.repository\.private == true && fromJSON\('\["self-hosted","Linux","ARM64"\]'\) \|\| 'macos-15' \}\}$/,
  );
  expect({ ...verifyRest, "runs-on": "" } as Record<string, unknown>).toEqual({
    name: "Verify the code signature on macOS",
    needs: ["build", "sign"],
    if: "github.event_name == 'workflow_dispatch' || (github.event_name == 'push' && github.ref_type == 'tag')",
    "runs-on": "",
    "timeout-minutes": 10,
    permissions: {},
  });
  const { run: _run, ...noticeRest } = notice;
  expect(noticeRest).toEqual({
    name: "The hosted macOS check is skipped while the repository is private",
    if: "github.event.repository.private == true",
  });
  const { uses: _uses, ...downloadRest } = download;
  expect(downloadRest).toEqual({
    if: "github.event.repository.private != true",
    with: { name: "ward-darwin-arm64-signed", path: "out" },
  });
  expect(codesign).toEqual({
    name: "codesign verifies the signature strictly",
    if: "github.event.repository.private != true",
    run: "codesign --verify --strict --verbose=2 out/ward-darwin-arm64",
  });
});

test("the workflow, the verify job and each verify step carry exactly the keys they are known to need", () => {
  // The shell override (`shell:`, `defaults: run: shell:`) and an environment
  // that defines codesign away (`env: BASH_ENV: ...`) are properties of the
  // parsed YAML, and a key can be spelled quoted, with a space before the colon
  // or as `? defaults`, none of which a text match sees. Exact key sets close the
  // class: any key not named here, however it is spelled, is red. `on` must
  // parse as the string key "on", not a boolean true.
  const parsed = parseWorkflow();
  expect(Object.keys(parsed).sort()).toEqual(
    ["jobs", "name", "on", "permissions"].sort(),
  );
  const verify = parsed.jobs.verify;
  expect(verify).toBeDefined();
  expect(Object.keys(verify ?? {}).sort()).toEqual(
    [
      "if",
      "name",
      "needs",
      "permissions",
      "runs-on",
      "steps",
      "timeout-minutes",
    ].sort(),
  );
  const steps = verify?.steps ?? [];
  expect(steps.map((step) => Object.keys(step).sort())).toEqual([
    ["if", "name", "run"],
    ["if", "uses", "with"],
    ["if", "name", "run"],
    ["if", "name", "run"],
  ]);
  expect(Object.keys(steps[1]?.with as object).sort()).toEqual([
    "name",
    "path",
  ]);
  // Every other job may carry only the keys the workflow already uses: no
  // defaults, env, container or reusable-workflow `uses:` anywhere.
  for (const job of Object.values(parsed.jobs))
    for (const key of Object.keys(job))
      expect([
        "environment",
        "if",
        "name",
        "needs",
        "permissions",
        "runs-on",
        "steps",
        "timeout-minutes",
      ]).toContain(key);
});

test("a repository payload with no repository object at all takes the verifying path", () => {
  const runsOn = expressionAfter(jobText("verify"), "runs-on");
  expect(evaluate(runsOn, undefined)).toBe("macos-15");
  const [notice, download, codesign] = stepIfs();
  expect(evaluate(notice ?? "", undefined)).toBe(false);
  expect(evaluate(download ?? "", undefined)).toBe(true);
  expect(evaluate(codesign ?? "", undefined)).toBe(true);
});

test("the verifying steps are skipped while private, run once public, and the skip says why", () => {
  const verify = jobText("verify");
  const ifs = stepIfs();
  expect(ifs).toEqual([
    "github.event.repository.private == true",
    "github.event.repository.private != true",
    "github.event.repository.private != true",
    "github.event.repository.private != true",
  ]);
  const [notice, download, codesign, smoke] = ifs;
  for (const [repository, notices, verifies] of [
    [{ private: true }, true, false],
    [{ private: false }, false, true],
    [{}, false, true],
  ] as const) {
    expect(evaluate(notice ?? "", repository)).toBe(notices);
    expect(evaluate(download ?? "", repository)).toBe(verifies);
    expect(evaluate(codesign ?? "", repository)).toBe(verifies);
    expect(evaluate(smoke ?? "", repository)).toBe(verifies);
  }
  expect(verify).toMatch(
    /::notice::codesign --verify --strict is skipped here/,
  );
  expect(verify).toMatch(
    /if: github\.event\.repository\.private != true\n\s+run: codesign --verify --strict --verbose=2 out\/ward-darwin-arm64/,
  );
  expect(verify).not.toContain("macos-latest");
});

test("the verify job still never holds a write permission", () => {
  expect(jobText("verify")).not.toContain("contents: write");
});

test("the release job needs the verify job, so an unverified artifact cannot publish", () => {
  expect(jobText("release")).toMatch(
    /^\s+needs: \[build, sign, verify, attest\]$/m,
  );
});

// WCLI-109 (W-15, W-36): build provenance for exactly the published artifact.
test("the attest job attests the verified artifact, on a tag only, and the release needs it", () => {
  const attest = parseWorkflow().jobs.attest ?? {};
  expect(attest.needs).toEqual(["build", "sign", "verify"]);
  expect(attest.if).toBe(
    "github.event_name == 'push' && github.ref_type == 'tag'",
  );
  const uses = (attest.steps ?? []).map((step) => String(step.uses ?? ""));
  expect(uses[0]).toMatch(/^actions\/download-artifact@[0-9a-f]{40}$/);
  expect(uses[1]).toMatch(/^actions\/attest-build-provenance@[0-9a-f]{40}$/);
  expect(attest.steps?.[0]?.with).toEqual({
    name: "ward-darwin-arm64-signed",
    path: "out",
  });
  expect(attest.steps?.[1]?.with).toEqual({
    "subject-path": "out/ward-darwin-arm64",
  });
  expect((attest.steps ?? []).length).toBe(2);
  // Exact key sets, so `if: false`, `continue-on-error` or an env on either
  // step turns this red.
  expect((attest.steps ?? []).map((step) => Object.keys(step).sort())).toEqual([
    ["uses", "with"],
    ["uses", "with"],
  ]);
  expect(JSON.stringify(attest)).not.toContain("continue-on-error");
});

test("the install docs tell the reader to run gh attestation verify, and say which releases carry one", () => {
  const command =
    "gh attestation verify ward-darwin-arm64 -R opum-ai/ward-cli --signer-workflow opum-ai/ward-cli/.github/workflows/release.yml --deny-self-hosted-runners";
  for (const file of [
    ["README.md"],
    ["docs", "runbooks", "install-and-upgrade-ward-from-a-release.md"],
  ]) {
    const text = readFileSync(join(root, ...file), "utf8").replace(/\s+/g, " ");
    expect(text).toContain(command);
    expect(text).toContain("v0.1.1 and earlier carry no attestation");
  }
});

test("a failed verify cannot be waved through: no continue-on-error, and release's condition has no status function", () => {
  expect(jobText("verify")).not.toContain("continue-on-error");
  expect(jobText("release")).not.toContain("continue-on-error");
  // An anchored whole-line match: `always()`, `!cancelled()` or `failure()`
  // appended to the condition would let release run after a failed verify.
  expect(jobText("release")).toMatch(
    /^\s+if: github\.event_name == 'push' && github\.ref_type == 'tag'$/m,
  );
});

test("the verify job takes no token permissions and the header states the gate", () => {
  expect(jobText("verify")).toMatch(/^\s+permissions: \{\}$/m);
  const header = workflow
    .slice(0, workflow.indexOf("\nname: Release"))
    .replace(/\n# ?/g, " ");
  expect(header).toContain(
    "The verify job below re-downloads the signed artifact and runs codesign --verify --strict again, and the release job needs it",
  );
  expect(header).toContain(
    "the release runbook reads /actions/runs/<id>/timing and MACOS billable must be 0",
  );
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

// WCLI-96 (W-9, DEC-255): the public Release notes name no runner, host or
// kernel. The notes block is sliced out as the install-URL test does, so a
// banned word elsewhere in the workflow cannot hide one in the notes.
function notesBlock(): string {
  const start = workflow.indexOf("- name: Hash it and write the release notes");
  expect(start).toBeGreaterThan(-1);
  const end = workflow.indexOf("- uses:", start);
  const step = workflow.slice(start, end);
  const open = step.indexOf("{\n", step.indexOf("run: |"));
  const close = step.indexOf("} > release-notes.md");
  expect(open).toBeGreaterThan(-1);
  expect(close).toBeGreaterThan(open);
  return step.slice(open, close);
}

test("the release notes carry no runner, host or kernel word", () => {
  const notes = notesBlock();
  expect(notes).toContain("- Source:");
  for (const banned of [
    "RUNNER_",
    "runner.name",
    "hostname",
    "HOSTNAME",
    "uname",
  ])
    expect(notes).not.toContain(banned);
  expect(workflow).not.toContain("RUNNER_HOST");
});

test("the release notes expand only an allowlisted set of variables and run no command", () => {
  // An allowlist closes the class: a runner, host or kernel value can reach the
  // notes only through an expansion or a command, and neither is allowed
  // beyond these names.
  const notes = notesBlock();
  const expanded = [...notes.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)].map(
    (m) => m[1],
  );
  expect([...new Set(expanded)].sort()).toEqual(
    [
      "REF_NAME",
      "REPO",
      "SOURCE_SHA",
      "cdhash",
      "sha256",
      "snapshot_bump",
    ].sort(),
  );
  expect(notes).not.toContain("$(");
  expect(notes).not.toContain("`");
  expect(notes).not.toContain("${{");
});

test("the notes carry the sha256 and cdhash lines the regeneration script rewrites", () => {
  const notes = notesBlock();
  expect(notes).toContain('echo "- sha256 ward-darwin-arm64: ${sha256}"');
  expect(notes).toContain(
    'echo "- cdhash (ad-hoc signature, macOS keychain trust follows it): ${cdhash}"',
  );
});

// WCLI-96 (DEC-255): step 5 of the publish runbook is the script, not prose,
// and the flip waits for it.
test("the publish runbook's verification step runs the fail-closed script", () => {
  const runbook = readFileSync(
    join(
      import.meta.dir,
      "..",
      "docs",
      "runbooks",
      "publish-a-mac-signed-ward-release-asset.md",
    ),
    "utf8",
  ).replace(/\s+/g, " ");
  // The fallback route verifies against the operator's local signed file.
  expect(runbook).toContain(
    "scripts/verify-published-release.sh TAG ward-darwin-arm64",
  );
  expect(runbook).toContain("Do not tag again until step 5 prints PASS.");
  // The CI route has no local file: it finds the tag run, downloads the
  // uploaded artifact and compares that with the published asset (WCLI-123).
  expect(runbook).toContain(
    "gh run list --workflow release.yml --event push --json databaseId,headBranch,headSha",
  );
  expect(runbook).toContain("gh run download RUN -n ward-darwin-arm64 -D DIR");
  expect(runbook).toContain(
    "scripts/verify-published-release.sh TAG DIR/ward-darwin-arm64",
  );
  expect(runbook).toContain(".billable.MACOS.total_ms");
  // Step 6 may be run twice: it appends its line only when it is absent, and it
  // must not make the superseded release the Latest one.
  expect(runbook).toContain(
    "grep -qxF 'Superseded by v0.1.1: install that release.' old.md",
  );
  expect(runbook).toContain("--notes-file old.md --latest=false");
});

// WCLI-99 (ruling W-34 A) moved the release workflow off the organisation's
// self-hosted groups, which refuse public repositories; WCLI-123 then moved the
// build to hosted macos-15 to sign it there. release stays on hosted Linux ARM64.
// verify keeps its WCLI-120 visibility-keyed runner and is the only place a
// self-hosted label may appear in either workflow.
function runsOnOf(name: string): string {
  const line = /^ {4}runs-on: (.+)$/m.exec(jobText(name));
  expect(line).not.toBeNull();
  return (line?.[1] ?? "").trim();
}

test("build runs on hosted macos-15 and release on hosted Linux ARM64", () => {
  expect(runsOnOf("build")).toBe("macos-15");
  expect(runsOnOf("release")).toBe("ubuntu-24.04-arm");
});

// WCLI-123 (DEC-253 (a4)): the artifact is built, ad-hoc signed and verified
// strictly on macOS in ONE job, before upload, and the checksum and notes are
// written from those signed bytes. Each assertion reads the parsed build job,
// so deleting the sign step, the verify command, the cdhash agreement check or
// reordering a step turns the matching test red.
function buildSteps(): Record<string, unknown>[] {
  const steps = parseWorkflow().jobs.build?.steps;
  expect(Array.isArray(steps)).toBe(true);
  return steps ?? [];
}
function stepIndex(match: (step: Record<string, unknown>) => boolean): number {
  return buildSteps().findIndex(match);
}
const runOf = (step: Record<string, unknown>): string =>
  typeof step.run === "string" ? step.run : "";
const signIndex = () =>
  stepIndex((s) => runOf(s).includes("codesign -s - --force"));
const notesIndex = () =>
  stepIndex((s) => s.name === "Hash it and write the release notes");
const uploadIndex = () =>
  stepIndex((s) => String(s.uses ?? "").startsWith("actions/upload-artifact@"));
const buildIndex = () =>
  stepIndex((s) =>
    runOf(s).includes(
      "bun scripts/build.ts --target bun-darwin-arm64 --outfile out/ward",
    ),
  );

test("the build job signs ad hoc with codesign -s - --force, then verifies strictly, in the same step", () => {
  const step = buildSteps()[signIndex()];
  expect(step).toBeDefined();
  const run = runOf(step ?? {});
  expect(run).toContain("set -euo pipefail");
  expect(
    run.indexOf("codesign -s - --force ward-darwin-arm64"),
  ).toBeGreaterThan(-1);
  expect(
    run.indexOf("codesign --verify --strict --verbose=2 ward-darwin-arm64"),
  ).toBeGreaterThan(run.indexOf("codesign -s - --force"));
});

test("the cdhash agreement between codesign and macho-cdhash.mjs fails the job", () => {
  const run = runOf(buildSteps()[signIndex()] ?? {});
  expect(run).toContain("codesign -dvvv ward-darwin-arm64");
  expect(run).toContain("node ../scripts/macho-cdhash.mjs ward-darwin-arm64");
  expect(run).toContain('[ -z "$signed" ]');
  expect(run).toContain('[ "$signed" != "$computed" ]');
  expect(run).toContain("exit 1");
});

// N1 (WCLI-123 review): nothing may make the sign step soft. A key the step does
// not need (continue-on-error, if, env, shell, defaults), a `|| true` after the
// verify command, or a comment-led trailer would all let a bad signature pass,
// so the build job and each of its steps carry exactly the keys they are known
// to need and the verify command is the whole of its line.
test("the build job and each build step carry exactly the keys they are known to need", () => {
  const build = parseWorkflow().jobs.build ?? {};
  expect(Object.keys(build).sort()).toEqual(
    ["name", "permissions", "runs-on", "steps", "timeout-minutes"].sort(),
  );
  const sign = buildSteps()[signIndex()] ?? {};
  expect(Object.keys(sign).sort()).toEqual(["name", "run"]);
  const known = [
    ["uses", "with"],
    ["name", "if", "env", "run"],
    ["name", "run"],
    ["name", "env", "run"],
    ["run"],
  ].map((keys) => [...keys].sort().join(","));
  for (const step of buildSteps())
    expect(known).toContain(Object.keys(step).sort().join(","));
  for (const step of buildSteps()) {
    expect("continue-on-error" in step).toBe(false);
    expect("shell" in step).toBe(false);
  }
});

test("nothing can follow the sign and verify commands on their line", () => {
  const lines = runOf(buildSteps()[signIndex()] ?? {})
    .split("\n")
    .map((l) => l.trim());
  expect(lines).toContain("codesign -s - --force ward-darwin-arm64");
  expect(lines).toContain(
    "codesign --verify --strict --verbose=2 ward-darwin-arm64",
  );
  for (const line of lines.filter((l) => l.startsWith("codesign ")))
    expect(/\|\||;|&|#/.test(line)).toBe(false);
  expect(runOf(buildSteps()[signIndex()] ?? {})).not.toMatch(/\|\|\s*true/);
});

test("build, sign and verify come before the notes and the upload, in that order", () => {
  const order = [buildIndex(), signIndex(), notesIndex(), uploadIndex()];
  for (const index of order) expect(index).toBeGreaterThan(-1);
  expect([...order].sort((a, b) => a - b)).toEqual(order);
  // The sign step is the only one that renames, so the notes hash the signed
  // file and no step after the signature touches its bytes.
  const steps = buildSteps();
  const renamed = steps
    .map((s, i) => (/\bmv ward /.test(runOf(s)) ? i : -1))
    .filter((i) => i !== -1);
  expect(renamed).toEqual([signIndex()]);
});

test("the build job hashes with shasum on macOS and no step builds the darwin target on Linux", () => {
  const job = jobText("build");
  expect(job).not.toContain("sha256sum");
  expect(job).toContain("shasum -a 256 ward-darwin-arm64");
  expect(runsOnOf("build")).not.toContain("ubuntu");
  expect(workflow.split("--target bun-darwin-arm64").length - 1).toBe(1);
});

test("verify still re-downloads the artifact and release needs build and verify", () => {
  const verify = parseWorkflow().jobs.verify;
  const uses = (verify?.steps ?? []).map((s) => String(s.uses ?? ""));
  expect(uses.some((u) => u.startsWith("actions/download-artifact@"))).toBe(
    true,
  );
  expect(parseWorkflow().jobs.release?.needs).toEqual([
    "build",
    "sign",
    "verify",
    "attest",
  ]);
});

test("no job names a self-hosted label except verify's own keyed expression", () => {
  const runsOns = [...workflow.matchAll(/^ {4}runs-on: (.+)$/gm)].map((m) =>
    (m[1] ?? "").trim(),
  );
  expect(runsOns).toHaveLength(5);
  const selfHosted = runsOns.filter((r) => r.includes("self-hosted"));
  expect(selfHosted).toHaveLength(1);
  // The one occurrence is verify's, and only through the visibility-keyed
  // expression: an unconditional self-hosted label is what WCLI-99 removes.
  expect(selfHosted[0]).toBe(runsOnOf("verify"));
  expect(selfHosted[0]).toContain("github.event.repository.private == true");
});

test("the release workflow job names are unchanged", () => {
  const names = [...workflow.matchAll(/^ {4}name: (.+)$/gm)].map((m) => m[1]);
  expect(names).toEqual([
    "Build darwin-arm64",
    "Sign and notarize on macOS",
    "Verify the code signature on macOS",
    "Attest the build provenance",
    "Create the GitHub Release",
  ]);
});

// WCLI-103 (W-8): the release path asks for the gate itself, because the
// rulesets that protect main and the tags are the operator's to apply.
const gatedCheck = join(root, "scripts", "check-release-gated.mjs");

async function runGatedCheck(
  runs: { name: string; conclusion: string | null; app?: number }[],
  total = runs.length,
  raw?: () => Response,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const server = Bun.serve({
    port: 0,
    fetch(request) {
      if (request.headers.get("authorization") !== "Bearer test-token")
        return new Response("bad credentials", { status: 401 });
      if (raw) return raw();
      return Response.json({
        total_count: total,
        check_runs: runs.map((r) => ({
          name: r.name,
          conclusion: r.conclusion,
          status: r.conclusion ? "completed" : "in_progress",
          app: { id: r.app ?? 15368 },
        })),
      });
    },
  });
  const proc = Bun.spawn(["node", gatedCheck], {
    env: {
      ...process.env,
      GH_TOKEN: "test-token",
      REPO: "opum-ai/ward-cli",
      SHA: "a".repeat(40),
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

const green = ["Check", "Docs", "Tracker integrity"].map((name) => ({
  name,
  conclusion: "success",
}));

test("the dev-gate check accepts three green required checks and refuses each way they can fail", async () => {
  const ok = await runGatedCheck(green);
  expect(ok.code).toBe(0);
  expect(ok.stdout).toContain("read 3 check runs");

  // Each required check missing, one at a time.
  for (const missing of green) {
    const result = await runGatedCheck(green.filter((r) => r !== missing));
    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      `${missing.name}: no run from GitHub Actions`,
    );
  }
  // Not green: failed, and still running.
  const failed = await runGatedCheck([
    { name: "Check", conclusion: "failure" },
    ...green.slice(1),
  ]);
  expect(failed.code).toBe(1);
  expect(failed.stderr).toContain("Check: failure");
  const running = await runGatedCheck([
    { name: "Check", conclusion: null },
    ...green.slice(1),
  ]);
  expect(running.code).toBe(1);
  expect(running.stderr).toContain("Check: in_progress");
  // A check of the right name from another app is not the required check.
  const forged = await runGatedCheck([
    { name: "Check", conclusion: "success", app: 1 },
    ...green.slice(1),
  ]);
  expect(forged.code).toBe(1);
  expect(forged.stderr).toContain("Check: no run from GitHub Actions");
  // Other conclusions are not success, and one failed run among two of the same
  // name is not a pass.
  for (const conclusion of ["skipped", "neutral", "cancelled"]) {
    const other = await runGatedCheck([
      { name: "Docs", conclusion },
      ...green.filter((r) => r.name !== "Docs"),
    ]);
    expect(other.code).toBe(1);
    expect(other.stderr).toContain(`Docs: ${conclusion}`);
  }
  const rerun = await runGatedCheck([
    ...green,
    { name: "Docs", conclusion: "failure" },
  ]);
  expect(rerun.code).toBe(1);
  expect(rerun.stderr).toContain("Docs: success, failure");
  // A non-2xx answer and a body without the lists are refusals, not passes.
  for (const status of [403, 429, 500]) {
    const refused = await runGatedCheck(
      [],
      0,
      () => new Response("{}", { status }),
    );
    expect(refused.code).toBe(1);
    expect(refused.stderr).toContain(`HTTP ${status}`);
  }
  const noList = await runGatedCheck([], 0, () =>
    Response.json({ total_count: 3 }),
  );
  expect(noList.code).toBe(1);
  expect(noList.stderr).toContain("no check_runs list");
  const noTotal = await runGatedCheck([], 0, () =>
    Response.json({ check_runs: [] }),
  );
  expect(noTotal.code).toBe(1);
  expect(noTotal.stderr).toContain("only 0 were read");
  // A partial page cannot be read as the whole history.
  const partial = await runGatedCheck(green, 150);
  expect(partial.code).toBe(1);
  expect(partial.stderr).toContain("only 3 were read");
});

test("the dev-gate step requires the tag on dev, runs on tags only, and precedes the build", () => {
  const steps = buildSteps();
  const at = steps.findIndex((s) =>
    runOf(s).includes("node scripts/check-release-gated.mjs"),
  );
  expect(at).toBeGreaterThan(-1);
  const step = steps[at] ?? {};
  expect(step.if).toBe("github.ref_type == 'tag'");
  expect(runOf(step)).toContain(
    'git merge-base --is-ancestor "$tag_commit" origin/dev',
  );
  expect(at).toBeLessThan(buildIndex());
  const build = parseWorkflow().jobs.build ?? {};
  expect(build.permissions).toEqual({ contents: "read", checks: "read" });
});

test("the required checks the gate script names match the CI jobs", () => {
  const ci = readFileSync(join(root, ".github", "workflows", "ci.yml"), "utf8");
  const script = readFileSync(gatedCheck, "utf8");
  const listed = /requiredChecks = \[([^\]]*)\]/.exec(script)?.[1] ?? "";
  const names = [...listed.matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? "");
  // Positive control: reading no names must fail, not pass.
  expect(names.length).toBeGreaterThan(0);
  for (const name of names)
    expect(ci).toMatch(new RegExp(`^\\s+name: ${name}$`, "m"));
});

test("the release job runs in the release environment and still holds the only write", () => {
  const release = parseWorkflow().jobs.release ?? {};
  expect(release.environment).toBe("release");
  expect(release.permissions).toEqual({ contents: "write" });
});

// WCLI-185 (DEC-301 item 1): the sign job and the keychain helper it runs.
function jobSteps(name: string): Record<string, unknown>[] {
  return parseWorkflow().jobs[name]?.steps ?? [];
}
const signJob = () => parseWorkflow().jobs.sign as ParsedJob;
const stepWith = (needle: string) =>
  jobSteps("sign").find((s) => runOf(s).includes(needle) || s.name === needle);

test("sign is the only job that references the signing secrets, each in the one step that needs it", () => {
  for (const [name, job] of Object.entries(parseWorkflow().jobs)) {
    if (name === "sign") continue;
    expect(JSON.stringify(job)).not.toMatch(/secrets\.(APPLE_|ASC_)/);
  }
  expect(workflow.match(/secrets\.[A-Z_]+/g)?.length).toBe(5);
  const reference = (step: Record<string, unknown> | undefined) =>
    Object.keys((step?.env as Record<string, unknown>) ?? {}).sort();
  expect(
    reference(
      stepWith("Import the signing certificate into a temporary keychain"),
    ),
  ).toEqual(["APPLE_CERT_P12_BASE64", "APPLE_CERT_PASSWORD"]);
  expect(reference(stepWith("Notarize and require Accepted"))).toEqual([
    "ASC_API_KEY_P8",
    "ASC_ISSUER_ID",
    "ASC_KEY_ID",
  ]);
  // The build job has no environment and no secret at all.
  const build = parseWorkflow().jobs.build ?? {};
  expect("environment" in build).toBe(false);
  expect(JSON.stringify(build)).not.toContain("secrets.");
});

test("sign runs in the release environment, with job-level contents: read, on a tag or a manual run from main", () => {
  const sign = signJob();
  expect(sign.environment).toBe("release");
  expect(sign.permissions).toEqual({ contents: "read" });
  expect(sign.needs).toBe("build");
  expect(sign["runs-on"]).toBe("macos-15");
  expect(sign.if).toBe(
    "(github.event_name == 'push' && github.ref_type == 'tag') || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')",
  );
  expect(JSON.stringify(sign)).not.toContain("continue-on-error");
});

test("sign runs no package manager and only the pinned actions it names", () => {
  const steps = jobSteps("sign");
  expect(steps.length).toBeGreaterThan(0);
  const text = steps.map(runOf).join("\n");
  expect(text).not.toMatch(
    /\b(bun|bunx|npm|npx|pnpm|yarn|corepack|brew|pip)\b/,
  );
  expect(text).not.toMatch(/\bset -x\b|--entitlements/);
  expect(
    steps
      .filter((s) => "uses" in s)
      .map((s) => String(s.uses).replace(/@.*/, "")),
  ).toEqual([
    "actions/checkout",
    "actions/download-artifact",
    "actions/upload-artifact",
  ]);
});

test("sign signs with the identifier ai.opum.ward, hardened runtime and a timestamp, then checks the requirement and notarization", () => {
  const sign = runOf(
    stepWith(
      "Re-sign with the Developer ID identity, hardened runtime and a timestamp",
    ) ?? {},
  );
  expect(sign).toContain(
    'codesign --force --options runtime --timestamp --identifier ai.opum.ward --keychain "$KEYCHAIN_PATH" --sign "$APPLE_SIGNING_IDENTITY" out/ward-darwin-arm64',
  );
  expect(sign).toContain("codesign --verify --strict --verbose=2");
  const requirement = runOf(
    stepWith("The designated requirement names the team and the identifier") ??
      {},
  );
  expect(requirement).toContain('identifier "ai.opum.ward"');
  expect(requirement).toContain("certificate leaf[subject.OU]");
  expect(requirement).toContain("*cdhash*");
  const notarize = runOf(stepWith("Notarize and require Accepted") ?? {});
  expect(notarize).toContain("--wait");
  expect(notarize).toContain('[ "$status" != "Accepted" ]');
  expect(notarize).toContain("exit 1");
  // The credential files live under RUNNER_TEMP, never in the upload path.
  expect(notarize).toContain("${RUNNER_TEMP}/ward-notary-key.p8");
  expect(notarize).not.toContain("out/ward-notary");
});

test("sign checks the order: sign, requirement, notarize, metadata, upload, and cleanup last and always", () => {
  const names = jobSteps("sign").map((s) => String(s.name ?? s.uses ?? ""));
  const at = (needle: string) => names.findIndex((n) => n.includes(needle));
  expect(at("Import the signing certificate")).toBeLessThan(at("Re-sign"));
  expect(at("Re-sign")).toBeLessThan(at("designated requirement"));
  expect(at("designated requirement")).toBeLessThan(at("Notarize"));
  expect(at("Notarize")).toBeLessThan(at("Regenerate the checksum"));
  expect(at("Regenerate the checksum")).toBeLessThan(
    at("actions/upload-artifact"),
  );
  const last = jobSteps("sign").at(-1) ?? {};
  expect(last.if).toBe("always()");
  expect(runOf(last)).toBe("bash scripts/signing-keychain.sh cleanup");
  const upload = jobSteps("sign").find((s) =>
    String(s.uses ?? "").startsWith("actions/upload-artifact@"),
  );
  expect(upload?.with).toEqual({
    name: "ward-darwin-arm64-signed",
    path: "out/ward-darwin-arm64\nout/ward-darwin-arm64.sha256\nout/release-notes.md\n",
    "if-no-files-found": "error",
  });
});

test("verify, attest and release all take the signed artifact, and the attest job's key set is exact", () => {
  for (const name of ["verify", "attest", "release"]) {
    const downloads = jobSteps(name).filter((s) =>
      String(s.uses ?? "").startsWith("actions/download-artifact@"),
    );
    expect(downloads).toHaveLength(1);
    expect((downloads[0]?.with as { name: string } | undefined)?.name).toBe(
      "ward-darwin-arm64-signed",
    );
  }
  expect(Object.keys(parseWorkflow().jobs.attest ?? {}).sort()).toEqual([
    "if",
    "name",
    "needs",
    "permissions",
    "runs-on",
    "steps",
    "timeout-minutes",
  ]);
  expect(parseWorkflow().jobs.release?.if).toBe(
    "github.event_name == 'push' && github.ref_type == 'tag'",
  );
});

// The keychain helper, run against a fake `security` that records its argv.
const keychainHelper = join(root, "scripts", "signing-keychain.sh");

function runKeychain(
  command: string,
  env: Record<string, string> = {},
  failOn = "",
) {
  const temp = createTempRoot("ward-keychain-");
  const bin = join(temp, "bin");
  const runner = join(temp, "runner");
  spawnSync("mkdir", ["-p", bin, runner]);
  const log = join(temp, "security.log");
  writeFileSync(
    join(bin, "security"),
    `#!/bin/bash\necho "$@" >> "${log}"\nif [ "$1" = "${failOn}" ]; then exit 1; fi\nexit 0\n`,
    { mode: 0o755 },
  );
  const result = spawnSync("bash", [keychainHelper, command], {
    encoding: "utf8",
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      RUNNER_TEMP: runner,
      ...env,
    },
  });
  return { ...result, runner, log };
}

const secretEnv = {
  APPLE_CERT_P12_BASE64: Buffer.from("synthetic-p12-bytes").toString("base64"),
  APPLE_CERT_PASSWORD: "synthetic-p12-password",
};

test("the keychain helper imports into a throwaway keychain, prints only the path, and leaves no decoded file", () => {
  const r = runKeychain("import", secretEnv);
  expect(r.status).toBe(0);
  expect(r.stdout.trim()).toBe(
    `KEYCHAIN_PATH=${r.runner}/ward-signing.keychain-db`,
  );
  expect(r.stdout + r.stderr).not.toContain("synthetic-p12");
  const log = readFileSync(r.log, "utf8");
  expect(log).toContain("create-keychain");
  expect(log).toContain("-T /usr/bin/codesign");
  expect(log).toContain("set-key-partition-list");
  expect(existsSync(join(r.runner, "ward-signing-cert.p12"))).toBe(false);
});

test("the keychain helper refuses without its credential variables and refuses an unknown command", () => {
  const missing = runKeychain("import", {});
  expect(missing.status).not.toBe(0);
  const unknown = runKeychain("sign", secretEnv);
  expect(unknown.status).toBe(2);
});

test("cleanup removes every decoded file and the keychain even after a failed import, and is safe when nothing ran", () => {
  // An import that fails after the .p12 was decoded leaves it behind...
  const failed = runKeychain("import", secretEnv, "import");
  expect(failed.status).not.toBe(0);
  expect(existsSync(join(failed.runner, "ward-signing-cert.p12"))).toBe(true);
  writeFileSync(join(failed.runner, "ward-notary-key.p8"), "x");
  writeFileSync(join(failed.runner, "ward-notary.zip"), "x");
  // ...and cleanup, run against the same runner directory, removes it all.
  const bin = join(failed.runner, "..", "bin");
  const cleanup = spawnSync("bash", [keychainHelper, "cleanup"], {
    encoding: "utf8",
    env: { PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: failed.runner },
  });
  expect(cleanup.status).toBe(0);
  for (const file of [
    "ward-signing-cert.p12",
    "ward-notary-key.p8",
    "ward-notary.zip",
  ])
    expect(existsSync(join(failed.runner, file))).toBe(false);
  expect(readFileSync(failed.log, "utf8")).toContain("delete-keychain");
  // Nothing ran at all: still exit 0.
  expect(runKeychain("cleanup").status).toBe(0);
});
