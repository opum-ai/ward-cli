#!/usr/bin/env node
// Deterministic structural gate for the eval suite.
//
// Enforces the floor invariants the `claude plugin eval init` authoring
// interview holds even when the author pushes back, plus the grader-hierarchy
// rule that an llm grader is a last resort. None of this needs a model, an API
// key, or a dollar - so it runs on every push, while the eval itself (which
// costs real money per run) is reserved for changes that can actually move it.
//
// Reference: opum-agent docs/reference/plugin-eval-authoring.md
//
// VENDORED, and this is the only part of the file that is ours (WCLI-50).
// Source: opum-fleet `scripts/check-evals.mjs`, last committed there as
// a0bec172959a421dc27b9d7395777867c1a01f7e (2026-09-09), file sha256
// 244d605e1c29a4965efa75542a4913f02f9dd7e92688d33e3e9423ce904ab589, taken
// from a clean working tree at opum-fleet 81fce93.
//
// Why a copy rather than calling the sibling: this gate has to run on any
// clone of this repository, including one with no opum-fleet checkout beside
// it, and a structural check that silently skips is worse than none. The
// behaviour below is that file's, unmodified; only this header, the formatting
// (normalized to this repository's biome config, which lints scripts/**/*.mjs)
// and two optional-chain rewrites biome flags - `(frontmatter(...) ?? {}).x`
// becoming `frontmatter(...)?.x` when reading a grader's and an agent file's
// type/name, the same value for a null return - differ from the original.
// Behavioural equivalence was measured, not assumed: both copies run side by
// side on the suite and on two deliberately broken copies of it, and agree on
// exit code and findings in all three, the negative controls chosen to fire
// different assertions of this file (the naming and per-skill-guard rules in
// one, the outcome-grader and turn-budget rules in the other).
//
// If opum-fleet's copy moves, re-vendor deliberately - read the diff, re-run
// that pair of measurements, and record the new commit and hash here. Do not
// patch this copy into a second dialect; the naming rule and floor invariants
// it enforces are what scripts/run-eval.sh's selection depends on.
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

const EVAL_DIR = "evals";
const SKILLS_DIR = "skills";
const AGENTS_DIR = "agents";
const findings = [];
const fail = (c, m) => findings.push(`${c}: ${m}`);

const frontmatter = (file) => {
  const text = readFileSync(file, "utf8");
  const m = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return null;
  const out = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z_]+):\s*(.*)$/);
    if (kv) out[kv[1]] = kv[2].trim();
  }
  return out;
};

const cases = readdirSync(EVAL_DIR).filter(
  (d) => d !== "results" && statSync(join(EVAL_DIR, d)).isDirectory(),
);

if (cases.length === 0) fail("suite", "no eval cases found");

let shouldNotFire = 0;

for (const name of cases) {
  const dir = join(EVAL_DIR, name);
  const promptPath = join(dir, "prompt.md");
  const gradersDir = join(dir, "graders");

  if (!existsSync(promptPath)) {
    fail(name, "missing prompt.md");
    continue;
  }
  if (!existsSync(gradersDir)) {
    fail(name, "missing graders/");
    continue;
  }

  const prompt = readFileSync(promptPath, "utf8");
  if (prompt.includes("TODO: describe what the agent should do")) {
    fail(name, "prompt.md is still the blank init template");
  }

  const fm = frontmatter(promptPath) ?? {};
  const maxTurns = Number(fm.max_turns ?? 10);

  const graders = readdirSync(gradersDir).filter((f) => f.endsWith(".md"));
  if (graders.length === 0) {
    fail(name, "no graders");
    continue;
  }

  const types = graders.map((g) => frontmatter(join(gradersDir, g))?.type);
  const outcome = types.filter((t) => t && t !== "tool_used");
  if (outcome.length === 0) {
    fail(
      name,
      "has no outcome grader - a tool_used grader must never be the only one",
    );
  }

  // A case that reads a repository needs a budget sized to the task, not the
  // template. An under-set budget scores 0 in BOTH arms and reads as "the
  // plugin did nothing" - which is exactly how OPAG-45 hid for a full run.
  const scaffolded = existsSync(join(dir, "case.yaml"));
  if (scaffolded && maxTurns < 20) {
    fail(
      name,
      `max_turns ${maxTurns} is under-set for a scaffolded repo-reading case (want >= 20)`,
    );
  }

  if (scaffolded) {
    const caseYaml = readFileSync(join(dir, "case.yaml"), "utf8");
    const script = caseYaml.match(/scaffold_script:\s*(\S+)/)?.[1];
    if (script) {
      if (!existsSync(join(dir, script))) {
        fail(
          name,
          `case.yaml names scaffold_script ${script}, which does not exist`,
        );
      } else if (!(statSync(join(dir, script)).mode & 0o111)) {
        fail(name, `scaffold_script ${script} is not executable`);
      }
    }
  }

  if (/should[- ]not|no[- ]trigger|unrelated/i.test(name)) shouldNotFire += 1;
}

if (shouldNotFire === 0) {
  fail(
    "suite",
    "no should-NOT-fire case - nothing guards against the skill over-triggering",
  );
}

// Every case name starts with the skill or agent it exercises, and every
// skill owns at least one should-NOT-fire case. This is not tidiness:
// `--case` takes ONE glob and understands no braces or comma lists, so
// `<skill>-*` and `*no-trigger*` are the only two selections the runner can
// express. Break the convention and the selective gate in run-eval.sh
// silently stops covering something.
const skills = existsSync(SKILLS_DIR)
  ? readdirSync(SKILLS_DIR).filter((d) =>
      statSync(join(SKILLS_DIR, d)).isDirectory(),
    )
  : [];

// Agents live as flat agents/<name>.md files, not skills/<name>/SKILL.md
// subdirectories, and only ones with real frontmatter count - a bare
// agents/README.md must not be read as an agent named "README".
const agents = existsSync(AGENTS_DIR)
  ? readdirSync(AGENTS_DIR)
      .filter(
        (f) => f.endsWith(".md") && frontmatter(join(AGENTS_DIR, f))?.name,
      )
      .map((f) => f.slice(0, -3))
  : [];

const dispatchTargets = [...skills, ...agents];

for (const name of cases) {
  if (
    !dispatchTargets.some(
      (n) =>
        name === n ||
        name.startsWith(`${n}-`) ||
        name.startsWith(`${n.replace(/^opum-/, "")}-`),
    )
  ) {
    fail(
      name,
      `case name does not start with a skill in ${SKILLS_DIR}/ or an agent in ${AGENTS_DIR}/ (have: ${dispatchTargets.join(", ")})`,
    );
  }
}

for (const sk of skills) {
  const short = sk.replace(/^opum-/, "");
  const owned = cases.filter(
    (n) => n.startsWith(`${sk}-`) || n.startsWith(`${short}-`),
  );
  if (owned.length === 0) {
    fail(sk, "skill has no eval cases at all");
    continue;
  }
  if (!owned.some((n) => /no[- ]trigger|should[- ]not/i.test(n))) {
    fail(
      sk,
      "skill has no should-NOT-fire case of its own - adding a skill can make ANOTHER skill over-trigger, so each one carries its own guard",
    );
  }
}

// Agents are dispatched explicitly by name, not autonomously triggered by a
// description the way skills are - nothing "over-fires" a subagent, so unlike
// skills they do not each need their own no-trigger case. What they need
// instead is one shared guard against skipping the pack-compilation
// discipline when a delegated task looks trivial or off-profile - see the
// eval-authoring reference's agent-dispatch section.
for (const ag of agents) {
  const owned = cases.filter((n) => n.startsWith(`${ag}-`));
  if (owned.length === 0) {
    fail(ag, "agent has no eval cases at all");
  }
}

if (agents.length > 0 && !cases.some((n) => /no[- ]mismatch/i.test(n))) {
  fail(
    "agents",
    "no shared no-mismatch guard case exists for agents/ (a case matching *no-mismatch*)",
  );
}

if (findings.length > 0) {
  console.error("eval suite structural check: FAIL");
  for (const f of findings) console.error(`  - ${f}`);
  process.exit(6);
}

console.log(
  `eval suite structural check: OK (${cases.length} cases, ${shouldNotFire} should-NOT-fire)`,
);
