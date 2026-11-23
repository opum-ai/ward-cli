// Asserts that the commit a release tag names has passed the three checks the
// `dev` ruleset requires, as reported by GitHub Actions (WCLI-103, W-8).
//
// This is a guard against a mistaken tag, not a control against a writer. A
// tag push runs the workflow as it exists at the tagged commit, so whoever can
// push a commit and a matching tag can remove the step that calls this script in
// that same commit. The control is the `main` and tag rulesets the operator
// applies (docs/runbooks/protect-the-release-path.md). What this refuses is a
// tag whose commit is not on `dev` (the gated ref, reachable only through a pull
// request; the workflow checks ancestry before it runs this) or that lacks a
// successful run of each required check from the GitHub Actions app.
//
// The names and the app id below are the ones ruleset 24097150 pins
// ("require CI on dev") and the job names in .github/workflows/ci.yml. Renaming
// a CI job means changing all three places in one change.
//
// Usage: node scripts/check-release-gated.mjs
// Environment: GH_TOKEN, REPO (owner/name), SHA (the tagged commit),
// GITHUB_API_URL (the runner sets it). Exit 0 when every required check is a
// success; exit 1 naming what is missing or not green.
export const requiredChecks = ["Check", "Docs", "Tracker integrity"];
export const actionsAppId = 15368;

const { GH_TOKEN, REPO, SHA } = process.env;
const api = (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(
  /\/$/,
  "",
);

function fail(message) {
  console.error(`::error::check-release-gated: ${message}`);
  process.exit(1);
}

if (!GH_TOKEN || !REPO || !SHA) fail("GH_TOKEN, REPO and SHA must be set");

const response = await fetch(
  `${api}/repos/${REPO}/commits/${SHA}/check-runs?per_page=100`,
  {
    headers: {
      Authorization: `Bearer ${GH_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  },
);
if (!response.ok)
  fail(`could not read the check runs of ${SHA} (HTTP ${response.status})`);

const body = await response.json();
const runs = body?.check_runs;
if (!Array.isArray(runs))
  fail("the check-runs response has no check_runs list");
// A page that is not the whole list could hide a required check, so refuse it
// rather than read part of the history.
if (typeof body.total_count !== "number" || body.total_count > runs.length)
  fail(
    `${SHA} has ${body.total_count} check runs and only ${runs.length} were read`,
  );

const problems = [];
for (const name of requiredChecks) {
  const named = runs.filter(
    (run) => run?.name === name && run?.app?.id === actionsAppId,
  );
  if (named.length === 0) problems.push(`${name}: no run from GitHub Actions`);
  else if (!named.every((run) => run.conclusion === "success"))
    problems.push(
      `${name}: ${named.map((run) => run.conclusion ?? run.status).join(", ")}`,
    );
}
if (problems.length > 0)
  fail(
    `${SHA} has not passed the checks dev requires (${problems.join("; ")})`,
  );

console.log(
  `${SHA} passed ${requiredChecks.join(", ")} (read ${runs.length} check runs)`,
);
