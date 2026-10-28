#!/usr/bin/env bash
# The ward skill's ship gate, run locally before a release.
#
#   ./scripts/run-eval.sh            full gate - every case. Run before a release.
#   ./scripts/run-eval.sh ward       selective - that skill's cases, plus every
#                                    skill's should-NOT-fire case. Run before
#                                    landing a change to one skill.
#
# A FAILING RUN BLOCKS THE RELEASE. Exit 0 means every case met the threshold
# and the plugin is releasable; a case below 1.0 exits 1 and the release waits
# until the cause is understood - either the skill changed in a way that broke
# the behaviour a case measures, or the case itself is wrong. Record each run's
# result rather than replacing the previous one, so the next reader can compare.
#
# THIS IS NOT A CI GATE, and wiring it into a required context would manufacture
# an infrastructure failure that reads as a regression. A run spends plan usage
# or API dollars on every case (x3 runs x2 arms by default, plus judge calls),
# and a run that hits a usage limit scores 0 WITHOUT the suite being marked
# partial - so a low score from CI would look like a skill regression and be
# one more thing nobody can reproduce. Run it on a workstation, before a
# release, and record what it scored. What CI does run is the deterministic
# half: scripts/check-evals.mjs, through `bun run check`'s eval:check step in
# the Check job, which needs no model and no key.
#
# The structural check runs FIRST, and the run does not start if it fails. It
# enforces the fleet's floor invariants and the `<skill>-*` / `*no-trigger*`
# naming the selective mode's globs depend on - see the header of
# scripts/check-evals.mjs for its provenance.
#
# Flags that are not optional, and why:
#   --ablation with-without  a score with no baseline arm cannot say the plugin
#                            caused it; the delta is the point
#   --judge-model sonnet     the default judge is below the sonnet-tier floor
#                            the fleet's authoring standards require for llm
#                            graders, and the judge is ~1% of run cost
#   --scaffold               cases that seed a workspace via scaffold_script
#                            score 0 without it
#   --threshold 1            fail the run if any case scores below 1.0
#   --no-publish             keep the HTML report local; do not upload it
#   --trust-plugin           the plugin under test is this repository's own
#                            plugin/ and the cases are ones we authored; without
#                            it a headless run stops at the first-run trust prompt
#
# WHAT IS EVALUATED. The plugin ships from plugin/, which carries only the
# manifest and skills/ (DEC-246 a4, a7), so evals/ cannot sit beside it there
# and `--eval-dir` refuses a path outside the plugin root (it rejects `..`).
# The run therefore assembles a scratch tree - a byte copy of plugin/ plus
# evals/ - and evaluates that. The plugin bytes are the ones that ship; only
# the evals ride along for the run. The scratch path is printed at the start.
#
# NEVER pipe this command. A shell pipeline reports its last stage's exit
# status, so `./scripts/run-eval.sh | tee` turns a failing suite into a green
# one.
#
# PROVING ONE RULE RATHER THAN THE PLUGIN. `--ablation with-without` compares
# the plugin against NO plugin, so it cannot isolate a sentence inside the
# skill. To prove a single rule, run `--ablation none` against two trees that
# differ only by that rule - this plugin and a copy with the paragraph removed -
# with identical cases, and compare those two mode-matched runs. Under
# `--ablation none` the with-only indicator graders (`tool_used: Skill`) ARE
# scored, so absolute scores differ between modes; never compare across them.
#
# RUN NONE-MODE PER CASE, NOT ACROSS THE SUITE. The same rule that makes the
# indicators score under `none` makes a whole-suite none run fail by
# construction: the should-NOT-fire guard's `tool_used: Skill` grader is
# SUPPOSED to fail there - a reported FAIL is the measurement that the skill
# stayed quiet - so the guard scores below 1.0 and threshold 1 exits 1. That is
# the guard working, not a regression. Filter every none-mode run with --case,
# the way the pair measurements do.
#
# A USAGE-LIMITED ZERO IS NOT A REGRESSION, and nothing in the tool says so.
# If the account hits a plan or rate limit while a suite runs, each later run
# ends with that error, is graded on what it produced, and usually scores 0,
# and the suite is NOT marked partial. The summary below scans for run errors
# and says so loudly. Re-run after the limit resets, with --runs 1 or a --case
# filter to stay under it.
set -euo pipefail
cd "$(dirname "$0")/.."

SKILL="${1:-}"

node scripts/check-evals.mjs

# evals/results/ is gitignored, so a fresh clone does not have it and the
# --json path below would land in a directory that does not exist.
mkdir -p evals/results

stage="$(mktemp -d "${TMPDIR:-/tmp}/ward-eval-plugin.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
cp -R plugin/. "$stage/"
mkdir "$stage/evals"
for entry in evals/*; do
  [ "$entry" = "evals/results" ] && continue
  cp -R "$entry" "$stage/evals/"
done
echo "Evaluating plugin tree assembled at $stage (plugin/ + evals/)"

run_arm() {
  # $1 = --case glob or empty, $2 = result file basename
  local glob="$1" out="evals/results/$2.json" status=0
  if [ -n "$glob" ]; then
    claude plugin eval "$stage" --case "$glob" \
      --ablation with-without --judge-model sonnet --scaffold --trust-plugin \
      --no-publish --threshold 1 --json "$out" || status=$?
  else
    claude plugin eval "$stage" \
      --ablation with-without --judge-model sonnet --scaffold --trust-plugin \
      --no-publish --threshold 1 --json "$out" || status=$?
  fi
  # `set -e` would abort before the summary printed, so the status is captured
  # and re-raised at the end. A failing gate must still show WHICH case failed.
  if [ ! -f "$out" ]; then
    echo "eval produced no result file for '${glob:-<all>}'; exiting $status" >&2
    exit "${status:-1}"
  fi
  node -e '
    const r = require("./" + process.argv[1]);
    const a = r.aggregates;
    console.log("");
    console.log(`cases ${a.casesPassed}/${a.casesTotal}  score ${a.overallScore.toFixed(3)}  mean delta ${a.meanDelta.toFixed(3)}  $${r.costUsd.toFixed(2)}`);
    for (const c of r.cases) {
      const g = c.aggregates;
      console.log(`  ${c.name.padEnd(34)} with ${g.score.toFixed(2)}  without ${(g.scoreWithout ?? 0).toFixed(2)}  delta ${(g.delta ?? 0).toFixed(2)}`);
    }
    // A plan usage or API rate limit scores later runs 0 and does NOT mark the
    // suite partial, so a clean-looking low score can be a limit rather than a
    // regression. Field names are from the published docs, not from an observed
    // result file, so the whole scan is best-effort and stays quiet on a shape
    // it does not recognise.
    try {
      const notes = [];
      if (r.partial) notes.push(`suite is PARTIAL (${r.partialReason ?? "no reason given"})`);
      let errored = 0, aborted = 0, skipped = 0, firstErr = null;
      for (const c of r.cases ?? []) {
        for (const arm of Object.values(c.arms ?? {})) {
          if (!Array.isArray(arm)) continue;
          for (const run of arm) {
            if (run && run.error) { errored++; if (firstErr === null) firstErr = String(run.error); }
            if (run && run.aborted) aborted++;
            if (run && run.skippedPaidGraders) skipped++;
          }
        }
      }
      if (errored) notes.push(`${errored} run(s) ended with an error, first: ${firstErr.slice(0, 160)}`);
      if (aborted) notes.push(`${aborted} run(s) stopped by a mock expectation (those score 0 with error null)`);
      if (skipped) notes.push(`${skipped} run(s) had paid graders SKIPPED, so their score is over fewer graders - keep these out of any trend`);
      if (notes.length) {
        console.log("");
        console.log("!! DO NOT READ THIS SCORE AS A REGRESSION WITHOUT CHECKING:");
        for (const n of notes) console.log(`   - ${n}`);
        if (errored) {
          console.log("   A plan usage or API rate limit scores later runs 0 and does NOT mark the suite partial.");
          console.log("   Re-run after the limit resets, with --runs 1 or a --case filter to stay under it.");
        }
      }
    } catch (e) {
      console.log("");
      console.log(`(could not scan for run errors: ${e.message} - check the NOTES column or cases[].arms.with[].error by hand)`);
    }
  ' "$out"
  return $status
}

overall=0
if [ -n "$SKILL" ]; then
  echo "Selective gate: ${SKILL}'s cases, plus every skill's should-NOT-fire guard."
  echo "Run without an argument for the full gate before a release."
  run_arm "${SKILL}-*" "local-${SKILL}" || overall=$?
  run_arm '*no-trigger*' "local-guards" || overall=$?
else
  run_arm "" "local" || overall=$?
fi
exit $overall
