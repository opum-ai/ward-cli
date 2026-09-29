// Every concept in the docs bundle must be a candidate source for at least one
// specialist profile (.lore/agents/*.toml) or be recorded below as a deliberate
// exclusion, and every source a profile declares must actually reach its
// compiled pack. Both halves are one defect: a concept absent from a
// specialist's evidence with every exit code at 0.
//
// `lore agent context` selects only among the sources a profile lists, so a
// concept no profile declares is reachable only by a hand query, and adding one
// leaves `lore check --strict` at exit 0 with every catalog unchanged
// (WCLI-25). The reverse direction is lore's own to report and is not restated
// here. ADR 0008 records the decision, the rejected alternatives, and why the
// budget assertion below is part of it.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const loreBin = process.env.LORE_BIN ?? "lore";

// Concepts that belong in no specialist profile, each with the reason it is
// excluded. Printed on every run, so an exclusion stays a visible decision
// rather than a quiet omission. This map is the record; LORE_EXCLUSIONS names
// a JSON object of id -> reason for the tests to exercise the accept path with
// a non-empty map without editing this file.
const excluded = new Map(
  Object.entries(
    process.env.LORE_EXCLUSIONS
      ? JSON.parse(readFileSync(process.env.LORE_EXCLUSIONS, "utf8"))
      : {
          // "adr/0009-example": "why no specialist profile needs it",
        },
  ),
);

// A profile's max_tokens bounds its compiled pack, and the assembler drops the
// least relevant sources once the declared set exceeds it -- reported as
// `truncated: true` on the pack, at exit 0. Measured: for a fixed declared set
// and budget that flag does not depend on the task text (three task texts, all
// truncated at one budget and none at a larger one); which sources drop is what
// varies with the task. One reference task therefore answers the capacity
// question this asserts, and it asserts the flag alone rather than the
// composition, which is the part that is task-dependent.
const referenceTask = "bring this repository's documentation up to date";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function readLore(command) {
  const args = [...command, "--json"];
  let stdout;
  try {
    stdout = execFileSync(loreBin, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    // The tool's own words, never a swallowed stderr: a failed read and an
    // empty one must not print the same thing.
    const detail = String(error.stderr ?? "").trim() || error.message;
    fail(`${loreBin} ${args.join(" ")} failed: ${detail}`);
  }
  try {
    return JSON.parse(stdout);
  } catch {
    fail(`${loreBin} ${args.join(" ")} did not print JSON`);
  }
}

// A declared reference may name a single heading ("id#section"), so compare on
// the concept id alone.
function conceptIdOf(reference) {
  return String(reference).split("#", 1)[0];
}

const concepts = readLore(["graph"]).data.nodes.map((node) => node.id);
const profiles = readLore(["agent", "list"]).data.profiles.map(
  (profile) => profile.name,
);

// The positive control. A check that read nothing reports nothing wrong, and
// that answer is indistinguishable from a clean bundle, so read-zero fails
// rather than passing.
if (concepts.length === 0) {
  fail(`${loreBin} graph returned 0 concepts; nothing was compared`);
}
if (profiles.length === 0) {
  fail(`${loreBin} agent list returned 0 profiles; no source list was read`);
}

const covered = new Set();
const truncated = [];
for (const name of profiles) {
  const profile = readLore(["agent", "show", name]).data;
  const references = [...(profile.pinned ?? []), ...(profile.sources ?? [])];
  for (const reference of references) covered.add(conceptIdOf(reference));
  const pack = readLore([
    "agent",
    "context",
    name,
    "--task",
    referenceTask,
  ]).data;
  if (pack.truncated) truncated.push(name);
}

for (const [id, reason] of excluded) {
  console.log(`excluded from every profile: ${id} -- ${reason}`);
}

const problems = [];

const uncovered = concepts.filter(
  (id) => !covered.has(id) && !excluded.has(id),
);
if (uncovered.length > 0) {
  problems.push(
    [
      `${uncovered.length} of ${concepts.length} concepts are in no specialist profile:`,
      ...uncovered.map((id) => `  ${id}`),
      "",
      "Add each to the sources of the profile(s) a specialist should reach it",
      "through in .lore/agents/*.toml, or record it in the excluded map in",
      "scripts/check-lore-agent-sources.mjs with the reason it belongs in none.",
    ].join("\n"),
  );
}

if (truncated.length > 0) {
  problems.push(
    [
      `${truncated.length} of ${profiles.length} profiles drop a declared source from their pack:`,
      ...truncated.map((name) => `  ${name}`),
      "",
      "A declared source that does not reach the pack is absent from that",
      "specialist's evidence, which is the same defect as a concept in no",
      "profile. Raise the profile's max_tokens in .lore/agents/<name>.toml to",
      "hold what it declares, or stop declaring what it does not need.",
    ].join("\n"),
  );
}

if (problems.length > 0) fail(problems.join("\n\n"));

console.log(
  `agent source coverage: ${concepts.length} concepts, ${profiles.length} ` +
    `profiles, ${excluded.size} excluded, 0 concepts in no profile, ` +
    "0 packs truncated",
);
