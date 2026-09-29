// Every concept in the docs bundle must be a candidate source for at least one
// specialist profile (.lore/agents/*.toml), or be recorded below as a
// deliberate exclusion. `lore agent context` compiles a pack from the sources
// a profile declares, so a concept no profile declares cannot reach a
// specialist except by a hand query -- and nothing else notices: adding a
// concept leaves `lore check --strict` at exit 0 with every catalog unchanged
// (WCLI-25). The opposite direction is already loud, so this covers only the
// silent half: a profile naming a concept that no longer exists fails
// `lore check --strict` and `lore agent context` both.
//
// A profile's max_tokens bounds its compiled pack, and an over-budget profile
// is narrowed by task relevance, so declaring a concept here does not push it
// into every pack. This check is about the candidate set a profile offers the
// assembler, not about what any one compiled pack contains.
import { execFileSync } from "node:child_process";

const loreBin = process.env.LORE_BIN ?? "lore";

// Concepts that belong in no specialist profile, each with the reason it is
// excluded. Printed on every run, so an exclusion stays a visible decision
// rather than a quiet omission.
const excluded = new Map([
  // ["adr/0009-example", "why no specialist profile needs it"],
]);

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
for (const name of profiles) {
  const profile = readLore(["agent", "show", name]).data;
  const references = [...(profile.pinned ?? []), ...(profile.sources ?? [])];
  for (const reference of references) covered.add(conceptIdOf(reference));
}

for (const [id, reason] of excluded) {
  console.log(`excluded from every profile: ${id} -- ${reason}`);
}

const uncovered = concepts.filter(
  (id) => !covered.has(id) && !excluded.has(id),
);

if (uncovered.length > 0) {
  fail(
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

console.log(
  `agent source coverage: ${concepts.length} concepts, ${profiles.length} ` +
    `profiles, ${excluded.size} excluded, 0 concepts in no profile`,
);
