// scripts/check-lore-agent-sources.mjs runs in the Docs job against this
// repository's real bundle, where the only reachable verdicts are a pass and
// whatever that bundle happens to be. These tests pin the other half with a
// stub `lore`: that the check rejects an undeclared concept and a pack that
// dropped a declared source, that it accepts a recorded exclusion, and that it
// fails rather than passes when it read nothing. Without them a check that had
// quietly become always-green would keep the Docs job green and be believed
// (ADR 0008).
import { expect, test } from "bun:test";
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createTempRoot } from "./support/temp-root.ts";

const script = join(
  import.meta.dir,
  "..",
  "scripts",
  "check-lore-agent-sources.mjs",
);

// Answers exactly the reads the check makes. The bundle is two concepts and one
// profile throughout; only the declarations and the failure modes vary, so a
// difference in verdict can only come from the check.
const stub = `#!/bin/sh
case "$STUB_MODE" in
  fails) echo "boom: backend unavailable" >&2; exit 3 ;;
esac
if [ "$1" = "graph" ]; then
  if [ "$STUB_MODE" = "zero-concepts" ]; then
    echo '{"data":{"nodes":[]}}'
  else
    echo '{"data":{"nodes":[{"id":"adr/0001-one"},{"id":"adr/0002-two"}]}}'
  fi
  exit 0
fi
if [ "$1" = "agent" ] && [ "$2" = "list" ]; then
  if [ "$STUB_MODE" = "zero-profiles" ]; then
    echo '{"data":{"profiles":[]}}'
  else
    echo '{"data":{"profiles":[{"name":"only"}]}}'
  fi
  exit 0
fi
if [ "$1" = "agent" ] && [ "$2" = "show" ]; then
  if [ "$STUB_MODE" = "uncovered" ]; then
    echo '{"data":{"pinned":[],"sources":["adr/0001-one"]}}'
  else
    echo '{"data":{"pinned":["adr/0001-one"],"sources":["adr/0002-two"]}}'
  fi
  exit 0
fi
if [ "$1" = "agent" ] && [ "$2" = "context" ]; then
  if [ "$STUB_MODE" = "truncated" ]; then
    echo '{"data":{"truncated":true}}'
  else
    echo '{"data":{"truncated":false}}'
  fi
  exit 0
fi
echo "unexpected arguments" >&2
exit 2
`;

// Through the shared helper, so the stub's directory is reclaimed by this
// file's teardown: it used to be created with no removal at all and leaked on
// every run (WCLI-46).
const stubDirectory = createTempRoot("ward-lore-stub-");
const stubPath = join(stubDirectory, "lore");
writeFileSync(stubPath, stub);
chmodSync(stubPath, 0o755);

const exclusionsPath = join(stubDirectory, "exclusions.json");
writeFileSync(
  exclusionsPath,
  JSON.stringify({ "adr/0002-two": "recorded by this test" }),
);

function runCheck(
  mode: string,
  extra: Record<string, string> = {},
): { code: number | undefined; output: string } {
  const result = Bun.spawnSync([process.execPath, script], {
    env: {
      ...process.env,
      LORE_BIN: stubPath,
      LORE_EXCLUSIONS: "",
      STUB_MODE: mode,
      ...extra,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  return {
    code: result.exitCode,
    output: `${result.stdout.toString()}${result.stderr.toString()}`,
  };
}

test("a concept declared by no profile is rejected by name", () => {
  const { code, output } = runCheck("uncovered");
  expect(code).toBe(1);
  expect(output).toContain("adr/0002-two");
});

test("declaring one concept in pinned and another in sources covers both", () => {
  // The check must union the two lists: the pass here rests on adr/0002-two
  // being read out of `sources` while adr/0001-one is pinned.
  const { code, output } = runCheck("covered");
  expect(code).toBe(0);
  expect(output).toContain("2 concepts, 1 profiles");
});

test("reading the bundle's own counts, so a broken stub cannot pass alone", () => {
  const { output } = runCheck("covered");
  expect(output).toContain("0 concepts in no profile");
});

test("a concept recorded in the exclusion map is accepted, and printed", () => {
  const { code, output } = runCheck("uncovered", {
    LORE_EXCLUSIONS: exclusionsPath,
  });
  expect(code).toBe(0);
  expect(output).toContain("excluded from every profile: adr/0002-two");
});

test("the same concept without the exclusion is still rejected", () => {
  // The pair is the evidence. An accept that would also accept everything
  // proves nothing about the exclusion path.
  const { code } = runCheck("uncovered");
  expect(code).toBe(1);
});

test("a profile that drops a declared source is rejected by name", () => {
  const { code, output } = runCheck("truncated");
  expect(code).toBe(1);
  expect(output).toContain("only");
  expect(output).toContain("max_tokens");
});

test("reading no concepts fails rather than reporting a clean bundle", () => {
  const { code, output } = runCheck("zero-concepts");
  expect(code).toBe(1);
  expect(output).toContain("0 concepts");
});

test("reading no profiles fails rather than reporting a clean bundle", () => {
  const { code, output } = runCheck("zero-profiles");
  expect(code).toBe(1);
  expect(output).toContain("0 profiles");
});

test("a lore that fails is reported with its own message, not an empty pass", () => {
  const { code, output } = runCheck("fails");
  expect(code).toBe(1);
  expect(output).toContain("boom: backend unavailable");
});
