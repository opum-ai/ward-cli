// bunfig.toml's preload replaces the credential-store binding only when
// `bun test` runs from the repository root. Every test file that can reach
// the adapter or the binding therefore imports the mock as its first import,
// so running from test/, an IDE or a parent directory cannot reach a real
// keychain item (WCLI-5).
import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const testDir = import.meta.dir;
const reachesStore = /src\/adapters\/|@napi-rs\/keyring/;

function firstImport(source: string): string | undefined {
  return source.match(/^import\s[^;]*?["']([^"']+)["']/m)?.[1];
}

test("every test that can reach the credential store imports the mock first", () => {
  const offenders: string[] = [];
  for (const name of readdirSync(testDir)) {
    if (!name.endsWith(".test.ts") || name === "test-isolation.test.ts")
      continue;
    const source = readFileSync(join(testDir, name), "utf8");
    if (!reachesStore.test(source)) continue;
    if (firstImport(source) !== "./support/no-real-keychain.ts")
      offenders.push(name);
  }
  expect(offenders).toEqual([]);
});

test("the check sees at least one such file", () => {
  const files = readdirSync(testDir).filter(
    (name) =>
      name.endsWith(".test.ts") &&
      name !== "test-isolation.test.ts" &&
      reachesStore.test(readFileSync(join(testDir, name), "utf8")),
  );
  expect(files.length).toBeGreaterThan(0);
});
