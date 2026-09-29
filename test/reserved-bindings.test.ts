// WCLI-34: the guard against Bun's silent strip of a binding named `declare`.
//
// Both directions are pinned, because a gate is only worth its green if it can
// go red: the deliberate hazards below are reported with their file and line,
// and the near-misses a real repository contains - the legitimate ambient
// `declare const` keyword, a member call, and the name mentioned in a comment
// or a string - are not. Without those, the check could be a grep for a word
// that happens to appear in prose and still look like it worked.
//
// The hazards are written into a temporary directory rather than committed as
// fixtures, so the check's own clean-tree run stays honest: a committed file
// with a stripped helper in it would make the check red everywhere, and
// excluding that file from the scan would leave the guard unable to see the
// exact case it exists for.
import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const script = join(root, "scripts", "check-reserved-bindings.mjs");

const work = mkdtempSync(join(tmpdir(), "ward-reserved-"));
process.on("exit", () => rmSync(work, { recursive: true, force: true }));

let cases = 0;
function fixture(source: string): string {
  const path = join(work, `case-${++cases}.ts`);
  writeFileSync(path, source);
  return path;
}

function guard(...paths: string[]) {
  const run = spawnSync(process.execPath, [script, ...paths], {
    cwd: root,
    encoding: "utf8",
  });
  return { output: `${run.stdout}${run.stderr}`, status: run.status ?? -1 };
}

describe("a binding named declare", () => {
  test("is reported where it is defined and where it is called", () => {
    const path = fixture(
      [
        "function declare(value: string): void {",
        '  console.log("ran", value);',
        "}",
        'declare("hello");',
        "",
      ].join("\n"),
    );
    const run = guard(path);
    expect(run.status).toBe(1);
    expect(run.output).toContain(`${path}:1: defines a binding named declare`);
    expect(run.output).toContain(
      `${path}:4: calls declare as a bare identifier`,
    );
  });

  test("is reported at any indentation, because a nested one is stripped too", () => {
    // Measured on bun 1.3.14: a `function declare` inside another function
    // prints nothing, exactly like a top-level one. The report called this a
    // top-level hazard; it is not only that.
    const path = fixture(
      [
        "function outer(): void {",
        "  const declare = (value: string) => value;",
        '  declare("hello");',
        "}",
        "",
      ].join("\n"),
    );
    const run = guard(path);
    expect(run.status).toBe(1);
    expect(run.output).toContain(`${path}:2: defines a binding named declare`);
  });

  test("is reported when it arrives as an import binding", () => {
    const path = fixture('import { declare } from "./elsewhere.ts";\n');
    const run = guard(path);
    expect(run.status).toBe(1);
    expect(run.output).toContain(`${path}:1: imports a binding named declare`);
  });

  test("is reported when the file is only a call, which is the half that goes quiet", () => {
    const path = fixture('declare("hello");\n');
    const run = guard(path);
    expect(run.status).toBe(1);
    expect(run.output).toContain(
      `${path}:1: calls declare as a bare identifier`,
    );
  });
});

describe("what is not a binding named declare", () => {
  const nearMisses: [label: string, source: string][] = [
    [
      "the ambient keyword, which is legitimate TypeScript",
      "declare const something: number;\ndeclare function elsewhere(): void;\n",
    ],
    [
      "a member call",
      "const holder = { declare: () => 1 };\nholder.declare();\n",
    ],
    ["a property in an object literal", "const config = { declare: true };\n"],
    [
      "a comment that names it",
      "// call declare(x) here once the helper exists\nconst other = 1;\n",
    ],
    ["a string that names it", 'const message = "declare(value)";\n'],
    ["a template literal that names it", "const message = `declare(value)`;\n"],
  ];

  for (const [label, source] of nearMisses) {
    test(`is not reported: ${label}`, () => {
      const path = fixture(source);
      const run = guard(path);
      expect(run.output).not.toContain("defines a binding named declare");
      expect(run.output).not.toContain("calls declare as a bare identifier");
      expect(run.status).toBe(0);
    });
  }

  test("the tracked tree is clean, and the check says how much it read", () => {
    // The clean half of the proof, and the reason it reports a count: a check
    // that read nothing and a check that read everything and found nothing
    // print the same empty finding otherwise (ADR 0008).
    const run = guard();
    expect(run.status).toBe(0);
    expect(run.output).toMatch(
      /reserved binding check: \d+ file\(s\), 0 bindings/,
    );
    const files = Number(/check: (\d+) file/.exec(run.output)?.[1] ?? 0);
    expect(files).toBeGreaterThan(50);
  });
});
