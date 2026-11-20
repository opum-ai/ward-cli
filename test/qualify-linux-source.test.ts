// WCLI-21 slice 4a-2b-2 part B2, first slice: the source tripwire over every
// module the compiled harness bundles (the agreed N-4 settlement), the golden
// pin of the generated interposer shell, and the N-5 rule that the ids-only
// groupIdsRow stays in P0. The check is LEXICAL: a command built at run time is
// not closed by it (one test below says so), and the real guarantee is that no
// P1-P4 code path builds a reboot or shutdown command. Never spawn `--phase
// facts` from a test.
//
// MUTANT REGISTER (predictions committed before any observation, never edited):
//   Z1  qualify-linux.ts gains a SECOND spawnSync( call -> "every spawn call is an allowed anchor" only (no forbidden word, no shell)
//   Z2  qualify-linux-shim.ts: the interposer's `umask 077` becomes `umask 022` -> both golden tests (plain and recording) only
//   Z3  qualify-linux-support.ts gains spawnSync("sh", ["-c", "id"]) -> "the bundled modules have no findings" (a shell as a command) AND "every spawn call is an allowed anchor" (support.ts has no allowance)
//   Z4  qualify-linux.ts calls groupIdsRow( from a second function -> "groupIdsRow stays in P0" only
//   Z5  test/support/harness-source.ts: "systemctl" removed from forbiddenWords -> "a spelled-out evasion is a finding" only
//   Z6  qualify-linux-shim.ts: the plain interposer's final line gains a second exec word (`exec exec /usr/bin/env ...`) -> the plain golden test and "the one allowed exec" only
// ROUND 2 (opus r1 REQUEST_CHANGES at 01b8a7e; predictions committed before the run):
//   V1  harness-source.ts: the shell rules lose their path prefix -> "a spelled-out evasion is a finding" only
//   V2  qualify-linux-shim.ts: a `Bun.spawnSync(["/bin/true"]);` statement inside interposerScript's body -> "every spawn call is an allowed anchor" only (the golden text is unchanged)
//   V3  harness-source.ts: closure() drops an unresolved import instead of throwing -> "a relative import that does not resolve throws" only
//   V4  qualify-linux.ts: `const weaker = groupIdsRow;` after runFacts (a reference, not a call) -> "groupIdsRow stays in P0" only
//   V5  harness-source.ts: the default/namespace child_process import rule removed -> "a spelled-out evasion is a finding" only
//   V6  harness-source.ts: withoutInterposerText blanks the whole body again (the r1 window) -> "inside interposerScript only string contents are blanked" only
// ROUND 3 (opus r2 REQUEST_CHANGES at fa1b20a; predictions committed before the run):
//   U1  qualify-linux-shim.ts: a `${tool === "tpm2_unseal" ? String(Bun.spawnSync(["/usr/bin/true"]).exitCode) : ""}` element added to the interposer head -> "every spawn call is an allowed anchor" only (the golden text is unchanged)
//   U2  qualify-linux-shim.ts: `/* it's */ Bun.spawnSync(["/usr/bin/true"]); /* ' */` as a statement in interposerScript -> "every spawn call is an allowed anchor" only
//   U3  inherited-acl.ts (src/): `export const planted = "/usr/sbin/reboot";` -> "have no findings" only
//   U4  inherited-acl.ts: the chmod call swapped for spawnSync("/usr/bin/true", []) with the old call kept as a comment -> "every spawn call is an allowed anchor" only
//   U5  harness-source.ts: the "a $ taken from bun" rule loses its `{ $ }` branch -> "a spelled-out evasion is a finding" only
//   U6  harness-source.ts: closure() no longer throws on two candidates -> "two candidate files for one import throw" only
//   U7  harness-source.ts: the sh -c left boundary goes back to the r2 class -> "a spelled-out evasion is a finding" only
//   U8  harness-source.ts: an allowance for a file that is not scanned is added -> "have no findings, and the scan read what it should" only
// OBSERVED (Mac, bun 1.3.14, 2026-11-19; predictions unchanged, no divergence): the unmodified tree passes 9 of 9 (the positive control; it read 5 named bundled modules). Z1 red on exactly the spawn-anchor test. Z2 red on both golden tests. Z3 red on the no-findings test and the spawn-anchor test. Z4 red on exactly the N-5 test. Z5 red on exactly the spelled-out evasion test. Z6 red on the plain golden test and the one-allowed-exec test. rows.ts removeRunDirectoryUnder's /bin/rm spawn is a third allowed anchor (P4's delete by literal path), found by the first run of the scan. All Mac measurements; none depends on Linux.
// OBSERVED, ROUND 2 (Mac, bun 1.3.14, 2026-11-19; predictions unchanged): the unmodified tree passes 11 of 11 (positive control; the closure over the four roots read 14 modules, src/adapters/tpm2-tools.ts and inherited-acl.ts among them). V1, V3, V4, V5, V6 each red on exactly their predicted test. V2 first aborted the suite because my planted spawn named /bin/true, which does not exist on a Mac (the golden describe calls interposerScript, so it threw there); re-run with /usr/bin/true it was red on exactly the spawn-anchor test, as predicted. Scanning src/ with the forbidden WORDS flagged ordinary messages (tpm2-tools.ts, contract/errors.ts), so the words rule applies to scripts/ only and every other rule runs over every bundled module; the settled spawn allowances for the product code are tpm2-tools.ts (Bun.spawn of the resolved tool path) and inherited-acl.ts (/bin/chmod -N).
// OBSERVED, ROUND 3 (Mac, bun 1.3.14, 2026-11-19; unmodified tree 14 of 14, the positive control): U2, U3, U4, U5, U6, U7, U8 each red on exactly their predicted test. U1 DIVERGED: red on the spawn-anchor test as predicted, and ALSO on both golden tests, because my mutant put the element into the `head` array, whose empty result joins as an extra blank line in the generated text; the spawn-anchor red is the one that matters (the shim's spawn count rose from 0 to 1 through a `${}` expression). Anchors and calls now both match on the comment-stripped normalised text; the transpiler reprints `} // end` as a plain closing line, so the window-end guard against a trailing comment is covered by that, and the 'another export' throw is a defensive check no Bun-reprinted source reaches.
// ROUND 4 (opus r3 REQUEST_CHANGES at 4bf8fb9; predictions committed before the run):
//   T1  qualify-linux.ts: a busctl entry naming "Reboot" added to factsCommands -> "have no findings" only (the word rule is now case-insensitive)
//   T2  qualify-linux-shim.ts: `const extra = tool === "tpm2_unseal" ? ["/sbin/reboot -f"] : [];` spread into the returned lines -> "no tool and no variant names a forbidden word" AND the source pin; the two golden tests stay green
//   T3  qualify-linux-shim.ts: the same branch keyed on realTool (`realTool.endsWith("tpm2_unseal")`) -> the source pin only (no per-tool text changes, since the loop passes /usr/bin/<tool>... which DOES end with tpm2_unseal, so the per-tool test is red too: predicted red on the pin AND the per-tool test)
//   T4  inherited-acl.ts: `export const sbin = "/usr/sbin"; export const p = `${sbin}/reboot`;` -> "have no findings" only
//   T5  qualify-linux-shim.ts: `/'/.test(tool); Bun.spawnSync(["/usr/bin/true"]); /'/.test(tool);` in interposerScript -> "every spawn call is an allowed anchor" AND the source pin
//   T6  harness-source.ts: the structural rules go back to the BLANKED code (normalise(source, file) for both) -> "inside interposerScript only literal text is blanked" only
//   T7  harness-source.ts: the word regex loses its `i` flag -> "a spelled-out evasion is a finding" and "a whole quoted literal or its last path component is a finding" only
//   T8  harness-source.ts: the \n \t whitespace conversion removed -> "a spelled-out evasion is a finding" only
//   T9  harness-source.ts: the package.json directory throw removed -> "a directory import with a package.json throws" only
// OBSERVED, ROUND 4 (Mac, bun 1.3.14, 2026-11-19; unmodified tree 17 of 17, the positive control, which also read every tool and both variants: 14 generated texts): T1, T4, T7, T8, T9 red on exactly their predicted tests (T7 on both the evasion and the src-literal test). T2 and T3 red on the per-tool test AND the source pin, as predicted. T5 red on the spawn-anchor test AND the source pin, as predicted. T6 DIVERGED: GREEN, because the window test counted spawns through normalise() directly and never exercised sourceProblems' own structural rules; a case was added (execSync through the regex-quote route and the `${}`-brace route, read by sourceProblems) and T6 re-run is then red on exactly that test. Pin: test/fixtures/qualify-linux/interposer-source.sha256.
// ROUND 5 (opus r4 REQUEST_CHANGES at 409a68c; predictions committed before the run):
//   R1  harness-source.ts: the literal-mode lookbehind loses `}` (and the `${` lookahead) -> "a whole quoted literal or its last path component is a finding" only
//   R2  harness-source.ts: the code-extension allow-list check removed -> "a non-code file, an attributes clause and two index candidates throw" only
//   R3  harness-source.ts: the attributes-clause throw removed -> the same test only (its .txt and index parts stay as they are, the attributes part goes red)
//   R4  harness-source.ts: "/index.tsx" removed from the extension list -> the same test only (the two-index part goes red)
//   (wordsFor now puts only src/ in literal mode; no mutant, it is a test-side selector and the positive control exercises it)
// OBSERVED, ROUND 5 (Mac, bun 1.3.14, 2026-11-19; unmodified tree 18 of 18, the positive control): R2, R3 and R4 each red on exactly their predicted test. R1 DIVERGED on its first run: GREEN, because my edit adding the two template-tail cases to the src-literal test silently did not apply (the formatter had reflowed the block it matched), so nothing exercised the `}` branch; after adding the cases for real (`${d}` + "reboot" and `${d}reboot`) R1 is red on exactly the src-literal test. The test-side selector wordsFor (src/ only in literal mode) has no mutant; the unmodified tree, with scripts/ and every other module in anywhere mode, is the positive control for it.
import "./support/no-real-keychain.ts";
import { describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { interposerScript } from "../scripts/qualify-linux-shim.ts";
import { diagnosticTool, requiredTools } from "../src/adapters/tpm2-tools.ts";
import {
  allowedSpawns,
  closure,
  forbiddenWords,
  normalise,
  root,
  sourceProblems,
  spawnCall,
} from "./support/harness-source.ts";

const entry = "scripts/qualify-linux.ts";
// Every named root is followed: rows and shim are bundled once P2 imports them,
// and they bring src/adapters/tpm2-tools.ts with them, so its spawn allowance is
// settled here and not discovered in B3.
const roots = [
  entry,
  "scripts/qualify-linux-rows.ts",
  "scripts/qualify-linux-shim.ts",
  "scripts/qualify-linux-support.ts",
];
const scanned = closure(roots);
const wordsFor = (file: string): "anywhere" | "literal" =>
  file.startsWith("src/") ? "literal" : "anywhere";
const read = (file: string): string =>
  readFileSync(resolve(root, file), "utf8");

describe("the bundled modules", () => {
  test("have no findings, and the scan read what it should", () => {
    expect(scanned).toEqual(
      expect.arrayContaining([
        entry,
        "scripts/build.ts",
        "scripts/qualify-linux-rows.ts",
        "scripts/qualify-linux-shim.ts",
        "scripts/qualify-linux-support.ts",
        "src/adapters/tpm2-tools.ts",
        "src/adapters/inherited-acl.ts",
      ]),
    );
    // Every file an allowance names is one the scan read, or it is dead.
    for (const allowance of allowedSpawns)
      expect([allowance.file, scanned.includes(allowance.file)]).toEqual([
        allowance.file,
        true,
      ]);
    for (const file of scanned)
      expect([
        file,
        sourceProblems(read(file), { file, words: wordsFor(file) }),
      ]).toEqual([file, []]);
  });

  test("every spawn call is an allowed anchor, by file and by call site", () => {
    for (const file of scanned) {
      // Calls AND anchors are matched on the same comment-stripped text, so a
      // commented-out anchor cannot stand in for a swapped call.
      const code = normalise(read(file), file, false);
      const calls = [...code.matchAll(spawnCall)].length;
      const allowed = allowedSpawns.filter((entry) => entry.file === file);
      const anchored = allowed.reduce(
        (sum, entry) => sum + [...code.matchAll(entry.anchor)].length,
        0,
      );
      expect([file, calls]).toEqual([
        file,
        allowed.reduce((sum, entry) => sum + entry.count, 0),
      ]);
      expect([file, anchored]).toEqual([file, calls]);
    }
  });
});

describe("the scan", () => {
  test("a spelled-out evasion is a finding", () => {
    const cases: [string, string][] = [
      ...(
        [
          "reboot",
          "shutdown",
          "systemctl",
          "poweroff",
          "halt",
          "init",
          "telinit",
        ] as const
      ).map((word): [string, string] => [`run("${word}")`, `names ${word}`]),
      ['run("re" + "boot")', "names reboot"],
      ["run(`re${'boot'}`)", "names reboot"],
      ['run("\\u0072eboot")', "names reboot"],
      ['run("\\x72eboot")', "names reboot"],
      ['run("sh", ["-c", "id"])', "a shell as a command"],
      ['run("/bin/sh", ["-c", "id"])', "a shell as a command"],
      ['run("/usr/bin/bash", ["-lc", "id"])', "a shell as a command"],
      ['run("/bin/dash", ["-ec", "id"])', "a shell as a command"],
      ['run("/bin/sh -c id")', "sh -c in one string"],
      ['spawnSync("id", [], { shell })', "a shell shorthand option"],
      ["run('re' + \"boot\")", "names reboot"],
      [
        'import proc from "node:child_process"; proc.exec("id");',
        "a default or namespace child_process import",
      ],
      [
        'import * as cp from "node:child_process";',
        "a default or namespace child_process import",
      ],
      ['import { $ as run } from "bun";', "a $ taken from bun"],
      ["const { $: run } = Bun;", "a $ taken from bun"],
      ["const { $ } = Bun;", "a $ taken from bun"],
      ['import * as B from "bun"; B.$`id`;', "a $ member"],
      ["const go = $; go`id`;", "a $ alias"],
      ['run("Reboot")', "names reboot"],
      ['run("busctl call login1 Reboot")', "names reboot"],
      ['run("\\nreboot")', "names reboot"],
      ['run("\\tsh -c id")', "sh -c in one string"],
      ['run("sh -e -c id")', "sh -c in one string"],
      ['run("x;sh -c id")', "sh -c in one string"],
      ['run("$(sh -c id)")', "sh -c in one string"],
      ['run("(sh -c id)")', "sh -c in one string"],
      ['run("a|sh -c id")', "sh -c in one string"],
      ['run("bash", ["-lc", "id"])', "a shell as a command"],
      ['run("dash", ["-ec", "id"])', "a shell as a command"],
      ['run("zsh -c id")', "sh -c in one string"],
      ['spawnSync("id", [], { shell: true })', "a shell option"],
      // The transpiler unquotes the key, so the plain rule fires; the quoted rule is a second net.
      ['spawnSync("id", [], { "shell": true })', "a shell option"],
      ['execSync("id")', "exec"],
      ['cp.exec("id")', "a member exec on a process module"],
      ["Bun.$`id`", "Bun.$"],
      ["const x = $`id`;", "Bun.$"],
      ['const m = await import("node:child_process")', "a dynamic module load"],
      ['const m = require("node:child_process")', "a dynamic module load"],
      [
        'import { spawnSync as run } from "node:child_process";',
        "an aliased process import",
      ],
    ];
    for (const [source, finding] of cases)
      expect([source, sourceProblems(source)]).toEqual([
        source,
        expect.arrayContaining([finding]),
      ]);
    expect(forbiddenWords.length).toBe(7);
  });

  test("comments, shell false and benign code are not findings", () => {
    for (const source of [
      "// never reboot\nconst x = 1;",
      "/* systemctl */ const x = 1;",
      'spawnSync("/usr/bin/id", ["-G"], { shell: false });',
      'const version = /v/.exec("v1");',
      'argAfter(args, "-c");',
    ])
      expect([source, sourceProblems(source)]).toEqual([source, []]);
  });

  test("the limit: a command built at run time is NOT closed by this scan", () => {
    const dynamic =
      'const cmd = ["/usr/bin/", name].join(""); spawnSync(cmd, []);';
    expect(sourceProblems(dynamic)).toEqual([]);
  });
});

describe("the generated interposer shell", () => {
  const plain = interposerScript(
    "tpm2_getcap",
    "/usr/bin/tpm2_getcap",
    "/run/ward/tools.log",
    false,
  );
  const recording = interposerScript(
    "tpm2_sessionconfig",
    "/usr/bin/tpm2_sessionconfig",
    "/run/ward/tools.log",
    true,
  );
  const golden = (name: string) =>
    readFileSync(resolve(root, "test/fixtures/qualify-linux", name), "utf8");

  test("the non-recording variant is exactly its golden text", () => {
    expect(plain).toBe(golden("interposer-plain.sh"));
  });
  test("the recording variant is exactly its golden text", () => {
    expect(recording).toBe(golden("interposer-recording.sh"));
  });

  test("neither names a forbidden word or runs sh -c, and the one allowed exec is the whole final line of the plain variant", () => {
    for (const text of [plain, recording]) {
      const body = text.split("\n").slice(1).join("\n");
      for (const word of forbiddenWords)
        expect([word, new RegExp(`\\b${word}\\b`).test(body)]).toEqual([
          word,
          false,
        ]);
      expect(/\bsh\s+-[a-zA-Z]*c\b/.test(body)).toBe(false);
    }
    const lines = plain.split("\n").filter((line) => line !== "");
    const execLines = lines.filter((line) => /\bexec\b/.test(line));
    expect(execLines).toEqual([lines[lines.length - 1] as string]);
    expect(execLines[0]).toBe(
      "exec /usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD '/usr/bin/tpm2_getcap' \"$@\"",
    );
    expect(/\bexec\b/.test(recording)).toBe(false);
  });
});

describe("the generated interposer shell, for every tool", () => {
  test("no tool and no variant names a forbidden word (any case), runs sh -c, or carries an exec other than the plain final line", () => {
    let seen = 0;
    for (const tool of [...requiredTools, diagnosticTool])
      for (const recordStdout of [false, true]) {
        const text = interposerScript(
          tool,
          `/usr/bin/${tool}`,
          "/run/ward/tools.log",
          recordStdout,
        );
        seen += 1;
        const body = text.split("\n").slice(1).join("\n");
        for (const word of forbiddenWords)
          expect([
            tool,
            word,
            new RegExp(`\\b${word}\\b`, "i").test(body),
          ]).toEqual([tool, word, false]);
        expect(/\bsh(?:\s+-[a-zA-Z]+)*\s+-[a-zA-Z]*c\b/.test(body)).toBe(false);
        const lines = text.split("\n").filter((line) => line !== "");
        const execs = lines.filter((line) => /\bexec\b/.test(line));
        expect(execs).toEqual(
          recordStdout ? [] : [lines[lines.length - 1] as string],
        );
      }
    // A positive control: the loop did run over every tool and both variants.
    expect(seen).toBe((requiredTools.length + 1) * 2);
  });

  test("interposerScript's own source is pinned (re-pin on purpose, like the golden files), so a branch on realTool or logPath goes red", () => {
    const source = read("scripts/qualify-linux-shim.ts");
    const start = source.indexOf("export function interposerScript(");
    const end = source.indexOf("\n}\n", start) + 3;
    expect(start).toBeGreaterThan(-1);
    const digest = createHash("sha256")
      .update(source.slice(start, end))
      .digest("hex");
    expect(`${digest}\n`).toBe(
      readFileSync(
        resolve(root, "test/fixtures/qualify-linux/interposer-source.sha256"),
        "utf8",
      ),
    );
  });
});

describe("N-5", () => {
  test("groupIdsRow stays in P0: every reference in every bundled module is its definition or the one call inside runFacts", () => {
    let references = 0;
    for (const file of scanned)
      references += [...normalise(read(file)).matchAll(/\bgroupIdsRow\b/g)]
        .length;
    // The definition and the single call; a reference that is not a call counts.
    expect(references).toBe(2);
    const source = normalise(read(entry));
    const facts = source.indexOf("function runFacts(");
    const end = source.indexOf("\nexport function", facts + 1);
    const insideFacts = source.slice(facts, end === -1 ? source.length : end);
    expect([...insideFacts.matchAll(/\bgroupIdsRow\b/g)].length).toBe(1);
  });
});

describe("the closure and the interposer window", () => {
  test("a relative import that does not resolve throws, and an extensionless one resolves", () => {
    const dir = mkdtempSync(join(tmpdir(), "ward-closure-"));
    try {
      writeFileSync(join(dir, "a.ts"), 'import { b } from "./b";\n');
      writeFileSync(join(dir, "b.ts"), "export const b = 1;\n");
      expect(closure(["a.ts"], dir)).toEqual(["a.ts", "b.ts"]);
      writeFileSync(join(dir, "a.ts"), 'import { x } from "./nope";\n');
      expect(() => closure(["a.ts"], dir)).toThrow(/does not resolve/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a directory import with a package.json throws", () => {
    const dir = mkdtempSync(join(tmpdir(), "ward-closure-"));
    try {
      mkdirSync(join(dir, "lib"));
      writeFileSync(join(dir, "lib", "index.ts"), "export const x = 1;\n");
      writeFileSync(join(dir, "lib", "package.json"), '{"main":"other.ts"}');
      writeFileSync(join(dir, "a.ts"), 'import { x } from "./lib";\n');
      expect(() => closure(["a.ts"], dir)).toThrow(/package directory/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a non-code file, an attributes clause and two index candidates throw", () => {
    const dir = mkdtempSync(join(tmpdir(), "ward-closure-"));
    try {
      writeFileSync(join(dir, "x.txt"), "reboot\n");
      writeFileSync(join(dir, "a.ts"), 'import x from "./x.txt";\n');
      expect(() => closure(["a.ts"], dir)).toThrow(/not a code file/);
      writeFileSync(join(dir, "y.ts"), "export default 1;\n");
      writeFileSync(
        join(dir, "a.ts"),
        'import y from "./y.ts" with { type: "text" };\n',
      );
      expect(() => closure(["a.ts"], dir)).toThrow(/attributes clause/);
      mkdirSync(join(dir, "lib"));
      writeFileSync(join(dir, "lib", "index.ts"), "export const x = 1;\n");
      writeFileSync(join(dir, "lib", "index.tsx"), "export const x = 2;\n");
      writeFileSync(join(dir, "a.ts"), 'import { x } from "./lib";\n');
      expect(() => closure(["a.ts"], dir)).toThrow(/resolves to 2 files/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("two candidate files for one import throw", () => {
    const dir = mkdtempSync(join(tmpdir(), "ward-closure-"));
    try {
      writeFileSync(join(dir, "a.ts"), 'import { b } from "./b";\n');
      writeFileSync(join(dir, "b.ts"), "export const b = 1;\n");
      writeFileSync(join(dir, "b.tsx"), "export const b = 2;\n");
      expect(() => closure(["a.ts"], dir)).toThrow(/resolves to 2 files/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  const shim = "scripts/qualify-linux-shim.ts";
  const window = (
    body: string,
    after = "export function other() {\n  return 1;\n}\n",
  ) => `export function interposerScript() {\n${body}\n}\n${after}`;

  test("inside interposerScript only literal text is blanked: a spawn in the body or in a ${} expression is counted, a word in a string is not", () => {
    const count = (source: string) =>
      [...normalise(source, shim, false).matchAll(spawnCall)].length;
    expect(count(window('  const x = "/sbin/reboot";'))).toBe(0);
    expect(
      sourceProblems(window('  const x = "/sbin/reboot";'), { file: shim }),
    ).toEqual([]);
    expect(count(window('  return Bun.spawnSync(["/bin/true"]);'))).toBe(1);
    // A template element is code: the r2 bypass.
    expect(
      count(
        window(
          '  return `x${tool === "tpm2_unseal" ? String(Bun.spawnSync(["/sbin/reboot"]).exitCode) : ""}`;',
        ),
      ),
    ).toBe(1);
    // Quotes in two comments cannot pair across the code between them.
    expect(
      count(window("  /* it's */ Bun.spawnSync([\"/bin/true\"]); /* ' */")),
    ).toBe(1);
    // A quote inside a regex literal pairs with the next one: the r3 route (a).
    expect(
      count(
        window(
          "  /'/.test(tool); Bun.spawnSync([\"/sbin/reboot\"]); /'/.test(tool);",
        ),
      ),
    ).toBe(1);
    // A brace inside a string desynchronises a `${}` depth counter: route (b).
    expect(
      count(
        window(
          '  return `${tool === "x" ? "}" + String(Bun.spawnSync(["/sbin/reboot"]).exitCode) : ""}`;',
        ),
      ),
    ).toBe(1);
    // The other structural rules read the unblanked code too (exec, here).
    for (const body of [
      "  /'/.test(tool); execSync(\"x\"); /'/.test(tool);",
      '  return `${tool === "x" ? "}" + execSync("x") : ""}`;',
    ])
      expect(sourceProblems(window(body), { file: shim })).toEqual(
        expect.arrayContaining(["exec"]),
      );
    // Outside the window the same string is a finding.
    expect(sourceProblems('const x = "/sbin/reboot";')).toEqual(
      expect.arrayContaining(["names reboot"]),
    );
  });

  test("the window is one function: after a closing line with a trailing comment, the next function's strings are still scanned", () => {
    const source =
      'export function interposerScript() {\n  return `a`;\n} // end\nexport function other() {\n  return "/sbin/reboot";\n}\n';
    expect(sourceProblems(source, { file: shim })).toEqual(
      expect.arrayContaining(["names reboot"]),
    );
  });
});

describe("words in src/", () => {
  test("a whole quoted literal or its last path component is a finding; prose is not", () => {
    for (const literal of [
      "/usr/sbin/reboot",
      "reboot",
      "Reboot",
      "systemctl",
      "/sbin/init",
      "/sys/dev/char/1:1/../../../../../usr/sbin/reboot",
    ])
      expect(
        sourceProblems(`export const p = "${literal}";`, { words: "literal" }),
      ).toEqual(expect.arrayContaining([expect.stringMatching(/^names /)]));
    for (const source of [
      "export const p = `${sbin}/reboot`;",
      'export const p = `${d}` + "reboot";',
      "export const p = `${d}reboot`;",
    ])
      expect([source, sourceProblems(source, { words: "literal" })]).toEqual([
        source,
        expect.arrayContaining(["names reboot"]),
      ]);
    for (const prose of [
      'const m = "Run `ward init` again after a reboot";',
      "// reboot",
      'const n = "reinit";',
    ])
      expect(sourceProblems(prose, { words: "literal" })).toEqual([]);
  });
});
