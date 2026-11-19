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
// OBSERVED (Mac, bun 1.3.14, 2026-11-19; predictions unchanged, no divergence): the unmodified tree passes 9 of 9 (the positive control; it read 5 named bundled modules). Z1 red on exactly the spawn-anchor test. Z2 red on both golden tests. Z3 red on the no-findings test and the spawn-anchor test. Z4 red on exactly the N-5 test. Z5 red on exactly the spelled-out evasion test. Z6 red on the plain golden test and the one-allowed-exec test. rows.ts removeRunDirectoryUnder's /bin/rm spawn is a third allowed anchor (P4's delete by literal path), found by the first run of the scan. All Mac measurements; none depends on Linux.
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { interposerScript } from "../scripts/qualify-linux-shim.ts";
import {
  allowedSpawns,
  closure,
  forbiddenWords,
  normalise,
  root,
  sourceProblems,
  spawnCall,
  withoutInterposerText,
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
      ]),
    );
    for (const file of scanned)
      expect([
        file,
        sourceProblems(
          withoutInterposerText(file, read(file)),
          file.startsWith("scripts/"),
        ),
      ]).toEqual([file, []]);
  });

  test("every spawn call is an allowed anchor, by file and by call site", () => {
    for (const file of scanned) {
      const code = normalise(withoutInterposerText(file, read(file)));
      const calls = [...code.matchAll(spawnCall)].length;
      const allowed = allowedSpawns.filter((entry) => entry.file === file);
      const anchored = allowed.reduce(
        (sum, entry) => sum + [...read(file).matchAll(entry.anchor)].length,
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

  test("inside interposerScript only string contents are blanked: a spawn in its body is still counted, a word in a string is not", () => {
    const source =
      'export function interposerScript() {\n  const x = "/sbin/reboot";\n  return Bun.spawnSync(["/bin/true"]);\n}\nexport function other() {\n  return 1;\n}\n';
    const code = normalise(
      withoutInterposerText("scripts/qualify-linux-shim.ts", source),
    );
    expect([...code.matchAll(spawnCall)].length).toBe(1);
    expect(
      sourceProblems(
        withoutInterposerText("scripts/qualify-linux-shim.ts", source),
      ),
    ).toEqual([]);
    // Outside the window the same string is a finding.
    expect(sourceProblems('const x = "/sbin/reboot";')).toEqual(
      expect.arrayContaining(["names reboot"]),
    );
  });
});
