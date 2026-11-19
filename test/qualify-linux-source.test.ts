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
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
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
// Named as well as followed: rows and shim are bundled once P2 imports them.
const scanned = [
  ...new Set([
    ...closure(entry),
    "scripts/qualify-linux-rows.ts",
    "scripts/qualify-linux-shim.ts",
    "scripts/qualify-linux-support.ts",
  ]),
].sort();
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
      ]),
    );
    for (const file of scanned)
      expect([
        file,
        sourceProblems(withoutInterposerText(file, read(file))),
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
  test("groupIdsRow stays in P0: its only use is inside runFacts, so seal and unseal cannot wire the weaker row", () => {
    const source = normalise(read(entry));
    const start = source.indexOf("function groupIdsRow(");
    const facts = source.indexOf("function runFacts(");
    expect(start).toBeGreaterThan(-1);
    expect(facts).toBeGreaterThan(start);
    const factsEnd = source.indexOf("\nfunction", facts + 1);
    const outside =
      source.slice(0, start) +
      source.slice(source.indexOf("\n}\n", start) + 3, facts) +
      source.slice(factsEnd === -1 ? source.length : factsEnd);
    expect([...outside.matchAll(/\bgroupIdsRow\b/g)].length).toBe(0);
    expect(
      [...source.slice(facts, factsEnd).matchAll(/\bgroupIdsRow\(/g)].length,
    ).toBe(1);
  });
});
