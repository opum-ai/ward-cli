// First slice of release gate T09: values supplied in rejected arguments,
// malformed input and synthetic exceptions never reappear in stdout or stderr.
// Assertions report a label, never the sentinel, so a failure report cannot
// itself disclose the value under test.
import "./support/no-real-keychain.ts";
import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type CommandHandler, handlers } from "../src/application/commands.ts";
import { runWard } from "../src/cli/main.ts";
import { type ExitCode, exitCodes } from "../src/contract/envelope.ts";
import { commands } from "../src/contract/manifest.ts";
import { buildPackagedWard } from "./support/packaged.ts";
import { createTempRoot } from "./support/temp-root.ts";

const SENTINEL = "ward-sentinel-7f3a9c1e";
const CLI = join(import.meta.dir, "..", "src", "cli");
const ENTRY = join(CLI, "ward.ts");

// This file's own build root, removed by the teardown createTempRoot registers
// rather than at process exit (WCLI-46).
const packagedWard = buildPackagedWard(createTempRoot("ward-packaged-"));

function disclosed(output: string): boolean {
  return output.includes(SENTINEL);
}

function spawnWard(argv: string[], env?: Record<string, string>) {
  const run = Bun.spawnSync([packagedWard, ...argv], {
    env: { ...process.env, ...env },
  });
  return {
    stdout: run.stdout.toString(),
    stderr: run.stderr.toString(),
    exitCode: run.exitCode,
  };
}

const rejectedArgv: [label: string, argv: string[], exitCode: ExitCode][] = [
  ["unknown command", [SENTINEL], exitCodes.usage],
  ["unknown command with value", ["get", SENTINEL], exitCodes.usage],
  ["unknown option", ["manifest", `--${SENTINEL}`], exitCodes.usage],
  [
    "unknown option with value",
    ["manifest", `--token=${SENTINEL}`],
    exitCodes.usage,
  ],
  [
    "value to a boolean option",
    ["manifest", `--json=${SENTINEL}`],
    exitCodes.usage,
  ],
  ["value to --help", ["manifest", `--help=${SENTINEL}`], exitCodes.usage],
  ["extra positional", ["manifest", SENTINEL], exitCodes.usage],
  [
    "extra positional after terminator",
    ["manifest", "--", SENTINEL],
    exitCodes.usage,
  ],
  ["unknown topic", ["instructions", SENTINEL], exitCodes.notFound],
  ["topic with --list", ["instructions", "--list", SENTINEL], exitCodes.usage],
  ["unknown help target", ["help", SENTINEL], exitCodes.usage],
  ["value to --version", ["--version", SENTINEL], exitCodes.usage],
  // Secret arguments are judged before any vault is opened or read, so a
  // sentinel in any of them is refused without touching a vault.
  ["unknown secret action", ["secret", SENTINEL], exitCodes.usage],
  [
    "secret alias with a leading digit",
    ["secret", "set", `9${SENTINEL}`],
    exitCodes.usage,
  ],
  ["missing secret alias", ["secret", "set"], exitCodes.usage],
  [
    "extra secret argument",
    ["secret", "set", "an-alias", SENTINEL],
    exitCodes.usage,
  ],
  ["secret alias on a list", ["secret", "list", SENTINEL], exitCodes.usage],
];

describe("rejected arguments are not echoed", () => {
  for (const [label, argv, exitCode] of rejectedArgv) {
    test(`${label} (in process)`, async () => {
      const result = await runWard(argv);
      expect(result.exitCode).toBe(exitCode);
      expect(disclosed(result.stdout)).toBe(false);
      expect(disclosed(result.stderr)).toBe(false);
    });

    test(`${label} (packaged executable)`, () => {
      const result = spawnWard(argv);
      expect(result.exitCode).toBe(exitCode);
      expect(disclosed(result.stdout)).toBe(false);
      expect(disclosed(result.stderr)).toBe(false);
    });
  }
});

describe("unexpected exceptions", () => {
  test("a thrown error's message never reaches output", async () => {
    const original = handlers.manifest as CommandHandler;
    handlers.manifest = () => {
      throw new Error(`upstream said ${SENTINEL}`);
    };
    try {
      const result = await runWard(["manifest"]);
      expect(result.exitCode).toBe(exitCodes.uncaught);
      expect(disclosed(result.stdout)).toBe(false);
      expect(disclosed(result.stderr)).toBe(false);
      expect((JSON.parse(result.stderr) as { code: string }).code).toBe(
        "uncaught",
      );
    } finally {
      handlers.manifest = original;
    }
  });

  // The guard is what stands between an error thrown outside runWard and
  // Bun's default report, which prints the message and stack.
  const escapes: [label: string, body: string][] = [
    ["synchronous throw", `throw new Error("${SENTINEL}");`],
    [
      "throw from a timer",
      `setTimeout(() => { throw new Error("${SENTINEL}"); }, 0);`,
    ],
    ["unhandled rejection", `Promise.reject(new Error("${SENTINEL}"));`],
  ];
  test("the entry point imports the guard before anything else", async () => {
    const source = await Bun.file(ENTRY).text();
    const imports = [...source.matchAll(/^import\s.*["'](.+)["'];?$/gm)].map(
      ([, target]) => target,
    );
    expect(imports[0]).toBe("./guard.ts");
  });

  for (const [label, body] of escapes) {
    test(`the guard reports a ${label} as a fixed envelope`, () => {
      const dir = mkdtempSync(join(tmpdir(), "ward-guard-"));
      try {
        const script = join(dir, "escape.ts");
        writeFileSync(script, `import "${join(CLI, "guard.ts")}";\n${body}\n`);
        const run = Bun.spawnSync(["bun", script]);
        expect(run.exitCode).toBe(exitCodes.uncaught);
        expect(disclosed(run.stdout.toString())).toBe(false);
        expect(disclosed(run.stderr.toString())).toBe(false);
        expect(
          (JSON.parse(run.stderr.toString()) as { code: string }).code,
        ).toBe("uncaught");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

describe("commands that do not unlock the vault never read or write ~/.ward", () => {
  // ~/.ward is planted as an unreadable, unwritable file. Opening it, listing
  // it, or creating anything beneath it throws, and the command exits 1. An
  // existence check or stat does not throw, so this does not catch those.
  test("every example succeeds with ~/.ward unusable, and HOME is unchanged", () => {
    const home = mkdtempSync(join(tmpdir(), "ward-home-"));
    const trap = join(home, ".ward");
    writeFileSync(trap, "");
    chmodSync(trap, 0o000);
    try {
      // setup unlocks the vault by design; its initialization behavior is
      // pinned in setup.test.ts against an injected directory.
      expect(commands.some((command) => command.unlocksVault)).toBe(true);
      for (const command of commands) {
        if (command.unlocksVault) continue;
        for (const example of command.examples) {
          const result = spawnWard(example.split(" ").slice(1), {
            HOME: home,
            USERPROFILE: home,
          });
          expect(result.exitCode).toBe(exitCodes.success);
        }
      }
      expect(readdirSync(home)).toEqual([".ward"]);
      expect(statSync(trap).size).toBe(0);
    } finally {
      chmodSync(trap, 0o600);
      rmSync(home, { recursive: true, force: true });
    }
  });
});
