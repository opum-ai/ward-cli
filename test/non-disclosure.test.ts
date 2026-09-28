// First slice of release gate T09: values supplied in rejected arguments,
// malformed input and synthetic exceptions never reappear in stdout or stderr.
// Assertions report a label, never the sentinel, so a failure report cannot
// itself disclose the value under test.
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type CommandHandler, handlers } from "../src/application/commands.ts";
import { runWard } from "../src/cli/main.ts";
import { type ExitCode, exitCodes } from "../src/contract/envelope.ts";
import { commands } from "../src/contract/manifest.ts";

const SENTINEL = "ward-sentinel-7f3a9c1e";
const MAIN = join(import.meta.dir, "..", "src", "cli", "main.ts");

function disclosed(output: string): boolean {
  return output.includes(SENTINEL);
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
  ["extra positional", ["manifest", SENTINEL], exitCodes.usage],
  [
    "extra positional after terminator",
    ["manifest", "--", SENTINEL],
    exitCodes.usage,
  ],
  ["unknown topic", ["instructions", SENTINEL], exitCodes.notFound],
  ["unknown help target", ["help", SENTINEL], exitCodes.usage],
  ["value to --version", ["--version", SENTINEL], exitCodes.usage],
];

describe("rejected arguments are not echoed", () => {
  for (const [label, argv, exitCode] of rejectedArgv) {
    test(label, () => {
      const result = runWard(argv);
      expect(result.exitCode).toBe(exitCode);
      expect(disclosed(result.stdout)).toBe(false);
      expect(disclosed(result.stderr)).toBe(false);
    });
  }

  test("the compiled entry behaves the same as a subprocess", () => {
    const run = Bun.spawnSync(["bun", MAIN, "manifest", `--token=${SENTINEL}`]);
    expect(run.exitCode).toBe(exitCodes.usage);
    expect(disclosed(run.stdout.toString())).toBe(false);
    expect(disclosed(run.stderr.toString())).toBe(false);
  });
});

describe("unexpected exceptions", () => {
  test("a thrown error's message never reaches output", () => {
    const original = handlers.manifest as CommandHandler;
    handlers.manifest = () => {
      throw new Error(`upstream said ${SENTINEL}`);
    };
    try {
      const result = runWard(["manifest"]);
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
});

describe("commands that do not unlock the vault never touch ~/.ward", () => {
  test("running each one under an empty HOME leaves it empty", () => {
    const home = mkdtempSync(join(tmpdir(), "ward-home-"));
    try {
      for (const command of commands) {
        expect(command.unlocksVault).toBe(false);
        const run = Bun.spawnSync(["bun", MAIN, command.name], {
          env: { ...process.env, HOME: home, USERPROFILE: home },
        });
        expect(run.exitCode).toBe(exitCodes.success);
      }
      expect(readdirSync(home)).toEqual([]);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
