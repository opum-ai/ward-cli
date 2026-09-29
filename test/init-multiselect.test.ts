// DEC-48/DEC-52: `ward init`'s instruction-file multiselect.
//
// The command-level cases drive the whole path with a scripted chooser, so
// the selection and cancel semantics are pinned without a terminal. The
// adapter cases pin what DEC-52 and DEC-48 fixed - the gate (stdin and
// stderr must both be TTYs), the peers' wording and labels, required:false,
// and the cancel mapping - through the same injected seam; the clack call
// itself is one line only a real terminal exercises.
//
// Every case runs in a throwaway checkout with no vault; nothing touches the
// developer's repositories, ~/.ward or keychain.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createTerminalInstructionChoice,
  type InstructionChoiceQuestion,
} from "../src/adapters/init-prompt.ts";
import { wardBlockBody } from "../src/application/bridges.ts";
import type { InstructionFileChooser } from "../src/application/instruction-choice.ts";
import { runWard } from "../src/cli/main.ts";
import type { AgentTarget } from "../src/contract/manifest.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import {
  managedBlockBegin,
  managedBlockEnd,
} from "../src/domain/managed-block.ts";

const root = mkdtempSync(join(tmpdir(), "ward-init-choice-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;
function checkout(): string {
  const directory = join(root, `case-${++cases}`);
  mkdirSync(join(directory, ".git"), { recursive: true });
  return directory;
}

// A scripted answer to the question, recording that it was asked.
function chooser(
  available: boolean,
  answer: readonly AgentTarget[] | undefined,
  asked: string[] = [],
): InstructionFileChooser {
  return {
    available: () => available,
    choose: async () => {
      asked.push("asked");
      return answer;
    },
  };
}

async function ward(
  cwd: string,
  argv: string[],
  instructionFiles?: InstructionFileChooser,
) {
  return await runWard(argv, {
    cwd,
    // Beside the checkout, never inside it: `ward init` refuses a vault
    // directory within the repository it is initializing (spec §6.1). No
    // case here registers, so it is never created.
    wardDirectory: join(root, "vault"),
    instructionFiles,
  });
}

const block = `${managedBlockBegin}\n${wardBlockBody}${managedBlockEnd}\n`;

describe("ward init's file choice", () => {
  test("a chosen file is written and an unchosen one is not", async () => {
    const cwd = checkout();
    const result = await ward(
      cwd,
      ["init", "--no-register"],
      chooser(true, ["claude"]),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(readFileSync(join(cwd, "CLAUDE.md"), "utf8")).toBe(block);
    expect(existsSync(join(cwd, "AGENTS.md"))).toBe(false);
    expect(existsSync(join(cwd, ".ward", "project.json"))).toBe(true);
  });

  test("both chosen writes both documents", async () => {
    const cwd = checkout();
    const result = await ward(
      cwd,
      ["init", "--no-register"],
      chooser(true, ["claude", "codex"]),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(readFileSync(join(cwd, "CLAUDE.md"), "utf8")).toBe(block);
    expect(readFileSync(join(cwd, "AGENTS.md"), "utf8")).toBe(block);
  });

  test("an empty choice is a decision: no bridge written, and the flags are named", async () => {
    const cwd = checkout();
    const result = await ward(
      cwd,
      ["init", "--no-register"],
      chooser(true, []),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(existsSync(join(cwd, "CLAUDE.md"))).toBe(false);
    expect(existsSync(join(cwd, "AGENTS.md"))).toBe(false);
    expect(result.stdout).toContain("ward init --claude --codex");
  });

  test("a cancel aborts the run before anything is written", async () => {
    const cwd = checkout();
    const result = await ward(cwd, ["init"], chooser(true, undefined));
    expect(result.exitCode).toBe(exitCodes.usage);
    expect(JSON.parse(result.stderr).code).toBe("init_cancelled");
    // Nothing at all: not the manifest, not an instruction file, and not a
    // registration prompt after it.
    expect(existsSync(join(cwd, ".ward"))).toBe(false);
    expect(existsSync(join(cwd, "CLAUDE.md"))).toBe(false);
  });

  test("a target flag turns the question off, and only the named files are written", async () => {
    const cwd = checkout();
    const asked: string[] = [];
    const result = await ward(
      cwd,
      ["init", "--no-register", "--claude"],
      chooser(true, ["codex"], asked),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(asked).toEqual([]);
    expect(existsSync(join(cwd, "CLAUDE.md"))).toBe(true);
    expect(existsSync(join(cwd, "AGENTS.md"))).toBe(false);
  });

  test("--json turns the question off, even with a terminal attached", async () => {
    const cwd = checkout();
    const asked: string[] = [];
    const result = await ward(
      cwd,
      ["init", "--no-register", "--json"],
      chooser(true, ["claude"], asked),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(asked).toEqual([]);
    expect(JSON.parse(result.stdout).data.bridges).toEqual([]);
  });

  test("no terminal turns the question off and leaves today's behavior", async () => {
    const cwd = checkout();
    const asked: string[] = [];
    const result = await ward(
      cwd,
      ["init", "--no-register"],
      chooser(false, ["claude"], asked),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(asked).toEqual([]);
    expect(existsSync(join(cwd, "CLAUDE.md"))).toBe(false);
  });
});

describe("the terminal chooser's gate and question", () => {
  const tty = () => true;
  const notTty = () => false;

  test("available only when both streams are TTYs", () => {
    expect(
      createTerminalInstructionChoice({
        stdinIsTty: notTty,
        stderrIsTty: tty,
      }).available(),
    ).toBe(false);
    expect(
      createTerminalInstructionChoice({
        stdinIsTty: tty,
        stderrIsTty: notTty,
      }).available(),
    ).toBe(false);
    expect(
      createTerminalInstructionChoice({
        stdinIsTty: tty,
        stderrIsTty: tty,
      }).available(),
    ).toBe(true);
  });

  test("a TTY check that throws is not an available terminal", () => {
    expect(
      createTerminalInstructionChoice({
        stdinIsTty: () => {
          throw new Error("no terminal");
        },
        stderrIsTty: tty,
      }).available(),
    ).toBe(false);
  });

  test("choose asks nothing when no terminal can answer", async () => {
    const asked: string[] = [];
    const choice = createTerminalInstructionChoice({
      stdinIsTty: notTty,
      stderrIsTty: notTty,
      ask: async () => {
        asked.push("asked");
        return [];
      },
    });
    expect(await choice.choose()).toBeUndefined();
    expect(asked).toEqual([]);
  });

  test("the question is the peers': their wording, two labels, nothing pre-checked", async () => {
    let seen: InstructionChoiceQuestion | undefined;
    const choice = createTerminalInstructionChoice({
      stdinIsTty: tty,
      stderrIsTty: tty,
      ask: async (question) => {
        seen = question;
        return ["claude"];
      },
    });
    expect(await choice.choose()).toEqual(["claude"]);
    expect(seen?.message).toBe(
      "Select instruction files to write (space toggles, enter accepts)",
    );
    expect(seen?.required).toBe(false);
    expect(seen?.options.map((option) => option.value)).toEqual([
      "claude",
      "codex",
    ]);
    expect(seen?.options[0]?.label).toContain("CLAUDE.md");
    expect(seen?.options[1]?.label).toContain("AGENTS.md");
  });

  test("an empty selection is returned as a decision, not as a cancel", async () => {
    const choice = createTerminalInstructionChoice({
      stdinIsTty: tty,
      stderrIsTty: tty,
      ask: async () => [],
    });
    expect(await choice.choose()).toEqual([]);
  });

  test("a cancel symbol and a failed prompt are both no answer", async () => {
    const cancelled = createTerminalInstructionChoice({
      stdinIsTty: tty,
      stderrIsTty: tty,
      ask: async () => Symbol("clack:cancel"),
    });
    expect(await cancelled.choose()).toBeUndefined();

    const failed = createTerminalInstructionChoice({
      stdinIsTty: tty,
      stderrIsTty: tty,
      ask: async () => {
        throw new Error("terminal went away");
      },
    });
    expect(await failed.choose()).toBeUndefined();
  });
});
