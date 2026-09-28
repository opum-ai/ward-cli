// The registration prompt's decision logic (spec §7.1, §4.3).
//
// What is pinned here is what Ward does with an answer. The platform gate
// itself — the default `process.stdin.isTTY` — is not tested, because a test
// process cannot decide whether it has a terminal: under `bun test` from a
// developer's terminal it does, and under an agent's shell it does not. The
// gate is injected for every case below, which is also how a caller that
// must never reach a terminal is simulated.
// The mock is imported first, whatever the working directory: the isolation
// check treats any test reaching into src/adapters/ as one that could reach
// the credential store (test-isolation.test.ts).
import "./support/no-real-keychain.ts";
import { describe, expect, test } from "bun:test";
import {
  createTerminalConsent,
  escapeForDisplay,
} from "../src/adapters/terminal-consent.ts";

const request = {
  projectId: "33b05c92-8a6e-4f15-9dcb-65ae5d371123",
  root: "/Users/dev/code/project",
};

function consent(options: {
  interactive: boolean;
  answer?: string;
  fail?: "read" | "write";
}) {
  const prompts: string[] = [];
  const approver = createTerminalConsent({
    isInteractive: () => options.interactive,
    writePrompt: (text) => {
      if (options.fail === "write") throw new Error("no terminal");
      prompts.push(text);
    },
    readAnswer: () => {
      if (options.fail === "read") throw new Error("no terminal");
      return options.answer ?? "";
    },
  });
  return { approver, prompts };
}

describe("the terminal gate", () => {
  test("no interactive terminal means Ward cannot ask, and does not", () => {
    const { approver, prompts } = consent({ interactive: false });
    expect(approver.available()).toBe(false);
    expect(approver.ask(request)).toBe("unavailable");
    expect(prompts).toEqual([]);
  });

  test("an interactive terminal is available, and the prompt names what is approved", () => {
    const { approver, prompts } = consent({ interactive: true, answer: "y" });
    expect(approver.available()).toBe(true);
    expect(approver.ask(request)).toBe("approved");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain(request.projectId);
    expect(prompts[0]).toContain(request.root);
    expect(prompts[0]?.endsWith("[y/N] ")).toBe(true);
  });
});

describe("what counts as consent", () => {
  for (const answer of ["y", "Y", "yes", "YES", " y \n"]) {
    test(`${JSON.stringify(answer)} is yes`, () => {
      expect(consent({ interactive: true, answer }).approver.ask(request)).toBe(
        "approved",
      );
    });
  }

  for (const answer of ["", "\n", "n", "no", "yolo", "1", "yes please"]) {
    test(`${JSON.stringify(answer)} is no`, () => {
      expect(consent({ interactive: true, answer }).approver.ask(request)).toBe(
        "declined",
      );
    });
  }

  test("a prompt nobody could see, or read, is not consent", () => {
    for (const fail of ["read", "write"] as const) {
      const { approver } = consent({ interactive: true, fail });
      expect(approver.ask(request)).toBe("unavailable");
    }
  });
});

describe("the prompt shows the value it is asking about", () => {
  test("control bytes in a path are escaped, never emitted", () => {
    expect(escapeForDisplay("/tmp/a\u001b[2Kb\nc\u007f")).toBe(
      "/tmp/a\\x1b[2Kb\\x0ac\\x7f",
    );
    expect(escapeForDisplay("/Volumes/plain")).toBe("/Volumes/plain");
  });

  test("an escaping root cannot redraw the prompt", () => {
    const { approver, prompts } = consent({ interactive: true, answer: "y" });
    approver.ask({ projectId: request.projectId, root: "/tmp/a\u001b[2Kb" });
    expect(prompts[0]).toContain("/tmp/a\\x1b[2Kb");
    expect(prompts[0]).not.toContain("\u001b");
  });
});
