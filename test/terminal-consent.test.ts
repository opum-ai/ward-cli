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
  createTerminalProfileApprover,
} from "../src/adapters/terminal-consent.ts";
import type {
  ProfileApprovalQuestion,
  ProfileRevocationQuestion,
} from "../src/application/approvals.ts";
import { escapeForDisplay } from "../src/domain/display.ts";
import type { NormalizedProfile } from "../src/domain/profile.ts";

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

  // Format characters print nothing and can act on the terminal that shows
  // them: U+202E reverses the text after it, so an unescaped one can make a
  // prompt read as a host it does not name.
  test("format characters are escaped too, including outside the BMP", () => {
    expect(escapeForDisplay("https://good.example/‮evil")).toBe(
      "https://good.example/\\u202eevil",
    );
    expect(escapeForDisplay("zero​width")).toBe("zero\\u200bwidth");
    expect(escapeForDisplay("tag󠀁char")).toBe("tag\\u{e0001}char");
  });

  test("an escaping root cannot redraw the prompt", () => {
    const { approver, prompts } = consent({ interactive: true, answer: "y" });
    approver.ask({ projectId: request.projectId, root: "/tmp/a\u001b[2Kb" });
    expect(prompts[0]).toContain("/tmp/a\\x1b[2Kb");
    expect(prompts[0]).not.toContain("\u001b");
  });
});

// The approval prompt itself: what a developer reads before an operation is
// recorded in their vault. The port's payload is measured in profile.test.ts;
// what is measured here is the rendering, because that is the artifact the
// person answers about — a payload nobody prints would pass a payload test.
const snapshot: NormalizedProfile = {
  adapter: "http",
  method: "POST",
  url: "https://api.example.invalid/rate_limit",
  auth: { type: "bearer", secret: "example.token" },
  headers: [
    { name: "Accept", value: "application/json" },
    { name: "X-Trace", value: "1" },
  ],
  requestBody: "none",
  output: "status",
};

const approval: ProfileApprovalQuestion = {
  kind: "approve",
  profile: "example-profile",
  projectId: request.projectId,
  root: request.root,
  snapshot,
};

const revocation: ProfileRevocationQuestion = {
  kind: "revoke",
  profile: "example-profile",
  projectId: request.projectId,
  root: request.root,
};

function profileConsent(options: {
  interactive: boolean;
  answer?: string;
  fail?: "read" | "write";
}) {
  const prompts: string[] = [];
  const approver = createTerminalProfileApprover({
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

const asked = (
  question: ProfileApprovalQuestion | ProfileRevocationQuestion,
  answer = "y",
) => {
  const { approver, prompts } = profileConsent({ interactive: true, answer });
  const result = approver.ask(question);
  return { result, prompt: prompts[0] ?? "" };
};

describe("the approval prompt", () => {
  test("shows every part of the operation being approved", () => {
    const { result, prompt } = asked(approval);
    expect(result).toBe("approved");
    for (const shown of [
      approval.profile,
      approval.projectId,
      approval.root,
      snapshot.method,
      snapshot.url,
      snapshot.auth.secret,
      "Accept: application/json",
      "X-Trace: 1",
      snapshot.requestBody,
      snapshot.output,
    ])
      expect(prompt).toContain(shown);
    expect(prompt.endsWith("[y/N] ")).toBe(true);
    // It says what approving does, in the same breath as what is approved.
    expect(prompt).toContain("records exactly this operation");
  });

  test("a value carrying control or format bytes cannot redraw the prompt", () => {
    // A declaration this hostile is refused before an approval is stored, so
    // what this pins is the renderer standing on its own: whatever a caller
    // hands the port, the bytes a person reads are escaped.
    const hostile: NormalizedProfile = {
      ...snapshot,
      url: "https://api.example.invalid/\u001b]0;PWNED\u0007‮evil",
      headers: [{ name: "X-Trace", value: "1\u0007‮" }],
    };
    const { prompt } = asked({ ...approval, snapshot: hostile });
    expect(prompt).not.toContain("\u001b");
    expect(prompt).not.toContain("\u0007");
    expect(prompt).not.toContain("‮");
    expect(prompt).toContain("\\x1b]0;PWNED\\x07\\u202eevil");
    expect(prompt).toContain("X-Trace: 1\\x07\\u202e");
  });

  test("only yes is consent, and an unreadable answer is not", () => {
    expect(asked(approval, "y").result).toBe("approved");
    expect(asked(approval, "yes").result).toBe("approved");
    expect(asked(approval, "n").result).toBe("declined");
    expect(asked(approval, "").result).toBe("declined");
    for (const fail of ["read", "write"] as const) {
      const { approver } = profileConsent({ interactive: true, fail });
      expect(approver.ask(approval)).toBe("unavailable");
    }
  });

  test("no interactive terminal means the question is never asked", () => {
    const { approver, prompts } = profileConsent({ interactive: false });
    expect(approver.available()).toBe(false);
    expect(approver.ask(approval)).toBe("unavailable");
    expect(prompts).toEqual([]);
  });

  test("the revocation prompt names the profile and not the operation", () => {
    const { result, prompt } = asked(revocation);
    expect(result).toBe("approved");
    expect(prompt).toContain(revocation.profile);
    expect(prompt).toContain(revocation.projectId);
    expect(prompt).toContain(revocation.root);
    // Revoking is not about the operation, so no part of it is shown.
    expect(prompt).not.toContain(snapshot.url);
    expect(prompt).not.toContain(snapshot.method);
    expect(prompt).not.toContain("Accept");
  });
});
