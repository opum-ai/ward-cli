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

  // The neighbours of the ranges above: U+009B is the eight-bit CSI, U+0085
  // a next-line request, and U+2028 ends a line in some renderers. None of
  // them prints, and a value Ward shows is shown as text.
  test("C1 controls and separators are escaped as well", () => {
    expect(escapeForDisplay("a\u009bb")).toBe("a\\x9bb");
    expect(escapeForDisplay("a\u0085b")).toBe("a\\x85b");
    expect(escapeForDisplay("a b")).toBe("a\\u2028b");
    expect(escapeForDisplay("a b")).toBe("a\\u2029b");
  });

  test("an escaping root cannot redraw the prompt", () => {
    const { approver, prompts } = consent({ interactive: true, answer: "y" });
    approver.ask({ projectId: request.projectId, root: "/tmp/a\u001b[2Kb" });
    expect(prompts[0]).toContain("/tmp/a\\x1b[2Kb");
    expect(prompts[0]).not.toContain("\u001b");
  });

  // WCLI-100: a value is also layout. A run of spaces is visible padding that
  // can scroll the real destination off screen, and a single space separator
  // such as NBSP is invisible laid against ordinary text. A single ordinary
  // space is kept so paths and prose stay readable.
  test("runs of spaces are escaped, a single space is not", () => {
    expect(escapeForDisplay("a b")).toBe("a b");
    expect(escapeForDisplay("a  b")).toBe("a\\x20\\x20b");
    expect(escapeForDisplay("a      b")).toBe(
      "a\\x20\\x20\\x20\\x20\\x20\\x20b",
    );
  });

  test("non-breaking and other space separators are escaped even alone", () => {
    expect(escapeForDisplay("a b")).toBe("a\\u00a0b");
    expect(escapeForDisplay("a b")).toBe("a\\u2003b");
    expect(escapeForDisplay("a　b")).toBe("a\\u3000b");
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

  // WCLI-100 AC1: the line above the answer restates the destination, so a
  // padded or wrapped value above it cannot leave a benign url line looking
  // like the operation being approved.
  test("the answer line repeats the method, destination host and header count", () => {
    const { prompt } = asked(approval);
    const answerLine = prompt.split("\n").at(-1);
    expect(answerLine).toBe(
      "Answer y to approve POST to api.example.invalid (2 headers), anything else to decline. [y/N] ",
    );
  });

  test("the answer line names zero headers when the profile declares none", () => {
    const { prompt } = asked({
      ...approval,
      snapshot: { ...snapshot, headers: [] },
    });
    expect(prompt).toContain("headers:  none");
    expect(prompt.split("\n").at(-1)).toContain("(0 headers)");
  });

  // WCLI-100 AC2: the displayed header list is capped in number and length,
  // and says how many it did not show. The snapshot itself is unchanged.
  test("the displayed header count is capped and says how many it hid", () => {
    const many = Array.from({ length: 32 }, (_, index) => ({
      name: `X-Pad-${index}`,
      value: `value-${index}`,
    }));
    const { prompt } = asked({
      ...approval,
      snapshot: { ...snapshot, headers: many },
    });
    expect(prompt).toContain("X-Pad-0: value-0");
    expect(prompt).toContain("X-Pad-7: value-7");
    expect(prompt).not.toContain("X-Pad-8");
    expect(prompt).toContain(
      "... 24 more headers not shown (all 32 are recorded on approval)",
    );
  });

  test("a long header value is shortened and marked as shortened", () => {
    const value = "A".repeat(500);
    const { prompt } = asked({
      ...approval,
      snapshot: { ...snapshot, headers: [{ name: "X-Long", value }] },
    });
    expect(prompt).not.toContain(value);
    const shownLine = prompt
      .split("\n")
      .find((line) => line.includes("X-Long: "));
    expect(shownLine).toBeDefined();
    const shownValue = (shownLine as string).slice("    X-Long: ".length);
    expect(shownValue.endsWith("...")).toBe(true);
    expect(shownValue.length).toBeLessThanOrEqual(120);
  });

  // WCLI-100 AC4: the padded-header spoof from the review, end to end. A
  // profile may declare 32 headers of 2048 characters each; padded values used
  // to scroll the real destination off screen and leave a benign url line
  // above the y/N. What the person answering reads last must still be the
  // true destination, and the whole prompt must stay bounded.
  test("padded header values cannot scroll the real destination off the answer line", () => {
    const padded: NormalizedProfile = {
      ...snapshot,
      method: "DELETE",
      url: "https://attacker.example/wipe",
      headers: Array.from({ length: 32 }, (_, index) => ({
        name: `X-Pad-${index}`,
        value: `${" ".repeat(2000)}benign-${index}`,
      })),
    };
    const { prompt, result } = asked({ ...approval, snapshot: padded });
    expect(result).toBe("approved");
    // The padding is escaped as text, never emitted as layout.
    expect(prompt).toContain("\\x20\\x20\\x20");
    expect(prompt).not.toContain(" ".repeat(20));
    // What the person answering reads last is the true destination.
    const answerLine = prompt.split("\n").at(-1) ?? "";
    expect(answerLine).toContain("DELETE");
    expect(answerLine).toContain("attacker.example");
    expect(answerLine).toContain("32 headers");
    expect(answerLine.endsWith("[y/N] ")).toBe(true);
    // 32 x 2000 declared characters, but a bounded prompt with bounded lines:
    // no single line wraps unpredictably.
    expect(prompt.length).toBeLessThan(4000);
    for (const line of prompt.split("\n"))
      expect(line.length).toBeLessThan(200);
  });

  test("a header-type credential names its header and the alias, never a value (DEC-248 (5))", () => {
    const header: NormalizedProfile = {
      ...snapshot,
      auth: {
        type: "header",
        name: "X-Example-Bypass",
        secret: "example.bypass",
      },
    };
    const { prompt } = asked({ ...approval, snapshot: header });
    expect(prompt).toContain(
      "auth:     header X-Example-Bypass, from the secret alias example.bypass",
    );
    expect(prompt).not.toContain("bearer");
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
