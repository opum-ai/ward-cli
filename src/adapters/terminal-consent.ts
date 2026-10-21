// The interactive half of registration (spec §7.1, §4.3).
//
// A person has to answer this one, so the gate is `process.stdin.isTTY`:
// stdin must be an interactive terminal for the answer to come from one.
// A caller whose stdin is a pipe — an agent, a script, `ward init < /dev/null`
// — cannot answer, and Ward refuses rather than reading consent off a stream
// something else can write to. That is a guardrail against a non-interactive
// caller, and it is explicitly not proof of a person: spec §4.3 forbids
// treating an isatty() check as authentication, so registration is
// described as a mistake-reducer and nothing else.
//
// The prompt goes to the controlling terminal, or to stderr when there is
// none, and never to stdout: stdout is the machine-readable result channel
// and a prompt in it would corrupt it. The answer is read from stdin, one
// byte at a time and bounded, so a stream that never ends cannot grow it.
import {
  closeSync,
  constants as fileConstants,
  openSync,
  readSync,
  writeSync,
} from "node:fs";
import type {
  GrantApprover,
  GrantQuestion,
  ProfileAnswer,
  ProfileApprovalQuestion,
  ProfileApprover,
  ProfileQuestion,
  ProfileRevocationQuestion,
  RegistrationAnswer,
  RegistrationApprover,
  RegistrationRequest,
} from "../application/approvals.ts";
import { escapeForDisplay } from "../domain/display.ts";

export interface TerminalConsentParts {
  isInteractive?: () => boolean;
  readAnswer?: () => string;
  writePrompt?: (text: string) => void;
}

// Only "y" and "yes" are consent. Everything else — including an empty line,
// EOF, and any word Ward does not recognize — is a no.
export function isConsentAnswer(answer: string): boolean {
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

// A path is the user's own filesystem, and a profile declaration comes from a
// tracked, editable file, so either can contain control bytes and terminal
// escapes. The value shown is the value being approved, so it is escaped
// rather than passed through: it cannot redraw the prompt that asks about it.
// The policy itself is shared with the text reports in the application layer
// (`escapeForDisplay` in src/domain/display.ts).
function promptFor(request: RegistrationRequest): string {
  return [
    "Ward is not registered for this checkout.",
    "",
    `  project:  ${request.projectId}`,
    `  checkout: ${escapeForDisplay(request.root)}`,
    "",
    "Register this checkout for the project? Secrets for the project become",
    "usable in this checkout, and the approval is recorded in your vault.",
    "Answer y to register, anything else to leave it unregistered. [y/N] ",
  ].join("\n");
}

function defaultWritePrompt(text: string): void {
  let terminal: number | undefined;
  try {
    terminal = openSync(
      "/dev/tty",
      fileConstants.O_WRONLY | fileConstants.O_NOCTTY,
    );
  } catch {
    terminal = undefined;
  }
  try {
    writeSync(terminal ?? 2, text);
  } finally {
    if (terminal !== undefined) closeSync(terminal);
  }
}

// One line from a terminal, bounded so a stream that never ends cannot grow
// it. Shared with every other yes/no question Ward asks on a terminal.
export function readAnswerLine(): string {
  const bytes: number[] = [];
  const buffer = new Uint8Array(1);
  while (bytes.length < 64) {
    const read = readSync(0, buffer, 0, 1, null);
    if (read === 0) break;
    const byte = buffer[0] as number;
    if (byte === 0x0a) break;
    if (byte !== 0x0d) bytes.push(byte);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

export function createTerminalConsent(
  parts: TerminalConsentParts = {},
): RegistrationApprover {
  const isInteractive =
    parts.isInteractive ?? (() => process.stdin.isTTY === true);
  const writePrompt = parts.writePrompt ?? defaultWritePrompt;
  const readAnswer = parts.readAnswer ?? readAnswerLine;
  const available = (): boolean => {
    try {
      return isInteractive();
    } catch {
      return false;
    }
  };

  return {
    available,
    ask(request): RegistrationAnswer {
      if (!available()) return "unavailable";
      try {
        writePrompt(promptFor(request));
        return isConsentAnswer(readAnswer()) ? "approved" : "declined";
      } catch {
        // A terminal that cannot be written to or read from cannot be
        // answered, and an unanswerable question is not consent.
        return "unavailable";
      }
    },
  };
}

// The approval question shows the normalized operation, because approving it
// is the whole point of asking: the developer has to read what Ward would
// send. Every value shown is escaped, so a URL or header value that contains
// terminal control bytes cannot redraw the prompt asking about it. Headers
// are listed one per line, and a body policy or output policy is named by
// its normalized value rather than described.
function profileApprovalPrompt(question: ProfileApprovalQuestion): string {
  const { snapshot } = question;
  const headers =
    snapshot.headers.length === 0
      ? ["  headers:  none"]
      : [
          "  headers:",
          ...snapshot.headers.map(
            (header) =>
              `    ${escapeForDisplay(header.name)}: ${escapeForDisplay(header.value)}`,
          ),
        ];
  return [
    "Ward is asking you to approve an HTTPS operation for this checkout.",
    "",
    `  profile:  ${escapeForDisplay(question.profile)}`,
    `  project:  ${question.projectId}`,
    `  checkout: ${escapeForDisplay(question.root)}`,
    `  method:   ${snapshot.method}`,
    `  url:      ${escapeForDisplay(snapshot.url)}`,
    `  auth:     bearer, from the secret alias ${escapeForDisplay(snapshot.auth.secret)}`,
    ...headers,
    `  body:     ${snapshot.requestBody}`,
    `  output:   ${snapshot.output}`,
    "",
    "Approving records exactly this operation in your vault, for this",
    "checkout. Ward refuses the profile if any part of it changes, and you",
    "would approve the new version. Nothing here is a secret value: the",
    "credential is read from the vault when the profile runs.",
    "Answer y to approve, anything else to decline. [y/N] ",
  ].join("\n");
}

function profileRevocationPrompt(question: ProfileRevocationQuestion): string {
  return [
    "Ward is asking you to revoke your approval of an HTTPS operation.",
    "",
    `  profile:  ${escapeForDisplay(question.profile)}`,
    `  project:  ${question.projectId}`,
    `  checkout: ${escapeForDisplay(question.root)}`,
    "",
    "Revoking blocks future Ward runs of this profile from this checkout.",
    "It revokes nothing at the credential's provider, and it cannot recall a",
    "request Ward has already sent.",
    "Answer y to revoke, anything else to leave it approved. [y/N] ",
  ].join("\n");
}

function promptForProfileQuestion(question: ProfileQuestion): string {
  return question.kind === "approve"
    ? profileApprovalPrompt(question)
    : profileRevocationPrompt(question);
}

// The same three answers as registration, from the same terminal and the
// same rule: an answer Ward could not read is "unavailable", never consent
// and never a refusal the caller may act on (spec §4.3).
export function createTerminalProfileApprover(
  parts: TerminalConsentParts = {},
): ProfileApprover {
  const isInteractive =
    parts.isInteractive ?? (() => process.stdin.isTTY === true);
  const writePrompt = parts.writePrompt ?? defaultWritePrompt;
  const readAnswer = parts.readAnswer ?? readAnswerLine;
  const available = (): boolean => {
    try {
      return isInteractive();
    } catch {
      return false;
    }
  };

  return {
    available,
    ask(question): ProfileAnswer {
      if (!available()) return "unavailable";
      try {
        writePrompt(promptForProfileQuestion(question));
        return isConsentAnswer(readAnswer()) ? "approved" : "declined";
      } catch {
        return "unavailable";
      }
    },
  };
}

function grantPrompt(question: GrantQuestion): string {
  return [
    "Ward is asking you to share a secret with another project.",
    "",
    `  owner project:  ${question.ownerProjectId}`,
    `  secret alias:   ${escapeForDisplay(question.alias)}`,
    `  target project: ${question.targetProjectId}`,
    `  target alias:   ${escapeForDisplay(question.targetAlias)}`,
    "",
    "The target project may then use this secret, under the target alias,",
    "in operations its own developer approves. It cannot read, change,",
    "delete or re-share it, and you can revoke the grant. A revoked grant",
    "blocks new runs; it recalls nothing already sent and revokes nothing at",
    "the credential's provider.",
    "Answer y to grant, anything else to decline. [y/N] ",
  ].join("\n");
}

// The same rule as every other question: an answer Ward could not read is
// "unavailable", never consent (spec §4.3).
export function createTerminalGrantApprover(
  parts: TerminalConsentParts = {},
): GrantApprover {
  const isInteractive =
    parts.isInteractive ?? (() => process.stdin.isTTY === true);
  const writePrompt = parts.writePrompt ?? defaultWritePrompt;
  const readAnswer = parts.readAnswer ?? readAnswerLine;
  const available = (): boolean => {
    try {
      return isInteractive();
    } catch {
      return false;
    }
  };

  return {
    available,
    ask(question): ProfileAnswer {
      if (!available()) return "unavailable";
      try {
        writePrompt(grantPrompt(question));
        return isConsentAnswer(readAnswer()) ? "approved" : "declined";
      } catch {
        return "unavailable";
      }
    },
  };
}
