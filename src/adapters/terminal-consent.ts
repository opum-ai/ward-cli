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
  RegistrationAnswer,
  RegistrationApprover,
  RegistrationRequest,
} from "../application/approvals.ts";

export interface TerminalConsentParts {
  isInteractive?: () => boolean;
  readAnswer?: () => string;
  writePrompt?: (text: string) => void;
}

// Only "y" and "yes" are consent. Everything else — including an empty line,
// EOF, and any word Ward does not recognize — is a no.
function isConsent(answer: string): boolean {
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

// A path is the user's own filesystem, so it can contain control bytes and
// terminal escapes. The value shown is the value being approved, so it is
// escaped rather than passed through: a path cannot redraw the prompt that
// asks about it.
export function escapeForDisplay(value: string): string {
  let escaped = "";
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    escaped +=
      code < 0x20 || code === 0x7f
        ? `\\x${code.toString(16).padStart(2, "0")}`
        : character;
  }
  return escaped;
}

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

function defaultReadAnswer(): string {
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
  const readAnswer = parts.readAnswer ?? defaultReadAnswer;
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
        return isConsent(readAnswer()) ? "approved" : "declined";
      } catch {
        // A terminal that cannot be written to or read from cannot be
        // answered, and an unanswerable question is not consent.
        return "unavailable";
      }
    },
  };
}
