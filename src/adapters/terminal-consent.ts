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
  UnregisterApprover,
  UnregisterQuestion,
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
import {
  isSignSnapshot,
  type NormalizedSignProfile,
} from "../domain/profile.ts";

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

// Display-only caps on the approval prompt (WCLI-100). These bound what is
// shown, never what is approved: `normalizeProfile` still accepts up to
// `profileLimits.maxHeadersPerProfile` headers of `maxHeaderValueChars`, and
// the snapshot recorded on approval is the full declared set (ADR 0003, and
// the snapshot version in src/domain/profile.ts is unchanged). A capped
// header list says how many it did not show, so a shortened view is visibly
// shortened rather than silently incomplete.
const maxDisplayedHeaders = 8;
const maxDisplayedHeaderNameChars = 60;
const maxDisplayedHeaderValueChars = 120;

// The destination host the final answer line repeats. The URL is normalized
// to HTTPS before it reaches this port, but the renderer stands on its own:
// an unparseable URL is named as such rather than thrown over, and the host
// is escaped but NOT shortened: the registrable suffix is the end of the host,
// a profile may declare a host far longer than any cap (a long run of labels
// ahead of the real domain), and a cap that keeps the left end would cut the
// one part the answer line exists to show. The host is ASCII with no spaces
// and bounded by the URL limit, so it cannot pad the line.
function destinationHostForDisplay(url: string): string {
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    return "(unparseable url)";
  }
  if (host === "") return "(no host)";
  return escapeForDisplay(host);
}

// The approval question shows the normalized operation, because approving it
// is the whole point of asking: the developer has to read what Ward would
// send. Every value shown is escaped, so a URL or header value that contains
// terminal control bytes cannot redraw the prompt asking about it, and runs
// of whitespace are escaped too, so padding cannot scroll the destination off
// screen. Headers are listed one per line, capped in number and length, and a
// body policy or output policy is named by its normalized value rather than
// described.
//
// The answer line repeats the method, the destination host and the header
// count, so the line immediately above the y/N cannot be counterfeited by
// layout: whatever else a value does to the screen, the person answering sees
// the real destination beside the question.
function profileApprovalPrompt(question: ProfileApprovalQuestion): string {
  const { snapshot } = question;
  if (isSignSnapshot(snapshot)) return signApprovalPrompt(question, snapshot);
  const shownHeaders = snapshot.headers.slice(0, maxDisplayedHeaders);
  const hiddenHeaders = snapshot.headers.length - shownHeaders.length;
  const headerCount = `${snapshot.headers.length} header${snapshot.headers.length === 1 ? "" : "s"}`;
  const headers =
    snapshot.headers.length === 0
      ? ["  headers:  none"]
      : [
          "  headers:",
          ...shownHeaders.map(
            (header) =>
              `    ${escapeForDisplay(header.name, { maxChars: maxDisplayedHeaderNameChars })}: ${escapeForDisplay(header.value, { maxChars: maxDisplayedHeaderValueChars })}`,
          ),
          ...(hiddenHeaders > 0
            ? [
                `    ... ${hiddenHeaders} more header${hiddenHeaders === 1 ? "" : "s"} not shown (all ${snapshot.headers.length} are declared in the manifest and recorded on approval; the ones shown are the first by name)`,
              ]
            : []),
        ];
  return [
    "Ward is asking you to approve an HTTPS operation for this checkout.",
    "",
    `  profile:  ${escapeForDisplay(question.profile)}`,
    `  project:  ${question.projectId}`,
    `  checkout: ${escapeForDisplay(question.root)}`,
    `  method:   ${snapshot.method}`,
    `  url:      ${escapeForDisplay(snapshot.url)}`,
    snapshot.auth.type === "header"
      ? `  auth:     header ${escapeForDisplay(snapshot.auth.name)}, from the secret alias ${escapeForDisplay(snapshot.auth.secret)}`
      : `  auth:     bearer, from the secret alias ${escapeForDisplay(snapshot.auth.secret)}`,
    ...headers,
    `  body:     ${snapshot.requestBody}`,
    `  output:   ${snapshot.output}`,
    "",
    "Approving records exactly this operation in your vault, for this",
    "checkout. Ward refuses the profile if any part of it changes, and you",
    "would approve the new version. Nothing here is a secret value: the",
    "credential is read from the vault when the profile runs.",
    `Answer y to approve ${escapeForDisplay(snapshot.method)} to ${destinationHostForDisplay(snapshot.url)} (${headerCount}), anything else to decline. [y/N] `,
  ].join("\n");
}

// A sign approval names the key and every domain prefix it may sign under
// (DEC-262 a3 (iii)). A prefix is shown twice, as escaped text and as the
// base64 of its exact bytes, because the text alone can hide a NUL or a
// look-alike character and the base64 alone cannot be read; the answer line
// repeats the key and the prefix count so it cannot be counterfeited by
// layout above it.
function signApprovalPrompt(
  question: ProfileApprovalQuestion,
  snapshot: NormalizedSignProfile,
): string {
  const prefixes = snapshot.prefixes.map((prefix) => {
    const bytes = Buffer.from(prefix, "base64");
    const text = new TextDecoder("utf-8").decode(bytes);
    return `    ${escapeForDisplay(text, { maxChars: 80 })}  [base64 ${prefix}, ${bytes.length} byte${bytes.length === 1 ? "" : "s"}]`;
  });
  const count = `${snapshot.prefixes.length} prefix${snapshot.prefixes.length === 1 ? "" : "es"}`;
  return [
    "Ward is asking you to approve a signing operation for this checkout.",
    "",
    `  profile:  ${escapeForDisplay(question.profile)}`,
    `  project:  ${question.projectId}`,
    `  checkout: ${escapeForDisplay(question.root)}`,
    `  key:      ${escapeForDisplay(snapshot.key)}`,
    "  prefixes (Ward signs only bytes that begin with one of these):",
    ...prefixes,
    "",
    "Approving records exactly this operation in your vault, for this",
    "checkout. Ward signs the bytes it is given and adds nothing to them. The",
    "private key is never shown and never leaves Ward.",
    `Answer y to approve signing with the key ${escapeForDisplay(snapshot.key)} under ${count}, anything else to decline. [y/N] `,
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

function unregisterPrompt(question: UnregisterQuestion): string {
  if (question.kind === "binding")
    return [
      "Ward is asking you to unregister this checkout.",
      "",
      `  project:  ${question.projectId}`,
      `  checkout: ${escapeForDisplay(question.root)}`,
      "",
      "This checkout loses access to the project's secrets until it is",
      "registered again. No other checkout is touched, and nothing is revoked",
      "at a credential's provider.",
      "Answer y to unregister, anything else to leave it registered. [y/N] ",
    ].join("\n");
  return [
    `This checkout holds ${question.approvals} profile approval${question.approvals === 1 ? "" : "s"}.`,
    "",
    `  checkout: ${escapeForDisplay(question.root)}`,
    "",
    "Remove them too? If you keep them, registering this same clone again",
    "makes the ones this version wrote live until they expire or are revoked;",
    "an approval written by an earlier version never does.",
    "Answer y to remove the approvals, anything else to keep them. [y/N] ",
  ].join("\n");
}

// The same rule as every other question: an answer Ward could not read is
// "unavailable", never consent (spec §4.3).
export function createTerminalUnregisterApprover(
  parts: TerminalConsentParts = {},
): UnregisterApprover {
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
        writePrompt(unregisterPrompt(question));
        return isConsentAnswer(readAnswer()) ? "approved" : "declined";
      } catch {
        return "unavailable";
      }
    },
  };
}
