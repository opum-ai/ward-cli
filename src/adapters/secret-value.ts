// The interactive half of `ward secret set` (spec §6.2, §8, §4.3).
//
// Two value paths, each with the gate its trust model needs. Hidden entry
// uses the same gate as registration and the backup passphrase:
// `process.stdin.isTTY` must be true, echo is suppressed by raw mode for the
// read and restored on every path, the terminal's pending input is discarded
// before echo comes back (a paste carries bytes past the newline the read
// stops on, and they would otherwise reach the shell; this narrows that
// window, it does not close it), and nothing is printed
// in place of the bytes — not even a mask, because a mask discloses the
// value's length.
// --stdin is the explicit automation path: exact bytes through EOF, and it
// refuses a terminal as its source, where the terminal's own line discipline
// would echo whatever is typed onto the screen.
//
// The replacement question reuses the consent shape from registration: only
// y/yes is consent, and anything unanswerable is a no. The alias is escaped
// for display: it came from argv, and it cannot redraw the prompt. Prompts
// go to the controlling terminal, or to stderr when there is none, and
// never to stdout.
import {
  closeSync,
  constants as fileConstants,
  openSync,
  readSync,
  writeSync,
} from "node:fs";
import type { SecretValueSource } from "../application/secrets.ts";
import { WardError } from "../contract/errors.ts";
import { escapeForDisplay } from "../domain/display.ts";
import { secretLimits } from "../domain/secret.ts";
import { isConsentAnswer, readAnswerLine } from "./terminal-consent.ts";
import { flushPendingInput, inputQueued } from "./terminal-input.ts";

export interface TerminalSecretParts {
  isInteractive?: () => boolean;
  setRaw?: (on: boolean) => void;
  readHiddenBytes?: () => Uint8Array;
  flushInput?: () => void;
  inputPending?: () => boolean;
  readStdinBytes?: (maxBytes: number) => Uint8Array;
  readAnswer?: () => string;
  writePrompt?: (text: string) => void;
}

function defaultSetRaw(on: boolean): void {
  const stdin = process.stdin as { setRawMode?: (mode: boolean) => void };
  if (typeof stdin.setRawMode !== "function") throw new Error("no raw mode");
  stdin.setRawMode(on);
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

// A descriptor read that is retried across the transient errors a
// non-blocking standard input can report before its first byte arrives.
function readOnce(descriptor: number, buffer: Uint8Array): number {
  for (;;) {
    try {
      return readSync(descriptor, buffer, 0, buffer.length, null);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EAGAIN" || code === "EWOULDBLOCK" || code === "EINTR")
        continue;
      throw error;
    }
  }
}

// The hidden reader, over any readable descriptor so its byte semantics can
// be tested without a pty. Backspace (0x7f and 0x08) removes the last byte;
// Enter ends the reading; Ctrl-C abandons it, which lands as empty; Ctrl-D
// ends the input, submitting what was typed — nothing, if nothing was.
// Reading refuses rather than truncates at the bound: a value of exactly the
// limit is accepted, and the next byte that is not a terminator, an edit or
// an end-of-input fails the entry as too large — a stored prefix of a larger
// value would be a silently wrong secret. Bytes past the refusal are left
// unread, exactly as the stdin path leaves them.
export function readHiddenValueBytes(descriptor = 0): Uint8Array {
  const bytes: number[] = [];
  const buffer = new Uint8Array(1);
  for (;;) {
    const read = readOnce(descriptor, buffer);
    if (read === 0) break;
    const byte = buffer[0] as number;
    if (byte === 0x0a || byte === 0x0d) break;
    if (byte === 0x03) return new Uint8Array(0);
    if (byte === 0x04) break;
    if (byte === 0x7f || byte === 0x08) {
      bytes.pop();
      continue;
    }
    if (bytes.length === secretLimits.maxValueBytes)
      throw new WardError("secret_value_too_large");
    bytes.push(byte);
  }
  return new Uint8Array(bytes);
}

// Standard input to EOF as exact bytes: nothing is stripped, and a
// terminator a producer sent is part of the value. Bounded rather than
// truncating — the read never takes more than one byte past the bound, so
// the refusal happens within one byte of it and the rest of the stream is
// left unread.
export function readStdinValueBytes(
  maxBytes: number,
  descriptor = 0,
): Uint8Array {
  const bytes: number[] = [];
  for (;;) {
    const size = Math.min(64 * 1024, maxBytes - bytes.length + 1);
    const buffer = new Uint8Array(size);
    const read = readOnce(descriptor, buffer);
    if (read === 0) break;
    for (let index = 0; index < read; index++) {
      bytes.push(buffer[index] as number);
    }
    if (bytes.length > maxBytes) throw new WardError("secret_value_too_large");
  }
  return new Uint8Array(bytes);
}

export function createTerminalSecretValues(
  parts: TerminalSecretParts = {},
): SecretValueSource {
  const isInteractive =
    parts.isInteractive ?? (() => process.stdin.isTTY === true);
  const setRaw = parts.setRaw ?? defaultSetRaw;
  const readHiddenBytes =
    parts.readHiddenBytes ?? (() => readHiddenValueBytes(0));
  const flushInput = parts.flushInput ?? (() => flushPendingInput(0));
  const inputPending = parts.inputPending ?? (() => inputQueued(0));
  const readStdinBytes =
    parts.readStdinBytes ?? ((maxBytes) => readStdinValueBytes(maxBytes, 0));
  const readAnswer = parts.readAnswer ?? readAnswerLine;
  const writePrompt = parts.writePrompt ?? defaultWritePrompt;
  const pending = (): boolean => {
    try {
      return inputPending();
    } catch {
      return false;
    }
  };
  const available = (): boolean => {
    try {
      return isInteractive();
    } catch {
      return false;
    }
  };

  return {
    available,
    readHidden() {
      if (!available()) return undefined;
      writePrompt("Enter the secret value: ");
      setRaw(true);
      try {
        const value = readHiddenBytes();
        // A value that ended on its terminator with more input still queued
        // behind it is a multi-line paste (DEC-255 a2 clause 3). It is refused
        // rather than stored as its first line, the same way a value past the
        // bound is refused rather than truncated; the finally below drains and
        // flushes what is queued before echo returns. An abandoned or empty
        // read is refused later on its own terms.
        if (value.length > 0 && pending())
          throw new WardError("secret_value_multiline");
        return value;
      } catch (error) {
        // A reading that refused the value is an answer, not a failure, and
        // is rethrown: swallowing it would report a too-large value as an
        // empty one. Everything else — a terminal that cannot be read —
        // cannot provide a value, and an unreadable answer is not a value.
        if (error instanceof WardError) throw error;
        return undefined;
      } finally {
        // Discard anything still queued on the terminal before echo comes
        // back. The bytes after the newline the read stopped on are not part
        // of the value; left in the line discipline, the shell that runs next
        // reads them as its own input. Best-effort, and never in place of
        // restoring echo.
        try {
          flushInput();
        } catch {
          // The flush is best-effort; restoring echo is not.
        }
        try {
          // Restored on every path, so a failure never leaves the
          // developer's terminal without echo.
          setRaw(false);
        } catch {
          // Nothing more can be done here, and the reading itself is what
          // the caller asked for.
        }
        writePrompt("\n");
      }
    },
    readStdin(maxBytes) {
      if (available()) throw new WardError("secret_stdin_terminal");
      return readStdinBytes(maxBytes);
    },
    confirmReplace(alias) {
      if (!available()) return false;
      try {
        writePrompt(
          [
            `A secret named ${escapeForDisplay(alias)} already exists in this project.`,
            "",
            "Replace it? The existing value cannot be recovered from Ward afterwards.",
            "Answer y to replace, anything else to leave it as it is. [y/N] ",
          ].join("\n"),
        );
        return isConsentAnswer(readAnswer());
      } catch {
        // An unanswerable question is not consent.
        return false;
      }
    },
  };
}
