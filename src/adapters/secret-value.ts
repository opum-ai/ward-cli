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
import {
  flushPendingInput,
  inputQueued,
  pollInput,
  POLLIN,
  QUIET_MS,
} from "./terminal-input.ts";

export interface TerminalSecretParts {
  isInteractive?: () => boolean;
  setRaw?: (on: boolean) => void;
  readHiddenBytes?: () => Uint8Array;
  // A result of exactly true means input arrived after the read stopped and
  // was flushed; anything else means none did.
  flushInput?: () => unknown;
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

// The seams a descriptor read takes, so a test can make it report the
// transient errors a real non-blocking descriptor does.
export interface ReadPorts {
  read?: (descriptor: number, buffer: Uint8Array) => number;
  // Called before an EAGAIN is retried: the descriptor has nothing to read yet.
  wait?: (descriptor: number) => void;
}

function defaultRead(descriptor: number, buffer: Uint8Array): number {
  return readSync(descriptor, buffer, 0, buffer.length, null);
}

// Waits until the descriptor is readable, or a quiet interval passes, so a
// retry does not spin. Where poll did not resolve it sleeps the interval.
function defaultWait(descriptor: number): void {
  if (pollInput(descriptor, QUIET_MS) !== undefined) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, QUIET_MS);
}

// A descriptor read that is retried across the transient errors a
// non-blocking standard input can report before its first byte arrives. EINTR
// is retried at once; EAGAIN waits for readability first, because a
// non-blocking terminal reports it for as long as the person has not typed.
export function readOnce(
  descriptor: number,
  buffer: Uint8Array,
  ports: ReadPorts = {},
): number {
  const read = ports.read ?? defaultRead;
  const wait = ports.wait ?? defaultWait;
  for (;;) {
    try {
      return read(descriptor, buffer);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EINTR") continue;
      if (code === "EAGAIN" || code === "EWOULDBLOCK") {
        wait(descriptor);
        continue;
      }
      throw error;
    }
  }
}

// A value that ended on a carriage return may be followed by its line feed (a
// value copied from a CRLF file, or a terminal that sends both on Enter), which
// is part of the terminator and not a second line. It is consumed when it is
// already there. Any other byte directly behind the return is input queued
// after the terminator, which is the multi-line paste DEC-255 (a2) clause 3
// refuses; the byte is not kept. The caller owns `next` and zeroes it.
function consumeLineFeedAfterReturn(
  descriptor: number,
  next: Uint8Array,
): void {
  const polled = pollInput(descriptor, QUIET_MS);
  if (polled === undefined || polled.result <= 0) return;
  if ((polled.revents & POLLIN) === 0) return;
  if (readOnce(descriptor, next) === 0) return;
  if (next[0] !== 0x0a) throw new WardError("secret_value_multiline");
}

// What a read keeps while it runs, handed to the caller only so a test can see
// that every one of them was zeroed on every way out.
export interface HiddenReadScratch {
  // The fixed array the bytes are held in, and the most it ever held.
  held?: Uint8Array;
  peak?: number;
  buffer?: Uint8Array;
  next?: Uint8Array;
}

// The hidden reader, over any readable descriptor so its byte semantics can
// be tested without a pty. Backspace (0x7f and 0x08) removes the last byte;
// Enter ends the reading; Ctrl-C abandons it, which lands as empty; Ctrl-D
// ends the input, submitting what was typed — nothing, if nothing was.
// Reading refuses rather than truncates at the bound: a value of exactly the
// limit is accepted, and the next byte that is not a terminator, an edit or
// an end-of-input fails the entry as too large — a stored prefix of a larger
// value would be a silently wrong secret. Bytes past the refusal are left
// unread, exactly as the stdin path leaves them. Whatever the way out (a
// value, an abandoned read, or a refusal that throws), the bytes read so far
// and the one-byte buffers are zeroed before it leaves. The bytes live in one
// fixed array and a backspace zeroes the slot it frees, so no typed byte
// outlives the read in a place fill(0) cannot reach. Only the returned copy
// survives, and its owner zeroes it.
export function readHiddenValueBytes(
  descriptor = 0,
  scratch: HiddenReadScratch = {},
): Uint8Array {
  const held = new Uint8Array(secretLimits.maxValueBytes);
  let count = 0;
  const buffer = new Uint8Array(1);
  const next = new Uint8Array(1);
  scratch.held = held;
  scratch.peak = 0;
  scratch.buffer = buffer;
  scratch.next = next;
  try {
    for (;;) {
      const read = readOnce(descriptor, buffer);
      if (read === 0) break;
      const byte = buffer[0] as number;
      if (byte === 0x0d) {
        consumeLineFeedAfterReturn(descriptor, next);
        break;
      }
      if (byte === 0x0a) break;
      if (byte === 0x03) return new Uint8Array(0);
      if (byte === 0x04) break;
      if (byte === 0x7f || byte === 0x08) {
        if (count > 0) held[--count] = 0;
        continue;
      }
      if (count === held.length) throw new WardError("secret_value_too_large");
      held[count++] = byte;
      scratch.peak = Math.max(scratch.peak, count);
    }
    return held.slice(0, count);
  } finally {
    held.fill(0);
    buffer.fill(0);
    next.fill(0);
  }
}

// Standard input to EOF as exact bytes: nothing is stripped, and a
// terminator a producer sent is part of the value. Bounded rather than
// truncating — the read never takes more than one byte past the bound, so
// the refusal happens within one byte of it and the rest of the stream is
// left unread.
//
// The bytes are read into one array, sized to the bound and one byte more,
// and that array is zeroed on every way out, the refusal included; no second
// copy is kept. Only the returned copy survives, and its owner zeroes it.
export interface StdinReadScratch {
  buffer?: Uint8Array;
}

export function readStdinValueBytes(
  maxBytes: number,
  descriptor = 0,
  scratch: StdinReadScratch = {},
  ports: ReadPorts = {},
): Uint8Array {
  const buffer = new Uint8Array(maxBytes + 1);
  scratch.buffer = buffer;
  let length = 0;
  try {
    for (;;) {
      const read = readOnce(descriptor, buffer.subarray(length), ports);
      if (read === 0) break;
      length += read;
      if (length > maxBytes) throw new WardError("secret_value_too_large");
    }
    return buffer.slice(0, length);
  } finally {
    buffer.fill(0);
  }
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
      let value: Uint8Array | undefined;
      let failure: { readonly error: unknown } | undefined;
      let queued = false;
      let arrivedLate = false;
      try {
        value = readHiddenBytes();
        // A value that ended on its terminator with more input still queued
        // behind it is a multi-line paste (DEC-255 a2 clause 3). It is refused
        // rather than stored as its first line, the same way a value past the
        // bound is refused rather than truncated. An abandoned or empty read is
        // refused later on its own terms.
        queued = value.length > 0 && pending();
      } catch (error) {
        failure = { error };
      } finally {
        // Discard anything still queued on the terminal before echo comes
        // back. The bytes after the newline the read stopped on are not part
        // of the value; left in the line discipline, the shell that runs next
        // reads them as its own input. Best-effort, and never in place of
        // restoring echo. The discard also reports whether input arrived after
        // the probe above looked: a paste that trickles in later is still a
        // paste, and storing its first line would be a silently wrong secret.
        try {
          arrivedLate = flushInput() === true;
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
        try {
          writePrompt("\n");
        } catch {
          // A prompt that cannot be written must not drop the value read.
        }
      }
      if (failure !== undefined) {
        // A reading that refused the value is an answer, not a failure, and
        // is rethrown: swallowing it would report a too-large value as an
        // empty one. Everything else — a terminal that cannot be read —
        // cannot provide a value, and an unreadable answer is not a value.
        if (failure.error instanceof WardError) throw failure.error;
        return undefined;
      }
      if (value !== undefined && value.length > 0 && (queued || arrivedLate)) {
        // The first line of a refused paste may be real secret material.
        value.fill(0);
        throw new WardError("secret_value_multiline");
      }
      return value;
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
