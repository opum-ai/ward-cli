// The interactive half of backup and restore (spec §10, §4.3).
//
// The gate is the same one registration uses: `process.stdin.isTTY` must be
// true. A backup passphrase is never read from an argument, the environment
// or a pipe, so a caller with no terminal is refused rather than served from
// a stream something else can write to. That is a guardrail against a
// non-interactive caller, and — exactly as with registration — explicitly
// not proof of a person (spec §4.3).
//
// Echo is suppressed by putting the terminal into raw mode for the read and
// restoring it afterwards, including on every failure path: the terminal's
// line discipline is what echoes, so with it off no typed byte is displayed.
// Before echo comes back the terminal's pending input is discarded (drained
// until quiet, then flushed). That narrows the window in which the bytes a
// paste carries past the newline the read stops on can reach the shell that
// runs next; it does not close it. Nothing is printed in place of what is typed, not
// even one mask character per byte, because a mask discloses the
// passphrase's length. Backspace (0x7f and 0x08) removes the last byte;
// Enter ends the reading; Ctrl-C and Ctrl-D end it too, leaving whatever was
// typed. Reading refuses past its bound rather than truncating: a stream that
// never ends cannot grow it, and a passphrase longer than the bound is
// rejected rather than silently shortened. The prompt goes to the controlling
// terminal (or stderr) and never to stdout.
import {
  closeSync,
  constants as fileConstants,
  openSync,
  writeSync,
} from "node:fs";
import type { PassphraseSource } from "../application/backup.ts";
import { WardError } from "../contract/errors.ts";
import { readOnce } from "./secret-value.ts";
import { flushPendingInput } from "./terminal-input.ts";

export interface TerminalPassphraseParts {
  isInteractive?: () => boolean;
  setRaw?: (on: boolean) => void;
  readBytes?: () => Uint8Array;
  flushInput?: () => void;
  writePrompt?: (text: string) => void;
}

// A bound, not a policy: the longest passphrase Ward reads. What makes a
// passphrase strong is its entropy, and length alone is not proof of it
// (spec §10) — that sentence lives in the command's guidance, not here.
export const maxPassphraseBytes = 1024;

function defaultSetRaw(on: boolean): void {
  const stdin = process.stdin as { setRawMode?: (mode: boolean) => void };
  if (typeof stdin.setRawMode !== "function") throw new Error("no raw mode");
  stdin.setRawMode(on);
}

// The reader the terminal path uses, over any readable descriptor so its
// byte semantics (backspace, Ctrl-C, the bound) can be tested without a pty.
// At the bound it refuses rather than truncates, matching the secret reader:
// a value of exactly the limit is accepted, and the next byte that is not a
// terminator, an edit or an end-of-input fails the read as too large. A
// silently shortened passphrase would let the confirm step compare two
// identically truncated values and accept one the user never chose.
// What a read keeps while it runs, handed to the caller only so a test can see
// that both were zeroed on every way out.
export interface PassphraseReadScratch {
  bytes?: number[];
  buffer?: Uint8Array;
}

// Whatever the way out (a passphrase, an abandoned read, or a refusal that
// throws), the bytes read so far and the one-byte buffer are zeroed before it
// leaves; only the returned copy survives, and its owner zeroes it. The read
// retries the transient errors a non-blocking descriptor reports, as the secret
// reader does.
export function readPassphraseBytes(
  descriptor = 0,
  scratch: PassphraseReadScratch = {},
): Uint8Array {
  const bytes: number[] = [];
  const buffer = new Uint8Array(1);
  scratch.bytes = bytes;
  scratch.buffer = buffer;
  try {
    for (;;) {
      const read = readOnce(descriptor, buffer);
      if (read === 0) break;
      const byte = buffer[0] as number;
      if (byte === 0x0a || byte === 0x0d) break;
      // Ctrl-C is the user cancelling, and cancelling is not submitting: the
      // reading is abandoned whether or not anything was typed. Ctrl-D is the
      // end of input, which submits what was typed — nothing, if nothing was.
      if (byte === 0x03) throw new WardError("backup_passphrase_rejected");
      if (byte === 0x04) break;
      if (byte === 0x7f || byte === 0x08) {
        bytes.pop();
        continue;
      }
      if (bytes.length === maxPassphraseBytes)
        throw new WardError("backup_passphrase_too_large");
      bytes.push(byte);
    }
    return new Uint8Array(bytes);
  } finally {
    bytes.fill(0);
    buffer.fill(0);
  }
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

export function createTerminalPassphrase(
  parts: TerminalPassphraseParts = {},
): PassphraseSource {
  const isInteractive =
    parts.isInteractive ?? (() => process.stdin.isTTY === true);
  const setRaw = parts.setRaw ?? defaultSetRaw;
  const readBytes = parts.readBytes ?? (() => readPassphraseBytes(0));
  const flushInput = parts.flushInput ?? (() => flushPendingInput(0));
  const writePrompt = parts.writePrompt ?? defaultWritePrompt;
  const available = (): boolean => {
    try {
      return isInteractive();
    } catch {
      return false;
    }
  };

  const readOnce = (prompt: string): Uint8Array => {
    writePrompt(prompt);
    setRaw(true);
    try {
      return readBytes();
    } finally {
      // Discard anything still queued on the terminal before echo comes
      // back: a paste carries bytes past the newline the read stops on, and
      // left in the line discipline the shell that runs next reads them as
      // its own input. Best-effort, and never in place of restoring echo.
      try {
        flushInput();
      } catch {
        // The flush is best-effort; restoring echo is not.
      }
      // Restored on every path, so a failure never leaves the developer's
      // terminal without echo.
      try {
        setRaw(false);
      } catch {
        // Nothing more can be done here, and the reading itself is what the
        // caller asked for.
      }
      writePrompt("\n");
    }
  };

  return {
    available,
    read({ confirm }) {
      if (!available()) return undefined;
      let first: Uint8Array | undefined;
      try {
        first = readOnce("Enter a passphrase for this backup: ");
        if (first.length === 0)
          throw new WardError("backup_passphrase_rejected");
        if (!confirm) return first;
        const second = readOnce("Enter it again to confirm: ");
        try {
          if (second.length !== first.length)
            throw new WardError("backup_passphrase_rejected");
          for (let index = 0; index < second.length; index++)
            if (second[index] !== first[index])
              throw new WardError("backup_passphrase_rejected");
        } finally {
          second.fill(0);
        }
        return first;
      } catch (error) {
        first?.fill(0);
        if (error instanceof WardError) throw error;
        // A terminal that cannot be put into raw mode, or cannot be read,
        // cannot answer; an unanswerable question is not a passphrase.
        return undefined;
      }
    },
  };
}
