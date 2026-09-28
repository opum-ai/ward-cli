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
// Nothing is printed in place of what is typed, not even one mask character
// per byte, because a mask discloses the passphrase's length. Backspace
// (0x7f and 0x08) removes the last byte; Enter ends the reading; Ctrl-C and
// Ctrl-D end it too, leaving whatever was typed. Reading is bounded, so a
// stream that never ends cannot grow it, and the prompt goes to the
// controlling terminal (or stderr) and never to stdout.
import {
  closeSync,
  constants as fileConstants,
  openSync,
  readSync,
  writeSync,
} from "node:fs";
import type { PassphraseSource } from "../application/backup.ts";
import { WardError } from "../contract/errors.ts";

export interface TerminalPassphraseParts {
  isInteractive?: () => boolean;
  setRaw?: (on: boolean) => void;
  readBytes?: () => Uint8Array;
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

function defaultReadBytes(): Uint8Array {
  const bytes: number[] = [];
  const buffer = new Uint8Array(1);
  while (bytes.length < maxPassphraseBytes) {
    const read = readSync(0, buffer, 0, 1, null);
    if (read === 0) break;
    const byte = buffer[0] as number;
    if (byte === 0x0a || byte === 0x0d) break;
    if (byte === 0x03 || byte === 0x04) break;
    if (byte === 0x7f || byte === 0x08) {
      bytes.pop();
      continue;
    }
    bytes.push(byte);
  }
  return new Uint8Array(bytes);
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
  const readBytes = parts.readBytes ?? defaultReadBytes;
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
