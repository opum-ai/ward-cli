// The terminal passphrase reader (spec §10).
//
// Echo is suppressed by the terminal being in raw mode while the reader
// reads, so these tests assert the sequence — raw mode on before any byte is
// read, and off again on every path including the refusals — rather than a
// terminal's own behaviour, which a test cannot observe. The bytes a
// terminal would deliver arrive here through the same seam the adapter takes
// them from, so nothing here needs a pty.
//
// The keychain mock is imported first because this file reaches an adapter,
// which is the isolation rule for every file under test/ (WCLI-5); nothing
// here calls the credential store.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  closeSync,
  mkdtempSync,
  openSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createTerminalPassphrase,
  maxPassphraseBytes,
  type PassphraseReadScratch,
  readPassphraseBytes,
} from "../src/adapters/passphrase.ts";
import { WardError } from "../src/contract/errors.ts";

const encode = (text: string) => new TextEncoder().encode(text);

function terminal(
  options: { inputs?: number[][]; interactive?: boolean } = {},
) {
  const events: string[] = [];
  const inputs = options.inputs ?? [];
  let index = 0;
  let raw = false;
  let reads = 0;
  return {
    events,
    parts: {
      isInteractive: () => options.interactive ?? true,
      setRaw: (on: boolean) => {
        raw = on;
        events.push(on ? "raw:on" : "raw:off");
      },
      readBytes: () => {
        reads += 1;
        // The property under test: no byte is read while the terminal would
        // be echoing it.
        events.push(raw ? "read" : "read-while-echoing");
        return new Uint8Array(inputs[index++] ?? []);
      },
      // Queued input is discarded on every exit path, before echo returns.
      flushInput: () => events.push("flush"),
      writePrompt: (text: string) => events.push(`prompt:${text.trim()}`),
    },
    raw: () => raw,
    reads: () => reads,
  };
}

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (error) {
    return error instanceof WardError ? error.code : "not-a-ward-error";
  }
}

describe("the terminal passphrase reader", () => {
  test("a confirmed passphrase is read twice, with echo off both times", () => {
    const t = terminal({
      inputs: [[...encode("correct horse")], [...encode("correct horse")]],
    });
    const source = createTerminalPassphrase(t.parts);
    const bytes = source.read({ confirm: true });
    expect(new TextDecoder().decode(bytes)).toBe("correct horse");
    expect(t.events).toEqual([
      "prompt:Enter a passphrase for this backup:",
      "raw:on",
      "read",
      "flush",
      "raw:off",
      // The reader ends each reading with a newline, so the terminal's next
      // output starts on its own line rather than beside the prompt.
      "prompt:",
      "prompt:Enter it again to confirm:",
      "raw:on",
      "read",
      "flush",
      "raw:off",
      "prompt:",
    ]);
    expect(t.raw()).toBe(false);
  });

  test("opening reads once, and never confirms", () => {
    const t = terminal({ inputs: [[...encode("the passphrase")]] });
    const bytes = createTerminalPassphrase(t.parts).read({ confirm: false });
    expect(new TextDecoder().decode(bytes)).toBe("the passphrase");
    expect(t.reads()).toBe(1);
    // One question asked, plus the newline the reader ends it with.
    expect(
      t.events.filter(
        (event) => event.startsWith("prompt:") && event !== "prompt:",
      ),
    ).toHaveLength(1);
  });

  test("an empty reading and a mismatch are both refused, terminal restored", () => {
    const empty = terminal({ inputs: [[]] });
    expect(
      codeOf(() =>
        createTerminalPassphrase(empty.parts).read({ confirm: true }),
      ),
    ).toBe("backup_passphrase_rejected");
    expect(empty.events).toEqual([
      "prompt:Enter a passphrase for this backup:",
      "raw:on",
      "read",
      "flush",
      "raw:off",
      "prompt:",
    ]);
    expect(empty.raw()).toBe(false);

    const mismatch = terminal({
      inputs: [[...encode("one")], [...encode("another")]],
    });
    expect(
      codeOf(() =>
        createTerminalPassphrase(mismatch.parts).read({ confirm: true }),
      ),
    ).toBe("backup_passphrase_rejected");
    expect(mismatch.raw()).toBe(false);
  });

  test("no terminal means no reading and no prompt", () => {
    const t = terminal({ interactive: false, inputs: [[...encode("x")]] });
    const source = createTerminalPassphrase(t.parts);
    expect(source.available()).toBe(false);
    expect(source.read({ confirm: true })).toBeUndefined();
    expect(t.events).toEqual([]);
  });

  test("a read that fails leaves the terminal as it was", () => {
    const events: string[] = [];
    let raw = false;
    const source = createTerminalPassphrase({
      isInteractive: () => true,
      setRaw: (on: boolean) => {
        raw = on;
        events.push(on ? "raw:on" : "raw:off");
      },
      readBytes: () => {
        throw new Error("the terminal went away");
      },
      flushInput: () => events.push("flush"),
      writePrompt: () => {},
    });
    expect(source.read({ confirm: false })).toBeUndefined();
    expect(events).toEqual(["raw:on", "flush", "raw:off"]);
    expect(raw).toBe(false);
  });

  test("the reading is bounded", () => {
    // The bound is a product property: a stream that never ends cannot grow
    // a passphrase without limit. The reader that enforces it takes any
    // readable descriptor, which is what the cases below drive.
    expect(maxPassphraseBytes).toBeGreaterThan(0);
    expect(maxPassphraseBytes).toBeLessThanOrEqual(4096);
  });
});

describe("the byte reader the terminal path uses", () => {
  const root = mkdtempSync(join(tmpdir(), "ward-passphrase-reader-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));
  let cases = 0;

  const bytes = (text: string) => [...new TextEncoder().encode(text)];

  function read(bytesHere: number[]): Uint8Array {
    const path = join(root, `case-${++cases}`);
    writeFileSync(path, Buffer.from(bytesHere));
    const descriptor = openSync(path, "r");
    try {
      return readPassphraseBytes(descriptor);
    } finally {
      closeSync(descriptor);
    }
  }

  test("the reader zeroes what it read on every way out", () => {
    const run = (input: number[], expected: string, length: number) => {
      const path = join(root, `case-${++cases}`);
      writeFileSync(path, Buffer.from(input));
      const descriptor = openSync(path, "r");
      const scratch: PassphraseReadScratch = {};
      let outcome: string;
      try {
        outcome = new TextDecoder().decode(
          readPassphraseBytes(descriptor, scratch),
        );
      } catch (error) {
        outcome = (error as { code?: string }).code ?? "unknown";
      } finally {
        closeSync(descriptor);
      }
      expect(outcome).toBe(expected);
      // An every() over an empty array is vacuously true: assert the length.
      expect(scratch.bytes?.length).toBe(length);
      expect(scratch.bytes?.every((byte) => byte === 0)).toBe(true);
      expect(scratch.buffer && [...scratch.buffer]).toEqual([0]);
    };
    run([...bytes("hunter2"), 0x0a], "hunter2", 7);
    run([...bytes("half"), 0x03], "backup_passphrase_rejected", 4);
    run(
      new Array(maxPassphraseBytes + 1).fill(0x61),
      "backup_passphrase_too_large",
      maxPassphraseBytes,
    );
  });

  test("a line ending ends the reading and is not part of it", () => {
    expect(
      new TextDecoder().decode(read([...bytes("correct horse"), 0x0a])),
    ).toBe("correct horse");
    expect(new TextDecoder().decode(read([...bytes("done"), 0x0d]))).toBe(
      "done",
    );
  });

  test("backspace removes the last byte, and EOF submits what was typed", () => {
    expect(
      new TextDecoder().decode(
        read([...bytes("ab"), 0x7f, ...bytes("c"), 0x0a]),
      ),
    ).toBe("ac");
    expect(new TextDecoder().decode(read([...bytes("partial"), 0x04]))).toBe(
      "partial",
    );
    expect(read([]).length).toBe(0);
  });

  test("Ctrl-C cancels rather than submitting what was typed", () => {
    // The distinction the catalog's third clause names: a cancel must not
    // hand back a partial passphrase as if it had been typed and entered.
    let caught: unknown;
    try {
      read([...bytes("half"), 0x03]);
    } catch (error) {
      caught = error;
    }
    expect((caught as { code?: string } | undefined)?.code).toBe(
      "backup_passphrase_rejected",
    );
  });

  test("the bound refuses a stream that never ends rather than truncating", () => {
    // The old reader stopped reading at the bound and returned what it had,
    // so the confirm step could compare two identically truncated values and
    // accept a passphrase the user never chose. It now refuses, exactly as
    // the secret reader does.
    const endless = new Array(maxPassphraseBytes + 16).fill(0x61);
    let caught: unknown;
    try {
      read(endless);
    } catch (error) {
      caught = error;
    }
    expect((caught as { code?: string } | undefined)?.code).toBe(
      "backup_passphrase_too_large",
    );
  });

  test("exactly the bound is accepted, and the next byte is a refusal", () => {
    const atBound = new Array(maxPassphraseBytes).fill(0x61);
    // Terminated at the bound: accepted, unchanged.
    expect(read([...atBound, 0x0a]).length).toBe(maxPassphraseBytes);
    // End of input at the bound submits what was typed.
    expect(read(atBound).length).toBe(maxPassphraseBytes);
    // One more byte, whatever it is, is too large — including a byte that
    // differs from the first reading only past the bound.
    let caught: unknown;
    try {
      read([...atBound, 0x62]);
    } catch (error) {
      caught = error;
    }
    expect((caught as { code?: string } | undefined)?.code).toBe(
      "backup_passphrase_too_large",
    );
  });

  test("a refusal or a cancel still flushes queued input before echo returns", () => {
    // Drive the real reader through the adapter, over a descriptor that
    // stands in for the terminal, so the bound refusal and the Ctrl-C cancel
    // both land in the adapter's finally. Nothing queued may survive it.
    const run = (input: number[]): string[] => {
      const path = join(root, `exit-${++cases}`);
      writeFileSync(path, Buffer.from(input));
      const descriptor = openSync(path, "r");
      const events: string[] = [];
      try {
        const source = createTerminalPassphrase({
          isInteractive: () => true,
          setRaw: (on: boolean) => events.push(on ? "raw:on" : "raw:off"),
          readBytes: () => readPassphraseBytes(descriptor),
          flushInput: () => events.push("flush"),
          writePrompt: () => {},
        });
        try {
          source.read({ confirm: false });
        } catch {
          // A refusal is an answer; only the ordering of the exit matters.
        }
        return events;
      } finally {
        closeSync(descriptor);
      }
    };

    const atBound = new Array(maxPassphraseBytes).fill(0x61);
    // The refusal at the bound, the Ctrl-C cancel, and a success all undo
    // echo, and each flushes the queue first.
    for (const input of [
      [...atBound, 0x62], // too large
      [...bytes("half"), 0x03], // Ctrl-C
      [...bytes("value"), 0x0a, ...bytes("leftover")], // success
    ]) {
      expect(run(input)).toEqual(["raw:on", "flush", "raw:off"]);
    }
  });
});
