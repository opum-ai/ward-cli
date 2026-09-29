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
      "raw:off",
      // The reader ends each reading with a newline, so the terminal's next
      // output starts on its own line rather than beside the prompt.
      "prompt:",
      "prompt:Enter it again to confirm:",
      "raw:on",
      "read",
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
      writePrompt: () => {},
    });
    expect(source.read({ confirm: false })).toBeUndefined();
    expect(events).toEqual(["raw:on", "raw:off"]);
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

  test("the bound stops a stream that never ends", () => {
    const endless = new Array(maxPassphraseBytes + 16).fill(0x61);
    expect(read(endless).length).toBe(maxPassphraseBytes);
  });
});
