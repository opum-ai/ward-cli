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
import { describe, expect, test } from "bun:test";
import {
  createTerminalPassphrase,
  maxPassphraseBytes,
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
    // a passphrase without limit. What a real terminal delivers is the
    // default reader's own business, which needs a pty to observe.
    expect(maxPassphraseBytes).toBeGreaterThan(0);
    expect(maxPassphraseBytes).toBeLessThanOrEqual(4096);
  });
});
