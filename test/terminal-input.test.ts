// WCLI-97 (W-2): every adapter test stubs the flush, and the real-pty proof is
// qualified on darwin only, so on Linux CI nothing would notice a libc call
// that no longer resolves. This case is not skipped anywhere: the real
// tcflush and poll must resolve on the platform that runs it.
import "./support/no-real-keychain.ts";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  constants,
  mkdtempSync,
  openSync,
  rmSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import {
  pollInput,
  terminalInputSupport,
} from "../src/adapters/terminal-input.ts";

test("the libc tcflush and poll the discard needs resolve on this platform", () => {
  expect(terminalInputSupport()).toEqual({ flush: true, drain: true });
});

// poll must actually answer, not merely resolve: nothing queued is "quiet"
// (0) and one byte is POLLIN (1). A fifo stands in for the terminal so this
// runs on Linux CI as well as darwin.
test("poll through the real binding reports quiet, then input", () => {
  const dir = mkdtempSync(join(tmpdir(), "ward-poll-"));
  const path = join(dir, "fifo");
  try {
    expect(spawnSync("mkfifo", [path]).status).toBe(0);
    const reader = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const writer = openSync(path, constants.O_WRONLY);
    try {
      expect(pollInput(reader, 0)).toEqual({ result: 0, revents: 0 });
      writeSync(writer, "x");
      expect(pollInput(reader, 0)).toEqual({ result: 1, revents: 1 });
    } finally {
      closeSync(reader);
      closeSync(writer);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
