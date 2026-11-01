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
  drainPending,
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

// The drain's stop conditions, answered by a fake poll because a tty will not
// report POLLHUP or POLLNVAL on demand. Without the revents check a hung-up or
// invalid descriptor returns 1 at once and the loop spins flushing until the
// 1.5 s cap, on every prompt.
function drained(answers: Array<{ result: number; revents: number }>) {
  let polls = 0;
  let flushes = 0;
  let clock = 0;
  drainPending({
    poll: () => {
      const answer = answers[polls++] ?? { result: 1, revents: 1 };
      return answer;
    },
    flush: () => {
      flushes++;
    },
    // Each read of the clock advances 1 ms, so a loop that never stops ends at
    // the cap rather than hanging the test.
    now: () => clock++,
  });
  return { polls, flushes };
}

test("the drain stops at once on POLLERR, POLLHUP or POLLNVAL, without flushing", () => {
  for (const revents of [0x8, 0x10, 0x20, 0x11, 0x21])
    expect(drained([{ result: 1, revents }])).toEqual({ polls: 1, flushes: 0 });
});

test("the drain flushes while input keeps arriving and stops when poll reports quiet", () => {
  expect(
    drained([
      { result: 1, revents: 1 },
      { result: 1, revents: 1 },
      { result: 0, revents: 0 },
    ]),
  ).toEqual({ polls: 3, flushes: 2 });
});

test("a failed poll is tried again, and a poll with no POLLIN stops the drain", () => {
  expect(
    drained([
      { result: -1, revents: 0 },
      { result: 1, revents: 1 },
      { result: 0, revents: 0 },
    ]),
  ).toEqual({ polls: 3, flushes: 1 });
  expect(drained([{ result: 1, revents: 0 }])).toEqual({
    polls: 1,
    flushes: 0,
  });
});

test("a terminal that never goes quiet is released at the cap", () => {
  const result = drained([]);
  expect(result.polls).toBeGreaterThan(0);
  expect(result.polls).toBeLessThan(2_000);
});
