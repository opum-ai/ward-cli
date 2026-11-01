// WCLI-97 (W-2): every adapter test stubs the flush, and the real-pty proof is
// qualified on darwin only, so on Linux CI nothing would notice a libc call
// that no longer resolves. This case is not skipped anywhere: the real
// tcflush and poll must resolve on the platform that runs it.
import "./support/no-real-keychain.ts";
import { expect, test } from "bun:test";
import { terminalInputSupport } from "../src/adapters/terminal-input.ts";

test("the libc tcflush and poll the discard needs resolve on this platform", () => {
  expect(terminalInputSupport()).toEqual({ flush: true, drain: true });
});
