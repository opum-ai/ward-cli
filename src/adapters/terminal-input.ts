// Discarding bytes a hidden read never consumed (WCLI-97, W-2).
//
// A hidden read ends on the newline that terminates the value, and a paste
// carries whatever followed it on the same input: the next lines of a pasted
// block, still sitting in the terminal's input queue or still being written
// into it. Echo is off while the read runs, so they are not displayed then -
// but the moment Ward restores echo and exits, the shell that runs next reads
// them as if they had been typed at its prompt, and can execute them.
//
// One tcflush(2) drops only what is queued at that instant. A paste longer than
// the tty's input queue (a multi-line PEM key is 1.6 to 3.2 KB; measured on
// darwin, a flush alone let the tail past about 1 KB through) is flow-controlled:
// the flush unblocks the writer and the rest lands afterwards. So the discard
// is drained: wait until the terminal has been quiet for a short interval,
// flushing whatever shows up, then flush once more. The adapters call it on
// every exit path before restoring echo. It narrows the residue window to a
// paste that stalls for longer than the quiet interval (iTerm2's Paste Slowly,
// mosh, ssh over a lossy link) or that is still streaming past the 1.5 s cap;
// it does not make a paste harmless.
//
// The selector is not the same number on every platform: Darwin (BSD) numbers
// TCIFLUSH 1, and Linux numbers it 0. POLLIN is 1 on both. The ship target is
// darwin-arm64; the Linux value is here because the suite and the Linux build
// must stay correct. Nothing here reaches a credential store, so a failing
// call is swallowed: the discard is the last, best-effort step of a read that
// has already succeeded or refused on its own terms, and a descriptor that is
// not a terminal has no queue a shell could later read. A discard that cannot
// run at all (no libc to load it from) is not silent: it says so once on
// stderr, because a silent no-op is indistinguishable from a working flush. The
// same line is printed when the flush resolves without poll.
import { dlopen } from "bun:ffi";
import { writeSync } from "node:fs";
import { isatty } from "node:tty";

type Tcflush = (descriptor: number, selector: number) => number;
type Poll = (
  fds: Int32Array,
  count: number | bigint,
  timeoutMs: number,
) => number;

// <termios.h>: TCIFLUSH, the selector for the terminal's input queue.
const TCIFLUSH = process.platform === "darwin" ? 1 : 0;

// <poll.h>: the event bit and the three revents that mean the descriptor is not
// simply readable. The values are the same on darwin and Linux.
const POLLIN = 0x1;
const POLLERR = 0x8;
const POLLHUP = 0x10;
const POLLNVAL = 0x20;

// How long the terminal must stay silent before the drain believes the paste
// is over, and the most it will wait in total so a terminal that never goes
// quiet cannot hold the command.
const QUIET_MS = 30;
const DRAIN_BUDGET_MS = 1_500;

// nfds_t is unsigned int on darwin and unsigned long on glibc.
const NFDS_TYPE = process.platform === "darwin" ? "u32" : "u64";

// The C library to load from. glibc exposes libc.so.6; musl's is normally
// reachable as libc.so. Tried in order, and the first that resolves wins.
function libraryCandidates(): string[] {
  return process.platform === "darwin"
    ? ["/usr/lib/libSystem.B.dylib"]
    : ["libc.so.6", "libc.so"];
}

type Resolved = { tcflush: Tcflush; poll: Poll | undefined };

// undefined means "not tried yet", so a machine without a loadable libc pays
// the failed lookup once rather than on every read.
let resolved: Resolved | null | undefined;

function resolve(): Resolved | undefined {
  if (resolved !== undefined) return resolved ?? undefined;
  resolved = null;
  for (const library of libraryCandidates()) {
    try {
      const symbols = dlopen(library, {
        tcflush: { args: ["int", "int"], returns: "int" },
        poll: { args: ["ptr", NFDS_TYPE, "int"], returns: "int" },
      }).symbols as { tcflush?: Tcflush; poll?: Poll };
      if (symbols.tcflush !== undefined) {
        resolved = { tcflush: symbols.tcflush, poll: symbols.poll };
        break;
      }
    } catch {
      // Try the next name; the caller only needs one that resolves.
    }
  }
  return resolved ?? undefined;
}

// Whether the discard can run on this machine, and whether it can wait for a
// long paste to finish. Read by the test that proves the real libc call
// resolves where CI runs, since every adapter test stubs the flush.
export function terminalInputSupport(): { flush: boolean; drain: boolean } {
  const found = resolve();
  return { flush: found !== undefined, drain: found?.poll !== undefined };
}

let warned = false;

function warnOnce(): void {
  if (warned) return;
  warned = true;
  try {
    writeSync(
      2,
      "ward: could not discard pending terminal input; text pasted after the value may reach your shell\n",
    );
  } catch {
    // Nothing more can be done here.
  }
}

// One poll of a descriptor for input, through the same binding the drain uses.
// result is poll's return (negative on error) and revents is what the kernel
// reported for the descriptor. A behavioural CI probe calls this on a pipe.
export function pollInput(
  descriptor: number,
  timeoutMs: number,
): { result: number; revents: number } | undefined {
  const found = resolve();
  if (found?.poll === undefined) return undefined;
  // struct pollfd { int fd; short events; short revents; }, little endian on
  // both targets: events is the low half of the second word and revents the
  // high half, which the kernel overwrites, so events is set again each call.
  const fds = new Int32Array([descriptor, POLLIN]);
  const count = NFDS_TYPE === "u64" ? 1n : 1;
  const result = found.poll(fds, count, timeoutMs);
  return { result, revents: ((fds[1] as number) >>> 16) & 0xffff };
}

// Whether input is still queued on a terminal right now, which after a hidden
// read has stopped on its terminator means the paste carried more than one line
// (DEC-255 a2 clause 3). It waits one quiet interval, because the rest of a
// paste can still be arriving, and counts only a plain readable descriptor: an
// error, a hang-up or an invalid descriptor is not queued input. A descriptor
// that is not a terminal has no queue a shell could later read and reports
// false, and so does a machine where poll did not resolve - the refusal is a
// best-effort narrowing of the paste window, like the discard it precedes.
export function inputQueued(descriptor = 0): boolean {
  if (!isatty(descriptor)) return false;
  const polled = pollInput(descriptor, QUIET_MS);
  if (polled === undefined || polled.result <= 0) return false;
  if (polled.revents & (POLLERR | POLLHUP | POLLNVAL)) return false;
  return (polled.revents & POLLIN) !== 0;
}

// Wait for the terminal to go quiet, flushing whatever arrives meanwhile. It
// stops when poll reports quiet, when the descriptor is in error or hung up, or
// at the deadline; a poll that fails (EINTR, say) is simply tried again within
// the deadline.
//
// The two calls are passed in so a test can answer them: a tty will not report
// POLLHUP or POLLNVAL on demand.
export type DrainPorts = {
  poll: (timeoutMs: number) => { result: number; revents: number } | undefined;
  flush: () => void;
  now?: () => number;
};

export function drainPending(ports: DrainPorts): void {
  const now = ports.now ?? (() => performance.now());
  const deadline = now() + DRAIN_BUDGET_MS;
  while (now() < deadline) {
    const polled = ports.poll(QUIET_MS);
    if (polled === undefined) return;
    if (polled.result < 0) continue;
    if (polled.result === 0) return;
    if (polled.revents & (POLLERR | POLLHUP | POLLNVAL)) return;
    if (!(polled.revents & POLLIN)) return;
    ports.flush();
  }
}

function drain(found: Resolved, descriptor: number): void {
  if (found.poll === undefined) return;
  drainPending({
    poll: (timeoutMs) => pollInput(descriptor, timeoutMs),
    flush: () => found.tcflush(descriptor, TCIFLUSH),
  });
}

export function flushPendingInput(descriptor = 0): void {
  if (!isatty(descriptor)) return;
  const found = resolve();
  if (found === undefined) {
    warnOnce();
    return;
  }
  // A flush with no drain leaks a paste past the tty queue (measured), so the
  // missing drain is said once, like a missing libc.
  if (found.poll === undefined) warnOnce();
  try {
    found.tcflush(descriptor, TCIFLUSH);
    drain(found, descriptor);
    found.tcflush(descriptor, TCIFLUSH);
  } catch {
    // Nothing more can be done here, and the reading is what the caller
    // asked for.
  }
}
