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
// paste that stalls for longer than the quiet interval; it does not make a
// paste harmless.
//
// The selector is not the same number on every platform: Darwin (BSD) numbers
// TCIFLUSH 1, and Linux numbers it 0. POLLIN is 1 on both. The ship target is
// darwin-arm64; the Linux value is here because the suite and the Linux build
// must stay correct. Nothing here reaches a credential store, so a failing
// call is swallowed: the discard is the last, best-effort step of a read that
// has already succeeded or refused on its own terms, and a descriptor that is
// not a terminal has no queue a shell could later read. A discard that cannot
// run at all (no libc to load it from) is not silent: it says so once on
// stderr, because a silent no-op is indistinguishable from a working flush.
import { dlopen } from "bun:ffi";
import { writeSync } from "node:fs";
import { isatty } from "node:tty";

type Tcflush = (descriptor: number, selector: number) => number;
type Poll = (fds: Int32Array, count: number, timeoutMs: number) => number;

// <termios.h>: TCIFLUSH, the selector for the terminal's input queue.
const TCIFLUSH = process.platform === "darwin" ? 1 : 0;

// <poll.h>: POLLIN.
const POLLIN = 1;

// How long the terminal must stay silent before the drain believes the paste
// is over, and the most it will wait in total so a terminal that never goes
// quiet cannot hold the command.
const QUIET_MS = 30;
const DRAIN_BUDGET_MS = 1_500;

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
        poll: { args: ["ptr", "u32", "int"], returns: "int" },
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

// Wait for the terminal to go quiet, flushing whatever arrives meanwhile.
function drain(found: Resolved, descriptor: number): void {
  if (found.poll === undefined) return;
  // struct pollfd { int fd; short events; short revents; }, little endian on
  // both targets: events is the low half of the second word.
  const fds = new Int32Array([descriptor, POLLIN]);
  const deadline = Date.now() + DRAIN_BUDGET_MS;
  while (Date.now() < deadline) {
    if (found.poll(fds, 1, QUIET_MS) <= 0) return;
    found.tcflush(descriptor, TCIFLUSH);
  }
}

export function flushPendingInput(descriptor = 0): void {
  if (!isatty(descriptor)) return;
  const found = resolve();
  if (found === undefined) {
    warnOnce();
    return;
  }
  try {
    found.tcflush(descriptor, TCIFLUSH);
    drain(found, descriptor);
    found.tcflush(descriptor, TCIFLUSH);
  } catch {
    // Nothing more can be done here, and the reading is what the caller
    // asked for.
  }
}
