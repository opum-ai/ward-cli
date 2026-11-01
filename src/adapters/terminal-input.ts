// Discarding bytes a hidden read never consumed (WCLI-97, W-2).
//
// A hidden read ends on the newline that terminates the value, and a paste
// carries whatever followed it on the same input: the next lines of a pasted
// block, still sitting in the terminal's input queue. Echo is off while the
// read runs, so they are not displayed then — but the moment Ward restores
// echo and exits, the shell that runs next reads them as if they had been
// typed at its prompt, and can execute them. tcflush(2) drops that queue in
// one step, and the adapters call it on every exit path before restoring
// echo.
//
// The selector is not the same number on every platform: Darwin (BSD) numbers
// TCIFLUSH 1, and Linux numbers it 0. The ship target is darwin-arm64; the
// Linux value is here because the suite and the Linux build must stay
// correct. Nothing here reaches a credential store, so any failure is
// swallowed: the flush is the last, best-effort step of a read that has
// already succeeded or refused on its own terms, and a descriptor that is
// not a terminal has no queue a shell could later read.
import { dlopen } from "bun:ffi";
import { isatty } from "node:tty";

// <termios.h>: TCIFLUSH, the selector for the terminal's input queue.
const TCIFLUSH = process.platform === "darwin" ? 1 : 0;

type Tcflush = (descriptor: number, selector: number) => number;

// The C library to load tcflush from. glibc exposes libc.so.6; musl's is
// normally reachable as libc.so. Tried in order, and the first that resolves
// wins.
function libraryCandidates(): string[] {
  return process.platform === "darwin"
    ? ["/usr/lib/libSystem.B.dylib"]
    : ["libc.so.6", "libc.so"];
}

// undefined means "not tried yet", so a machine without a loadable libc pays
// the failed lookup once rather than on every read.
let resolved: Tcflush | null | undefined;

function tcflush(): Tcflush | undefined {
  if (resolved !== undefined) return resolved ?? undefined;
  resolved = null;
  for (const library of libraryCandidates()) {
    try {
      const symbol = dlopen(library, {
        tcflush: { args: ["int", "int"], returns: "int" },
      }).symbols.tcflush as Tcflush | undefined;
      if (symbol !== undefined) {
        resolved = symbol;
        break;
      }
    } catch {
      // Try the next name; the caller only needs one that resolves.
    }
  }
  return resolved ?? undefined;
}

export function flushPendingInput(descriptor = 0): void {
  if (!isatty(descriptor)) return;
  try {
    tcflush()?.(descriptor, TCIFLUSH);
  } catch {
    // Nothing more can be done here, and the reading is what the caller
    // asked for.
  }
}
