// A one-shot process for test/setup.test.ts (WCLI-152): wait at a start
// barrier, take the real setup lock exactly once, look for another holder
// inside it, and exit.
//   <ward-dir> <marker-dir> <barrier-dir> <index> locked|unlocked
// The barrier is a file: the probe writes `ready-<index>` into <barrier-dir>
// and spins until `go` appears, so a batch of fresh processes contends in the
// same instant instead of staggered by Bun start-up skew.
// Inside the lock a marker file is created with O_EXCL, held for a moment and
// removed. An O_EXCL that finds the marker already there is another holder
// inside the lock, counted as an overlap. `unlocked` skips the lock and is
// the control: it proves this detector sees overlapping holders, so a zero
// from `locked` means the lock excluded them and not that nothing could be seen.
// Odd-numbered probes exit while still holding the lock, without releasing
// it, so every round leaves dead recorded holders behind: the shape a
// pid-recording lock file reaps, and the kernel lock must not.
// Prints {"acquired":n,"denied":n,"overlaps":n}.
import {
  constants as fileConstants,
  closeSync,
  existsSync,
  openSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { acquireSetupSession } from "../../src/adapters/setup-session.ts";
import { WardError } from "../../src/contract/errors.ts";

const [wardDirectory, markerDirectory, barrierDirectory, indexText, mode] =
  process.argv.slice(2);
if (
  wardDirectory === undefined ||
  markerDirectory === undefined ||
  barrierDirectory === undefined ||
  indexText === undefined ||
  (mode !== "locked" && mode !== "unlocked")
)
  throw new Error(
    "usage: <ward-dir> <marker-dir> <barrier-dir> <index> locked|unlocked",
  );
const index = Number(indexText);
const marker = join(markerDirectory, "holder");
const cell = new Int32Array(new SharedArrayBuffer(4));
const pause = (ms: number) => Atomics.wait(cell, 0, 0, ms);

writeFileSync(join(barrierDirectory, `ready-${index}`), "");
const go = join(barrierDirectory, "go");
while (!existsSync(go)) {
  // Spin: a sleep here would reintroduce the skew the barrier removes.
}

let acquired = 0;
let denied = 0;
let overlaps = 0;

function insideTheLock(): void {
  acquired++;
  let fd: number | undefined;
  try {
    fd = openSync(
      marker,
      fileConstants.O_CREAT | fileConstants.O_EXCL | fileConstants.O_WRONLY,
      0o600,
    );
  } catch {
    overlaps++;
    return;
  }
  pause(3);
  closeSync(fd);
  rmSync(marker);
}

function report(): void {
  process.stdout.write(`${JSON.stringify({ acquired, denied, overlaps })}\n`);
}

if (mode === "unlocked") {
  insideTheLock();
  report();
} else {
  let session: ReturnType<typeof acquireSetupSession> | undefined;
  try {
    session = acquireSetupSession(wardDirectory);
  } catch (error) {
    if (!(error instanceof WardError && error.code === "setup_in_progress"))
      throw error;
    denied++;
  }
  if (session !== undefined) {
    insideTheLock();
    if (index % 2 === 0) session.release();
  }
  report();
  // Exit explicitly: an odd probe leaves the descriptor open on purpose.
  process.exit(0);
}
