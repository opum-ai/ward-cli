// A separate process for test/setup.test.ts (WCLI-152): take the real setup
// lock in a loop and look for another holder inside it.
//   <ward-dir> <marker-dir> <rounds> locked|unlocked
// Inside the lock a marker file is created with O_EXCL, held for a moment and
// removed. An O_EXCL that finds the marker already there is another holder
// inside the lock, counted as an overlap. `unlocked` skips the lock and is
// the control: it proves this detector sees overlapping holders, so a zero
// from `locked` means the lock excluded them and not that nothing could be seen.
// Prints {"acquired":n,"denied":n,"overlaps":n}.
import {
  constants as fileConstants,
  closeSync,
  openSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { acquireSetupSession } from "../../src/adapters/setup-session.ts";
import { WardError } from "../../src/contract/errors.ts";

const [wardDirectory, markerDirectory, roundsText, mode] =
  process.argv.slice(2);
if (
  wardDirectory === undefined ||
  markerDirectory === undefined ||
  roundsText === undefined ||
  (mode !== "locked" && mode !== "unlocked")
)
  throw new Error("usage: <ward-dir> <marker-dir> <rounds> locked|unlocked");
const rounds = Number(roundsText);
const marker = join(markerDirectory, "holder");
const cell = new Int32Array(new SharedArrayBuffer(4));
const pause = (ms: number) => Atomics.wait(cell, 0, 0, ms);

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
  pause(2);
  closeSync(fd);
  rmSync(marker);
}

for (let round = 0; round < rounds; round++) {
  if (mode === "unlocked") {
    insideTheLock();
    continue;
  }
  let session: ReturnType<typeof acquireSetupSession>;
  try {
    session = acquireSetupSession(wardDirectory);
  } catch (error) {
    if (error instanceof WardError && error.code === "setup_in_progress") {
      denied++;
      pause(1);
      continue;
    }
    throw error;
  }
  try {
    insideTheLock();
  } finally {
    session.release();
  }
}
process.stdout.write(`${JSON.stringify({ acquired, denied, overlaps })}\n`);
