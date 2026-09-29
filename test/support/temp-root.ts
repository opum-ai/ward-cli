// The one way a test file makes a temporary root under TMPDIR (WCLI-46).
//
// Cleanup used to depend on the process reaching its exit handlers, so a run
// that was killed - a CI cancellation, a crash fixture, a timeout - left its
// whole root behind. The packaged build root holds two compiled binaries,
// about 122 MB, and the residue added up: 183 roots and 21 GiB on one
// developer machine, and a CI runner's boot disk filled in about a day.
//
// So the removal is registered in an afterAll here, which runs at the end of
// the importing file's own tests rather than at process exit. Measured before
// writing it: a support module can register the hook from module scope and it
// does run for the importing file - three consecutive runs of a probe file
// left nothing behind.
//
// What this does NOT do is sweep residue a previous killed run left behind.
// That was the other half of WCLI-46's second criterion and it is deliberately
// absent: it means recursively deleting age-filtered directories from a shared
// TMPDIR, which is a destructive-cleanup capability that belongs to the
// repository's own user rather than to a test helper, and the permission
// layer refused it the first time it was exercised. The criterion is recorded
// as unmet on the task, with the measurement that shows what remains.
import { afterAll } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function createTempRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  afterAll(() => rmSync(root, { recursive: true, force: true }));
  return root;
}
