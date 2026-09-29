// The packaged ward executable, built through scripts/build.ts so
// entry-point tests measure what ships rather than `bun src/cli/ward.ts`.
//
// It is built into a root the CALLING FILE owns, rather than one this module
// creates, and that is measured rather than assumed: `bun test` evaluates this
// module once for the whole process, so a root created here belongs to
// whichever file imported it first, and the second file's copy disappears
// mid-run when the first file's teardown runs - measured, one evaluation for
// two importing files and then ENOENT on the binary from the other. A root per
// file also keeps the removal in the file that owns it (WCLI-46). The build is
// about 0.3 s, so a second one costs nothing worth trading that for.
import { join } from "node:path";
import { buildExecutable, entry } from "../../scripts/build.ts";

export function buildPackagedWard(root: string): string {
  return buildExecutable({ entry, outfile: join(root, "ward") });
}
