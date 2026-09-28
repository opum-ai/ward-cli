// The packaged ward executable, built once per test file through
// scripts/build.ts so entry-point tests measure what ships rather than
// `bun src/cli/ward.ts`.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildExecutable, entry } from "../../scripts/build.ts";

export const buildRoot = mkdtempSync(join(tmpdir(), "ward-packaged-"));
process.on("exit", () => rmSync(buildRoot, { recursive: true, force: true }));

export const packagedWard = buildExecutable({
  entry,
  outfile: join(buildRoot, "ward"),
});
