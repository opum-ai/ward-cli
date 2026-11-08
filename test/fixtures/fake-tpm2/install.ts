// Generates a directory of fake tpm2_* executables for one test. Generated at
// run time, with this runtime's absolute path baked in, because the adapter
// gives tools a minimal environment: a fake cannot find `bun` on PATH or learn
// its record directory from the environment, and a committed file mode is not
// something a checkout is guaranteed to keep.
//
// `multicall` mirrors tpm2-tools 5.x: one `tpm2` binary that dispatches on
// argv[0], with every tpm2_* a symlink to it.
import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { requiredTools } from "../../../src/adapters/tpm2-tools.ts";

const FAKE = join(import.meta.dir, "fake-tool.ts");

export function installFakeTools(
  directory: string,
  recordDirectory: string,
  modes: Readonly<Record<string, string>> = {},
  options: { multicall?: boolean } = {},
): void {
  mkdirSync(directory, { recursive: true });
  mkdirSync(recordDirectory, { recursive: true });
  const run = (tool: string, mode: string) =>
    `exec '${process.execPath}' '${FAKE}' ${tool} '${recordDirectory}' '${mode}' "$@"\n`;
  if (options.multicall === true) {
    const multicall = join(directory, "tpm2");
    writeFileSync(multicall, `#!/bin/sh\n${run('"${0##*/}"', "record")}`);
    chmodSync(multicall, 0o755);
    for (const tool of requiredTools)
      symlinkSync(multicall, join(directory, tool));
    return;
  }
  for (const tool of requiredTools) {
    const path = join(directory, tool);
    writeFileSync(
      path,
      `#!/bin/sh\n${run(`'${tool}'`, modes[tool] ?? "record")}`,
    );
    chmodSync(path, 0o755);
  }
}
