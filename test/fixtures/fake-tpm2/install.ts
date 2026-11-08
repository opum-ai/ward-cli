// Generates a directory of fake tpm2_* executables for one test. Generated at
// run time, with this runtime's absolute path baked in, because the adapter
// gives tools a minimal environment: a fake cannot find `bun` on PATH or learn
// its record directory from the environment, and a committed file mode is not
// something a checkout is guaranteed to keep.
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { requiredTools } from "../../../src/adapters/tpm2-tools.ts";

const FAKE = join(import.meta.dir, "fake-tool.ts");

export function installFakeTools(
  directory: string,
  recordDirectory: string,
  modes: Readonly<Record<string, string>> = {},
): void {
  mkdirSync(directory, { recursive: true });
  mkdirSync(recordDirectory, { recursive: true });
  for (const tool of requiredTools) {
    const path = join(directory, tool);
    writeFileSync(
      path,
      `#!/bin/sh\nexec '${process.execPath}' '${FAKE}' '${tool}' '${recordDirectory}' '${modes[tool] ?? "record"}' "$@"\n`,
    );
    chmodSync(path, 0o755);
  }
}
