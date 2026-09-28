// Builds the ward executable, the only artifact that may be installed as
// `ward` (WCLI-16). Launched through `bun`, Ward would read the working
// directory's bunfig.toml and .env before its own code runs: a planted
// preload executes with argv in reach, and .env lands in process.env. Ward
// runs inside repositories an agent can edit, so every runtime autoload is
// switched off here, including the two Bun already defaults off, so that a
// change of default cannot silently turn one back on.
//
// Not closed by these flags, measured on bun 1.3.14: BUN_OPTIONS in the
// inherited environment still preloads code, and BUN_BE_BUN=1 turns the
// executable into the full bun CLI (WCLI-19).
import { join } from "node:path";

const root = join(import.meta.dir, "..");

export const entry = join(root, "src", "cli", "ward.ts");
export const outfile = join(root, "dist", "ward");

export const hardeningFlags = [
  "--no-compile-autoload-dotenv",
  "--no-compile-autoload-bunfig",
  "--no-compile-autoload-tsconfig",
  "--no-compile-autoload-package-json",
] as const;

// The argv buildExecutable runs, exposed so a test can assert what is
// actually passed to `bun build` rather than what the list above declares.
export function buildCommand(options: {
  entry: string;
  outfile: string;
}): string[] {
  return [
    process.execPath,
    "build",
    "--compile",
    ...hardeningFlags,
    options.entry,
    "--outfile",
    options.outfile,
  ];
}

// Tests build their executables and a probe entry through this same
// function, so the flags they measure are the flags that ship.
export function buildExecutable(options: {
  entry: string;
  outfile: string;
}): string {
  const run = Bun.spawnSync(buildCommand(options), { cwd: root });
  if (run.exitCode !== 0)
    throw new Error(
      `bun build exited ${run.exitCode}\n${run.stderr.toString()}`,
    );
  return options.outfile;
}

if (import.meta.main) buildExecutable({ entry, outfile });
