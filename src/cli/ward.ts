// The process entry point. Import order is load-bearing: guard.ts must
// evaluate before anything else. Ship it only as the executable
// scripts/build.ts compiles: run through `bun`, it inherits the working
// directory's bunfig.toml and .env (WCLI-16).
import "./guard.ts";
import { writeSync } from "node:fs";
import { runWard } from "./main.ts";

const result = await runWard(process.argv.slice(2));
// Synchronous writes, so the explicit exit below cannot truncate the
// command's output.
if (result.stdoutBytes !== undefined) writeSync(1, result.stdoutBytes);
else writeSync(1, result.stdout);
writeSync(2, result.stderr);
// A pending native credential-store call can keep the process alive after
// its bound expired (WCLI-5 review), so those failures exit explicitly.
if (result.exitExplicitly) process.exit(result.exitCode);
process.exitCode = result.exitCode;
