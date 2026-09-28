// The process entry point. Import order is load-bearing: guard.ts must
// evaluate before anything else. This file is not a hardened launcher; run
// through `bun`, it inherits the working directory's bunfig.toml and .env
// (WCLI-16).
import "./guard.ts";
import { runWard } from "./main.ts";

const result = runWard(process.argv.slice(2));
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
process.exitCode = result.exitCode;
