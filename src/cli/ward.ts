// The process entry point. Import order is load-bearing: guard.ts must
// evaluate before anything else. Ship it only as the executable
// scripts/build.ts compiles: run through `bun`, it inherits the working
// directory's bunfig.toml and .env (WCLI-16).
import "./guard.ts";
import { runWard } from "./main.ts";

const result = await runWard(process.argv.slice(2));
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
// A pending native credential-store call can keep the process alive after
// its bound expired (WCLI-5 review), so those failures exit explicitly.
if (result.exitExplicitly) process.exit(result.exitCode);
process.exitCode = result.exitCode;
