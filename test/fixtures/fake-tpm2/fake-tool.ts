// One fake tpm2_* executable (WCLI-21 slice 2). A generated wrapper runs it as
//   <tool> <record-dir> <mode> [args...]
// It records what it actually received - argv, the whole environment, and the
// bytes on stdin - so a test can assert what the adapter passed, and nothing
// reaches a real TPM. Modes: `record` exits 0; `fail` exits 1; `hang` never
// exits; `touch-wide` also writes a 0660 file named by its first argument.
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [tool, recordDirectory, mode, ...args] = process.argv.slice(2);
if (tool === undefined || recordDirectory === undefined || mode === undefined)
  throw new Error("usage: <tool> <record-dir> <mode> [args...]");

const stdin = Buffer.from(await new Response(Bun.stdin.stream()).arrayBuffer());
writeFileSync(
  join(recordDirectory, `${tool}.json`),
  JSON.stringify({
    tool,
    args,
    env: process.env,
    stdinHex: stdin.toString("hex"),
  }),
);
if (mode === "hang") await new Promise(() => {});
if (mode === "fail") process.exit(1);
if (mode === "touch-wide" && args[0] !== undefined) {
  writeFileSync(args[0], "blob");
  chmodSync(args[0], 0o660);
}
