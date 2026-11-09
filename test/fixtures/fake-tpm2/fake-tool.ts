// One fake tpm2_* executable (WCLI-21 slice 2). A generated wrapper runs it as
//   <tool> <record-dir> <mode> [args...]
// It records what it actually received - argv, the whole environment, and the
// bytes on stdin - so a test can assert what the adapter passed, and nothing
// reaches a real TPM. Like the real tools it writes a file for each of that
// tool's OUTPUT flags (the real ones leave them wider than 0600: WCLI-153, so
// these are 0660 on purpose) and, like them, exits 3 when a file named by an
// INPUT flag does not exist. The same letter is an output for one tool and an
// input for another (-c), so both are tables. Modes: `record` exits 0; `fail` exits 1; `hang` never
// exits; `touch-wide` also writes a 0660 file named by its first argument;
// `flood` writes far more output than any tool should; `no-read` exits at once
// without reading stdin; `flood-stderr` writes far more than the cap to stderr
// and exits 0; `flood-stderr-fail` does that and exits 1; `race-final`
// also creates the final name (the -r path without its ".partial" suffix), as
// a second writer would between the check and the publish; `grandchild` leaves a process holding its stdout open
// (its pid in <record-dir>/grandchild.pid) and exits 0.
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [tool, recordDirectory, mode, ...args] = process.argv.slice(2);
if (tool === undefined || recordDirectory === undefined || mode === undefined)
  throw new Error("usage: <tool> <record-dir> <mode> [args...]");

if (mode === "no-read") process.exit(0);
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
const outputFlags: Record<string, readonly string[]> = {
  tpm2_createprimary: ["-c"],
  tpm2_create: ["-u", "-r"],
  tpm2_load: ["-c"],
  tpm2_startauthsession: ["-S"],
};
const inputFlags: Record<string, readonly string[]> = {
  tpm2_create: ["-C"],
  tpm2_load: ["-C", "-u", "-r"],
  tpm2_unseal: ["-c"],
  tpm2_startauthsession: ["-c"],
};
for (const [index, flag] of args.entries()) {
  const path = args[index + 1];
  if (
    path !== undefined &&
    inputFlags[tool]?.includes(flag) &&
    !existsSync(path)
  )
    process.exit(3);
}
for (const [index, flag] of args.entries()) {
  const path = args[index + 1];
  if (path !== undefined && outputFlags[tool]?.includes(flag)) {
    writeFileSync(path, `${tool} ${flag}`);
    chmodSync(path, 0o660);
    if (mode === "race-final" && flag === "-r" && path.endsWith(".partial"))
      writeFileSync(path.slice(0, -".partial".length), "planted");
  }
}
if (mode === "flood-stderr" || mode === "flood-stderr-fail")
  process.stderr.write("e".repeat(64 * 1024));
if (mode === "hang") await new Promise(() => {});
if (mode === "fail" || mode === "flood-stderr-fail") process.exit(1);
if (mode === "flood") process.stdout.write("x".repeat(64 * 1024));
if (mode === "grandchild") {
  const held = Bun.spawn(["/bin/sleep", "60"], {
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });
  writeFileSync(join(recordDirectory, "grandchild.pid"), String(held.pid));
  held.unref();
}
if (mode === "touch-wide" && args[0] !== undefined) {
  writeFileSync(args[0], "blob");
  chmodSync(args[0], 0o660);
}
