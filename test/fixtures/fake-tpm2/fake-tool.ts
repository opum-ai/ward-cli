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
// (its pid in <record-dir>/grandchild.pid) and exits 0; `lock-directory` makes
// its working directory read-only (0500) once its outputs exist, so a later
// link(2) into it fails with EACCES for any non-root user.
// Every call is also appended to <record-dir>/calls.jsonl (tool, argv, and the
// mode of the session file the call names, as it was when the call began), so
// a test can assert the ORDER of calls and what a tool saw. tpm2_unseal writes
// the 32-byte synthetic key 0x5a to stdout (`short-unseal`: 31 bytes);
// tpm2_sessionconfig with no --enable/--disable prints the attributes
// (`session-off`: no encrypt; `session-zero`: "encrypt: 0"). The default
// printout is the real tpm2-tools 5.6 output, measured on the jetson on
// 2026-11-09; the two off modes are inventions that exercise the fail-closed
// parse.
import {
  appendFileSync,
  chmodSync,
  existsSync,
  statSync,
  writeFileSync,
} from "node:fs";
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
const sessionPath = (() => {
  const given = args.find((arg) => arg.startsWith("session:"));
  if (given !== undefined) return given.slice("session:".length);
  const last = args.at(-1);
  return (tool === "tpm2_sessionconfig" || tool === "tpm2_flushcontext") &&
    last !== undefined &&
    !last.startsWith("-")
    ? last
    : undefined;
})();
appendFileSync(
  join(recordDirectory, "calls.jsonl"),
  `${JSON.stringify({
    tool,
    args,
    stdinHex: stdin.toString("hex"),
    sessionMode:
      sessionPath !== undefined && existsSync(sessionPath)
        ? statSync(sessionPath).mode & 0o777
        : null,
  })}\n`,
);
// A session file named for sessionconfig or by "-p session:" must exist.
if (
  sessionPath !== undefined &&
  tool !== "tpm2_flushcontext" &&
  !existsSync(sessionPath)
)
  process.exit(3);
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
if (mode === "lock-directory") chmodSync(process.cwd(), 0o500);
if (mode === "flood-stderr" || mode === "flood-stderr-fail")
  process.stderr.write("e".repeat(64 * 1024));
if (mode === "hang") await new Promise(() => {});
if (mode === "fail" || mode === "flood-stderr-fail") process.exit(1);
if (mode === "flood") process.stdout.write("x".repeat(64 * 1024));
if (tool === "tpm2_unseal")
  process.stdout.write(Buffer.alloc(mode === "short-unseal" ? 31 : 32, 0x5a));
if (
  tool === "tpm2_sessionconfig" &&
  !args.some((arg) => /^--(en|dis)able-/.test(arg))
)
  process.stdout.write(
    mode === "session-off"
      ? "Session-Attributes: continuesession\n"
      : mode === "session-zero"
        ? "decrypt: 1\nencrypt: 0\n"
        : "Session-Handle: 0x02000000\nSession-Attributes: continuesession|decrypt|encrypt\n",
  );
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
