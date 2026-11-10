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
// `flood` writes far more output than any tool should; `flood-hang` does that and
// never exits; `no-read` exits at once
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
// (`session-off`: no encrypt; `session-no-decrypt`: measured shape, decrypt
// missing; `session-unknown-token`: measured shape plus a token outside the
// vocabulary; `session-zero`: "encrypt: 0"; `wide-on-enable` and
// `wide-on-read` widen the session file to 0660 at that call). The default
// printout is the real tpm2-tools 5.6 output, measured on the jetson on
// 2026-11-09, and so are the off shapes (probe 4: --disable-encrypt prints
// `continuesession|decrypt`, then --disable-decrypt prints `continuesession`,
// each after the Session-Handle line); `session-unknown-token` and
// `session-zero` are inventions that exercise the unparsed branch.
import {
  appendFileSync,
  chmodSync,
  existsSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";

const [tool, recordDirectory, fullMode, ...args] = process.argv.slice(2);
if (
  tool === undefined ||
  recordDirectory === undefined ||
  fullMode === undefined
)
  throw new Error("usage: <tool> <record-dir> <mode> [args...]");
// A mode may carry a `--version` behaviour after a "+": `session-zero+version-long`.
const [mode = "record", versionMode = "record"] = fullMode.split("+");

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
// `--version` prints the measured one-line shape (tpm2-tools 5.6, jetson,
// 2026-11-09) and does nothing else. The version modes (after a "+") break it:
// `version-fail` exits 1, `version-long` is over 32 characters,
// `version-quote`, `version-ansi` and `version-newline` carry the character
// they name inside the quoted version.
if (args[0] === "--version") {
  if (versionMode === "version-fail") process.exit(1);
  const version =
    versionMode === "version-long"
      ? "1".repeat(40)
      : versionMode === "version-quote"
        ? '5.6"x'
        : versionMode === "version-ansi"
          ? "5.6\u001b[31m"
          : versionMode === "version-newline"
            ? "5.6\nx"
            : "5.6";
  process.stdout.write(
    `tool="${tool}" version="${version}" tctis="libtss2-tctildr" tcti-default=tcti-device\n`,
  );
  process.exit(0);
}
// `fail-no-output`: exits 1 before writing any output file.
if (mode === "fail-no-output") process.exit(1);
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
if (mode === "lock-directory") {
  // Refuse to chmod anything outside this case's own directory.
  const inside = relative(
    realpathSync(dirname(recordDirectory)),
    realpathSync(process.cwd()),
  );
  if (inside === "" || inside.startsWith("..") || inside.startsWith("/"))
    throw new Error("lock-directory: cwd is outside the test case directory");
  chmodSync(process.cwd(), 0o500);
}
if (mode === "flood-stderr" || mode === "flood-stderr-fail")
  process.stderr.write("e".repeat(64 * 1024));
if (mode === "hang") await new Promise(() => {});
if (mode === "fail" || mode === "flood-stderr-fail") process.exit(1);
if (mode === "flood" || mode === "flood-hang")
  process.stdout.write("x".repeat(64 * 1024));
if (mode === "flood-hang") await new Promise(() => {});
// `wide-on-enable`: the enable call rewrites the session file 0660.
// `wide-on-read`: the bare read widens it to 0660 first.
if (tool === "tpm2_sessionconfig" && sessionPath !== undefined) {
  const enabling = args.some((arg) => /^--(en|dis)able-/.test(arg));
  if (
    (mode === "wide-on-enable" && enabling) ||
    (mode === "wide-on-read" && !enabling)
  )
    chmodSync(sessionPath, 0o660);
}
if (tool === "tpm2_unseal")
  process.stdout.write(Buffer.alloc(mode === "short-unseal" ? 31 : 32, 0x5a));
if (
  tool === "tpm2_sessionconfig" &&
  !args.some((arg) => /^--(en|dis)able-/.test(arg))
)
  process.stdout.write(
    mode === "session-off"
      ? "Session-Handle: 0x02000000\nSession-Attributes: continuesession\n"
      : mode === "session-no-decrypt"
        ? "Session-Handle: 0x02000000\nSession-Attributes: continuesession|encrypt\n"
        : mode === "session-unknown-token"
          ? "Session-Handle: 0x02000000\nSession-Attributes: continuesession|decrypt|encrypt|newattr\n"
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
