// The rows of the Linux T26 harness (WCLI-21 slice 4a-2a): each one is a pure
// function from what the run observed to a named Check, so `bun test` measures
// how a row is decided and the hardware run only has to supply honest inputs.
// Nothing here touches a TPM; the helpers that touch the filesystem (the run
// directory, the ~/.ward snapshot) touch only what they are handed.
import { timingSafeEqual } from "node:crypto";
import { lstatSync, mkdirSync, readdirSync, realpathSync } from "node:fs";
import { userInfo } from "node:os";
import { join, relative } from "node:path";
import { classifySessionPrintoutForTest } from "../src/adapters/tpm2-tools.ts";
import {
  assertRunDirectory,
  bootIdChanged,
  type Check,
  type HandleSnapshot,
  modeProblems,
  runDirectoryName,
  sha256,
  deriveKey,
  diffHandles,
  type ScanResult,
} from "./qualify-linux-support.ts";

// The ruled TCTI, and the one device it names (DEC-262 a29).
export const ruledTcti = "device:/dev/tpmrm0";

// The home directory comes from the passwd entry, never from $HOME: Bun's
// homedir() honours $HOME, and a harness whose home could be redirected could be
// pointed at someone else's run directory or at the real store.
export function passwdHome(): string {
  return userInfo().homedir;
}

// The one path a run uses, computed from the home, never taken from an argument.
export function ruledRunDirectory(home: string): string {
  return join(realpathSync(home), runDirectoryName);
}

// --- the run directory --------------------------------------------------------

// Creates the run directory exclusively: a non-recursive mkdir at 0700 that
// refuses EEXIST, so a stale directory from an earlier run is never adopted (and
// then deleted by the clean phase). The guard runs first and its result is
// re-measured after the create.
export function createRunDirectory(
  directory: string,
  home: string,
  volatile?: readonly string[],
): void {
  assertRunDirectory(directory, home, volatile);
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST")
      throw new Error(
        "the run directory already exists: clean it first, it is not adopted",
      );
    throw error;
  }
  const problems = modeProblems(directory);
  if (problems.length > 0)
    throw new Error(`the run directory is not private: ${problems.join(", ")}`);
}

// Removes the run directory by its literal path. The guard runs again here,
// immediately before the delete, because this follows a reboot and the
// directory may have been replaced since it was created. Returns false when
// there is nothing to remove. The delete is `rm -rf --` on the path as a single
// argument, no shell and no trailing slash.
export function removeRunDirectory(
  directory: string,
  home: string,
  volatile?: readonly string[],
): boolean {
  assertRunDirectory(directory, home, volatile);
  try {
    lstatSync(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  const run = Bun.spawnSync(["/bin/rm", "-rf", "--", directory]);
  if (run.exitCode !== 0) throw new Error("the run directory was not removed");
  return true;
}

// The environment a packaged ward child gets: the run's own HOME (so the
// developer's real ~/.ward is never opened), a confined PATH, and a TMPDIR under
// the run. Nothing is inherited.
export function childEnvironment(
  runHome: string,
  runTemp: string,
): Record<string, string> {
  return {
    HOME: runHome,
    PATH: "/usr/bin:/bin",
    TMPDIR: runTemp,
    TERM: "xterm",
  };
}

// --- the real ~/.ward, measured and not read ----------------------------------

// A line per entry under `wardDirectory`: kind, mode, size, mtime and inode,
// from lstat only. No file is opened, so taking the snapshot is not itself a
// touch of the store's contents. A missing directory is "absent".
export function wardStoreSnapshot(wardDirectory: string): string {
  const lines: string[] = [];
  const walk = (path: string): void => {
    const stats = lstatSync(path);
    const kind = stats.isDirectory()
      ? "d"
      : stats.isSymbolicLink()
        ? "l"
        : stats.isFile()
          ? "f"
          : "o";
    lines.push(
      [
        relative(wardDirectory, path) || ".",
        kind,
        (stats.mode & 0o7777).toString(8),
        stats.size,
        stats.mtimeMs,
        stats.ino,
        stats.nlink,
      ].join(" "),
    );
    if (stats.isDirectory())
      for (const entry of readdirSync(path).sort()) walk(join(path, entry));
  };
  try {
    lstatSync(wardDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "absent";
    throw error;
  }
  walk(wardDirectory);
  return lines.join("\n");
}

export function realWardRow(before: string, after: string): Check {
  return {
    name: "real-ward-untouched",
    ok: before !== "" && before === after,
    detail: { before: before === "absent" ? "absent" : "present" },
  };
}

// --- the boot id --------------------------------------------------------------

// Exactly one trailing newline, never a trim: a trim would also admit a
// leading space, and a boot id is read as the kernel prints it.
export function stripOneNewline(raw: string): string {
  return raw.endsWith("\n") ? raw.slice(0, -1) : raw;
}

// The reboot proof: two reads of the current boot id, which must agree (the
// kernel's uuid file has the same shape and differs on every read, so a wrong
// file fails the stability control), and only bootIdChanged decides the row. A
// read that fails the shape check refuses, and a refusal is an ok:false row.
export function bootIdRow(
  sealed: string,
  firstRead: string,
  secondRead: string,
): Check {
  const first = stripOneNewline(firstRead);
  const second = stripOneNewline(secondRead);
  const stable = first === second;
  let changed = false;
  let reason: string | undefined;
  try {
    changed = bootIdChanged(sealed, first);
  } catch (error) {
    reason = (error as Error).message;
  }
  return {
    name: "boot-id-differs-from-seal",
    ok: stable && changed,
    detail: { stable, ...(reason === undefined ? {} : { reason }) },
  };
}

// --- the handle lists ---------------------------------------------------------

export function handleListsRow(
  before: HandleSnapshot,
  after: HandleSnapshot,
): Check {
  try {
    const moved = diffHandles(before, after);
    return {
      name: "handle-lists-unchanged",
      ok: moved.length === 0,
      detail: { moved },
    };
  } catch (error) {
    return {
      name: "handle-lists-unchanged",
      ok: false,
      detail: { refused: (error as Error).message },
    };
  }
}

// The run made no persistent handle: the persistent list is as it was and no
// tool that persists an object ran.
export function noPersistentHandlesRow(
  before: HandleSnapshot,
  after: HandleSnapshot,
  calls: readonly ToolCall[],
): Check {
  const persisted = calls.filter((call) => call.tool === "tpm2_evictcontrol");
  let unchanged = false;
  try {
    unchanged = !diffHandles(before, after).includes("handles-persistent");
  } catch {
    unchanged = false;
  }
  return {
    name: "no-persistent-handles",
    ok: unchanged && persisted.length === 0,
    detail: { unchanged, persistCalls: persisted.length },
  };
}

// --- the effective groups -----------------------------------------------------

// `id -G` and `id -Gn` as recorded: numeric ids, and as many names, none empty.
export function groupsRow(idG: string, idGn: string): Check {
  const ids = idG.trim().split(/\s+/);
  const names = idGn.trim().split(/\s+/);
  const ok =
    ids.every((id) => /^\d+$/.test(id)) &&
    names.every((name) => name !== "") &&
    ids.length === names.length;
  return {
    name: "effective-groups-recorded",
    ok,
    detail: ok ? { ids: idG.trim(), names: idGn.trim() } : { malformed: true },
  };
}

// --- the synthetic key --------------------------------------------------------

// The key the TPM returned is compared to deriveKey(nonce) byte for byte, not
// only through a digest, so the sealed bytes are tied to the synthetic key; the
// stored digest must be that key's own.
export function keyRows(
  nonce: string,
  keyDigest: string,
  unsealed: Uint8Array,
): Check[] {
  const expected = deriveKey(nonce);
  const same =
    unsealed.length === expected.length &&
    timingSafeEqual(Buffer.from(unsealed), expected);
  return [
    {
      name: "synthetic-key-only",
      ok: sha256(expected) === keyDigest,
    },
    { name: "unseal-matches-sealed", ok: same },
  ];
}

// --- the tool log -------------------------------------------------------------

export interface ToolCall {
  readonly tool: string;
  readonly tcti: string;
  readonly args: readonly string[];
  // The stdout of a tool that is allowed to be logged (tpm2_sessionconfig's
  // printout), never tpm2_unseal's or tpm2_create's.
  readonly stdout?: string;
}

// An interposer for one tool: it records the call (the name, the TCTI the
// environment carried, each argument) and then runs the real tool by absolute
// path. Stdin is untouched and no stdout is recorded, except for the one tool
// whose output is a non-secret printout. An argument holding a newline would
// forge a log line, so it stops the call.
export function interposerScript(
  tool: string,
  realTool: string,
  logPath: string,
  recordStdout: boolean,
): string {
  for (const value of [tool, realTool, logPath])
    if (/[^A-Za-z0-9_./-]/.test(value))
      throw new Error("an interposer path is letters, digits and _ . / -");
  const head = [
    "#!/bin/sh",
    'for a in "$@"; do case $a in *\'',
    "'*) exit 97;; esac; done",
    "{",
    `  printf 'CALL %s\\n' '${tool}'`,
    "  printf 'TCTI %s\\n' \"$TPM2TOOLS_TCTI\"",
    '  for a in "$@"; do printf \'ARG %s\\n\' "$a"; done',
    "  printf 'END\\n'",
    `} >> '${logPath}'`,
  ];
  const run = recordStdout
    ? [
        `out=$('${realTool}' "$@"); rc=$?`,
        "printf '%s\\n' \"$out\"",
        `{ printf 'OUT-BEGIN\\n%s\\nOUT-END\\nRC %s\\nDONE\\n' "$out" "$rc"; } >> '${logPath}'`,
        'exit "$rc"',
      ]
    : [`exec '${realTool}' "$@"`];
  return `${[...head, ...run].join("\n")}\n`;
}

// The log back into calls. A line that is not part of the format is a refusal:
// a log that cannot be read whole is not evidence.
export function parseToolLog(text: string): ToolCall[] {
  const calls: ToolCall[] = [];
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  let current:
    | { tool: string; tcti: string; args: string[]; stdout?: string }
    | undefined;
  let state: "idle" | "args" | "out" | "after-out" = "idle";
  let out: string[] = [];
  const malformed = (): never => {
    throw new Error("the tool log is malformed");
  };
  for (const line of lines) {
    if (state === "out") {
      if (line === "OUT-END") {
        (current as NonNullable<typeof current>).stdout = out.join("\n");
        state = "after-out";
      } else out.push(line);
      continue;
    }
    if (line.startsWith("CALL ")) {
      if (state === "args") malformed();
      current = { tool: line.slice(5), tcti: "", args: [] };
      calls.push(current as ToolCall & { args: string[] });
      state = "args";
    } else if (state === "args" && line.startsWith("TCTI "))
      (current as NonNullable<typeof current>).tcti = line.slice(5);
    else if (state === "args" && line.startsWith("ARG "))
      (current as NonNullable<typeof current>).args.push(line.slice(4));
    else if (state === "args" && line === "END") state = "idle";
    else if (
      state === "idle" &&
      line === "OUT-BEGIN" &&
      current !== undefined
    ) {
      out = [];
      state = "out";
    } else if (state === "after-out" && /^RC \d+$/.test(line)) continue;
    else if (state === "after-out" && line === "DONE") state = "idle";
    else malformed();
  }
  if (state !== "idle") malformed();
  return calls;
}

export function tctiRow(calls: readonly ToolCall[]): Check {
  return {
    name: "tcti-is-device-tpmrm0",
    ok: calls.length > 0 && calls.every((call) => call.tcti === ruledTcti),
    detail: { calls: calls.length },
  };
}

const argAfter = (
  args: readonly string[],
  flag: string,
): string | undefined => {
  const at = args.indexOf(flag);
  return at === -1 ? undefined : args[at + 1];
};

// For every tpm2_unseal in the log: the session it ran under (-p session:<path>)
// was started by a tpm2_startauthsession writing that path, was configured, and
// its LAST printout before the unseal, from tpm2_sessionconfig on that same
// path, reads decrypt and encrypt on. No other session is looked at. The printout
// is what the tool printed: this proves the session used for the unseal reported
// those attributes, and says nothing about the wire, which stays UNMEASURED
// (DEC-262 a29 Q1).
export function sessionPrintoutRows(calls: readonly ToolCall[]): Check[] {
  const unseals = calls
    .map((call, at) => ({ call, at }))
    .filter(({ call }) => call.tool === "tpm2_unseal");
  let printoutOk = unseals.length > 0;
  let boundOk = unseals.length > 0;
  for (const { call, at } of unseals) {
    const flag = argAfter(call.args, "-p") ?? "";
    const path = flag.startsWith("session:") ? flag.slice(8) : undefined;
    const started = calls
      .slice(0, at)
      .map((c, i) => ({ c, i }))
      .filter(
        ({ c }) =>
          c.tool === "tpm2_startauthsession" && argAfter(c.args, "-S") === path,
      )
      .at(-1);
    if (path === undefined || started === undefined) {
      printoutOk = false;
      boundOk = false;
      continue;
    }
    const printouts = calls
      .slice(started.i + 1, at)
      .filter(
        (c) =>
          c.tool === "tpm2_sessionconfig" &&
          c.args.includes(path) &&
          !c.args.some(
            (a) => a.startsWith("--enable") || a.startsWith("--disable"),
          ) &&
          c.stdout !== undefined,
      );
    const last = printouts.at(-1);
    if (last === undefined) {
      printoutOk = false;
      boundOk = false;
      continue;
    }
    printoutOk =
      printoutOk &&
      classifySessionPrintoutForTest(last.stdout as string) === "on";
  }
  return [
    { name: "session-printout-decrypt-encrypt", ok: printoutOk },
    { name: "session-printout-is-the-unseal-session", ok: boundOk },
  ];
}

// The session was salted to the primary: for every unseal, the
// tpm2_startauthsession that made its session is an HMAC session whose -c (the
// key that salts it) is the context a tpm2_createprimary in this log wrote. An
// unsalted session, or one salted to anything else, is not that.
export function saltedRow(calls: readonly ToolCall[]): Check {
  const primaries = new Set(
    calls
      .filter((call) => call.tool === "tpm2_createprimary")
      .map((call) => argAfter(call.args, "-c"))
      .filter((path): path is string => path !== undefined),
  );
  const unseals = calls
    .map((call, at) => ({ call, at }))
    .filter(({ call }) => call.tool === "tpm2_unseal");
  let ok = unseals.length > 0;
  for (const { call, at } of unseals) {
    const flag = argAfter(call.args, "-p") ?? "";
    const path = flag.startsWith("session:") ? flag.slice(8) : undefined;
    const started = calls
      .slice(0, at)
      .filter(
        (c) =>
          c.tool === "tpm2_startauthsession" && argAfter(c.args, "-S") === path,
      )
      .at(-1);
    const salt =
      started === undefined ? undefined : argAfter(started.args, "-c");
    ok =
      ok &&
      started?.args.includes("--hmac-session") === true &&
      salt !== undefined &&
      primaries.has(salt);
  }
  return { name: "session-salted-to-primary", ok };
}

// The secret scan, as rows: the key and the nonce appear in no file under the
// store, and none in the tool log (which holds every argument and the
// environment of every tool call, so a key in argv or the environment would be
// in it). A scan that read no file, or a log with no call, proves nothing and
// fails.
export function scanRows(
  store: ScanResult,
  log: ScanResult,
  calls: readonly ToolCall[],
): Check[] {
  const read = store.filesRead > 0 && log.filesRead > 0 && calls.length > 0;
  return [
    {
      name: "secret-scan-clean",
      ok: read && store.matches.length === 0,
      detail: { storeFiles: store.filesRead, logFiles: log.filesRead },
    },
    {
      name: "key-not-in-argv-environment-or-temp-file",
      ok: read && log.matches.length === 0 && store.matches.length === 0,
      detail: { calls: calls.length },
    },
  ];
}

// The run directory is private all the way down.
export function privateRow(directory: string): Check {
  const problems = modeProblems(directory);
  return {
    name: "run-directory-private",
    ok: problems.length === 0,
    detail: { problems },
  };
}
