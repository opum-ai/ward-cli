// The logging shim of the Linux T26 harness (WCLI-21 slice 4a-2b, DEC-262 a30):
// the interposers that sit in front of the trusted tpm2-tools binaries, the row
// that judges the environment they saw, and the before/after listing of the
// places a run could leave a key (the run directory, $TMPDIR, /tmp, /dev/shm).
// The run therefore qualifies "Ward plus a logging shim in front of the trusted
// binaries", and the report says so. Nothing here touches a TPM.
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  type BigIntStats,
  type Stats,
  statSync,
  writeFileSync,
} from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import type { Tpm2Presence } from "../src/adapters/tpm2-tools.ts";
import { ruledTcti, type ToolCall } from "./qualify-linux-rows.ts";
import { type Check, holdsAny, sha256 } from "./qualify-linux-support.ts";

// The one tool whose stdout the shim records: its printout is not a secret.
export const recordedStdoutTool = "tpm2_sessionconfig";

// --- the interposer -----------------------------------------------------------

// A shell script for one tool. A shell adds names of its own to what it runs
// (PWD, OLDPWD, SHLVL, and _ , which bash sets for every command), with values
// that are not the harness's to predict and that differ between shells, so the
// script unsets them and runs both its own listing and the real tool through
// /usr/bin/env -u for each of them: the tool sees exactly the environment the
// adapter built. It records the call (the name, the TCTI the environment
// carried, the NAME of every environment variable with the sha256 of its value,
// each argument), then runs the real tool by the absolute path detection
// resolved. Stdin is untouched and is never logged. Stdout is never logged
// either, except for the one printout tool: that one is written to a private
// file, copied to the caller byte for byte, and logged with its exit code. An
// argument holding a newline would forge a log line, so it stops the call before
// anything runs or is logged.
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
    "umask 077",
    "unset PWD OLDPWD SHLVL _",
    'for a in "$@"; do case $a in *\'',
    "'*) exit 97;; esac; done",
    "{",
    `  printf 'CALL %s\\n' '${tool}'`,
    "  printf 'TCTI %s\\n' \"$TPM2TOOLS_TCTI\"",
    "  /usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD /usr/bin/env | while IFS= read -r line; do",
    "    case $line in *=*) name=${line%%=*}; value=${line#*=};; *) name=$line; value=;; esac",
    "    digest=$(printf '%s' \"$value\" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)",
    '    printf \'ENV %s %s\\n\' "$name" "$digest"',
    "  done",
    '  for a in "$@"; do printf \'ARG %s\\n\' "$a"; done',
    "  printf 'END\\n'",
    `} >> '${logPath}'`,
  ];
  const run = recordStdout
    ? [
        `capture='${logPath}.out.'$$`,
        `/usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD '${realTool}' "$@" > "$capture"; rc=$?`,
        'cat "$capture"',
        `{ printf 'OUT-BEGIN\\n'; cat "$capture"; printf '\\nOUT-END\\nRC %s\\nDONE\\n' "$rc"; } >> '${logPath}'`,
        'rm -f "$capture"',
        'exit "$rc"',
      ]
    : [`exec /usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD '${realTool}' "$@"`];
  return `${[...head, ...run].join("\n")}\n`;
}

// Writes one interposer per tool in `presence` into `directory` and returns a
// presence whose tools are the interposers. The directory is made exclusively at
// 0700 (a stale one is never adopted) and each script is 0700, the one place a
// file in the run is executable. The log is created here at 0600 so the shell
// appends to a private file. Each real path is the absolute one detection
// resolved: a relative path would be resolved against the run's own PATH.
export function installInterposers(
  directory: string,
  presence: Tpm2Presence,
  logPath: string,
): Tpm2Presence {
  const tools: Record<string, string> = {};
  for (const [tool, realTool] of Object.entries(presence.tools)) {
    if (realTool === undefined || !isAbsolute(realTool))
      throw new Error(`the real path of ${tool} is not absolute`);
    // Validate before anything is created.
    interposerScript(tool, realTool, logPath, tool === recordedStdoutTool);
  }
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  writeFileSync(logPath, "", { flag: "wx", mode: 0o600 });
  for (const [tool, realTool] of Object.entries(presence.tools)) {
    const path = join(directory, tool);
    writeFileSync(
      path,
      interposerScript(
        tool,
        realTool as string,
        logPath,
        tool === recordedStdoutTool,
      ),
      { flag: "wx", mode: 0o700 },
    );
    chmodSync(path, 0o700);
    tools[tool] = path;
  }
  return { device: presence.device, tools } as Tpm2Presence;
}

// --- the environment ----------------------------------------------------------

// The environment the adapter builds for a tool (toolEnvironment in
// src/adapters/tpm2-tools.ts): the tool's own directory, then /usr/bin and /bin;
// the ruled device; a C locale. Here the tool is the interposer, so its
// directory is the interposer directory.
export function expectedEnvironment(
  interposerDirectory: string,
): Record<string, string> {
  return {
    PATH: [...new Set([interposerDirectory, "/usr/bin", "/bin"])].join(
      delimiter,
    ),
    TPM2TOOLS_TCTI: ruledTcti,
    LANG: "C",
    LC_ALL: "C",
  };
}

const digestOf = (value: string): string => sha256(Buffer.from(value));

// (a30)(i) says no argv element and no environment value contains the synthetic
// key. The environment half is proved here by equality, not by search: every
// variable the interposer logged must be one of the adapter's four, with a value
// whose sha256 is the sha256 of the value the harness expects. And the equality
// proves nothing about the key unless the expected values hold none of its forms,
// so each expected value is searched for them too. A name outside the four, a
// missing name, a mismatched digest, an expected value holding a form of the key,
// a call with no ENV lines, or no call at all, fails the row. No value is written
// anywhere.
export function envRow(
  calls: readonly ToolCall[],
  interposerDirectory: string,
  keyForms: readonly Buffer[],
): Check {
  const expected = expectedEnvironment(interposerDirectory);
  const names = new Set<string>();
  let ok = calls.length > 0;
  // An expected value is a string the harness wrote; its bytes, each character
  // taken as one byte, are what a raw form would have to match.
  const expectedHoldsKey = Object.values(expected).some((value) =>
    holdsAny(Buffer.from(value, "latin1"), keyForms),
  );
  if (expectedHoldsKey) ok = false;
  for (const call of calls) {
    const env = call.env;
    if (env === undefined || env.length === 0) {
      ok = false;
      continue;
    }
    for (const { name } of env) names.add(name);
    for (const [name, value] of Object.entries(expected))
      if (env.find((e) => e.name === name)?.digest !== digestOf(value))
        ok = false;
    for (const { name } of env) if (!Object.hasOwn(expected, name)) ok = false;
  }
  return {
    name: "key-not-in-tool-environment",
    ok,
    detail: {
      calls: calls.length,
      names: [...names].sort(),
      asserts: "no env value contains the synthetic key",
      proof:
        "every logged variable is one of the adapter's four and its value's sha256 equals the sha256 of the value the harness expects, and none of the expected values holds a raw, hex or base64 form of the key",
    },
  };
}

// (a30)(i)'s argv half: no argument of any logged call contains the key in raw,
// hex or base64 form. A call with no argument list to read, or no call at all,
// proves nothing and fails.
export function argvRow(
  calls: readonly ToolCall[],
  keyForms: readonly Buffer[],
): Check {
  const holding = calls.filter((call) =>
    call.args.some((arg) => holdsAny(Buffer.from(arg, "latin1"), keyForms)),
  ).length;
  return {
    name: "key-not-in-tool-argv",
    ok: calls.length > 0 && holding === 0,
    detail: {
      calls: calls.length,
      holding,
      asserts: "no argv element contains the synthetic key",
    },
  };
}

// --- the window ---------------------------------------------------------------

// A scan reads a file once; one larger than this is not scanned and fails the
// row instead.
export const maxWindowFileBytes = 64 * 1024 * 1024;

export interface WindowListing {
  // Each root as given, and whether it exists (/dev/shm may not).
  readonly present: Readonly<Record<string, boolean>>;
  // Each regular file by absolute path, with what changes when it is replaced or
  // rewritten: size, mtime, ctime and inode, exact.
  readonly files: Readonly<Record<string, string>>;
  // Directories this run's user owns and could not read: unknown contents, so
  // the row fails. A directory another user owns and this user cannot read could
  // not have been written by this run, and is only counted.
  readonly foreignUnreadable: number;
  readonly ownUnreadable: readonly string[];
}

const unreadable = (error: unknown): boolean =>
  ["EACCES", "EPERM"].includes((error as NodeJS.ErrnoException).code ?? "");

// The regular files under each root, by lstat, without opening any. Symlinks
// are neither followed nor listed. A root that does not exist is recorded as
// absent; one that exists but cannot be resolved is an error.
export function listWindowRoots(
  roots: readonly string[],
  uid: number,
): WindowListing {
  const present: Record<string, boolean> = {};
  const files: Record<string, string> = {};
  const ownUnreadable: string[] = [];
  let foreignUnreadable = 0;
  const walk = (path: string): void => {
    let stats: Stats;
    let big: BigIntStats;
    try {
      big = lstatSync(path, { bigint: true });
      stats = lstatSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (stats.isDirectory()) {
      let entries: string[];
      try {
        entries = readdirSync(path);
      } catch (error) {
        if (!unreadable(error)) throw error;
        if (stats.uid === uid) ownUnreadable.push(path);
        else foreignUnreadable++;
        return;
      }
      for (const entry of entries.sort()) walk(join(path, entry));
    } else if (stats.isFile())
      files[path] = [
        big.size,
        big.mtimeNs,
        big.ctimeNs,
        big.ino,
        stats.uid,
      ].join(" ");
  };
  for (const root of roots) {
    let real: string;
    try {
      real = realpathSync(root);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        present[root] = false;
        continue;
      }
      throw error;
    }
    present[root] = true;
    walk(real);
  }
  return { present, files, foreignUnreadable, ownUnreadable };
}

// The files that are new, or whose size, times or inode moved, between the two
// listings.
export function changedFiles(
  before: WindowListing,
  after: WindowListing,
): string[] {
  return Object.keys(after.files)
    .filter((path) => before.files[path] !== after.files[path])
    .sort();
}

export interface WindowScan {
  readonly filesRead: number;
  readonly matches: readonly string[];
  // Another user's file this user cannot read, or one that was gone by the time
  // it was read: neither can be this run's key.
  readonly foreign: number;
  readonly vanished: number;
  // This user's own file that could not be read, or that is too large to scan.
  readonly unreadable: readonly string[];
}

// Reads each changed file once and looks for the needles. `needlesFor` gives the
// forms to look for in that file, so a file that holds the nonce by design
// (state.json) is searched for the key forms only.
export function scanWindow(
  paths: readonly string[],
  needlesFor: (path: string) => readonly Buffer[],
  uid: number,
): WindowScan {
  const matches: string[] = [];
  const bad: string[] = [];
  let filesRead = 0;
  let foreign = 0;
  let vanished = 0;
  for (const path of paths) {
    try {
      const stats = statSync(path);
      if (stats.size > maxWindowFileBytes) {
        bad.push(path);
        continue;
      }
      const content = readFileSync(path);
      filesRead++;
      if (holdsAny(content, needlesFor(path))) matches.push(path);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") vanished++;
      else if (unreadable(error)) {
        let owner: number | undefined;
        try {
          owner = lstatSync(path).uid;
        } catch {
          owner = undefined;
        }
        if (owner !== undefined && owner !== uid) foreign++;
        else bad.push(path);
      } else throw error;
    }
  }
  return { filesRead, matches, foreign, vanished, unreadable: bad };
}

// The row for AC1's temp-file clause (DEC-262 a30 (ii)): every file new or
// changed between the two listings was read, and none holds the key. It fails
// when a root the run must have (the run directory) is missing from either
// listing, when a directory of this user's own could not be listed, when a file
// of this user's own could not be read or was too large, when a file was
// neither read nor accounted for, and when nothing at all was read (the run
// directory alone gains files, so a window that read none looked at nothing).
export function windowRow(
  before: WindowListing,
  after: WindowListing,
  scan: WindowScan,
  requiredRoots: readonly string[],
): Check {
  const changed = changedFiles(before, after).length;
  const rootsOk = requiredRoots.every(
    (root) => before.present[root] === true && after.present[root] === true,
  );
  const sameRoots =
    JSON.stringify(Object.entries(before.present).sort()) ===
    JSON.stringify(Object.entries(after.present).sort());
  const ok =
    rootsOk &&
    sameRoots &&
    before.ownUnreadable.length === 0 &&
    after.ownUnreadable.length === 0 &&
    scan.unreadable.length === 0 &&
    scan.filesRead > 0 &&
    scan.filesRead + scan.foreign + scan.vanished === changed &&
    scan.matches.length === 0;
  return {
    name: "key-not-in-temp-files-of-the-window",
    ok,
    detail: {
      changed,
      read: scan.filesRead,
      foreign: scan.foreign,
      vanished: scan.vanished,
      foreignUnreadableDirectories: after.foreignUnreadable,
      ownUnreadable: [...after.ownUnreadable, ...scan.unreadable],
      matches: scan.matches,
    },
  };
}

export const interposerDirectoryName = "interposers";
export const toolLogName = "tools.log";
