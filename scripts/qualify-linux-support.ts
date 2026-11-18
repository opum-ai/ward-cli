// The pure parts of the Linux T26 harness (WCLI-21 slice 4a): everything that
// can be proved without a TPM, so `bun test` measures it and the hardware run
// only has to trust it. Nothing here touches a TPM or a credential store.
import { createHash } from "node:crypto";
import {
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  type Stats,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

// The four handle lists the run compares before and after: a run that leaves a
// transient, persistent, saved-session or loaded-session handle behind has
// leaked a slot.
export const handleLists = [
  "handles-transient",
  "handles-persistent",
  "handles-saved-session",
  "handles-loaded-session",
] as const;
export type HandleList = (typeof handleLists)[number];
// One list as the run read it: the exit code of the tpm2_getcap that produced
// it travels with its stdout, because an unread list ("") must never compare
// equal to an empty one.
export interface HandleRead {
  readonly exitCode: number;
  readonly stdout: string;
}
export type HandleSnapshot = Readonly<Record<HandleList, HandleRead>>;

export function isHandleRead(value: unknown): value is HandleRead {
  const read = value as Partial<HandleRead> | null | undefined;
  return (
    typeof read === "object" &&
    read !== null &&
    typeof read.exitCode === "number" &&
    typeof read.stdout === "string"
  );
}

// Every list that was not read cleanly (a missing value, a non-zero exit).
export function unreadHandles(snapshot: HandleSnapshot): HandleList[] {
  return handleLists.filter((list) => {
    const read: unknown = snapshot[list];
    return !isHandleRead(read) || read.exitCode !== 0;
  });
}

// The lists that moved between two snapshots. A snapshot with an unread list
// on either side is refused, not compared: DEC-262 (a29) stops the run on any
// difference, and a list nobody read cannot be shown not to differ.
export function diffHandles(
  before: HandleSnapshot,
  after: HandleSnapshot,
): HandleList[] {
  for (const [side, snapshot] of [
    ["before", before],
    ["after", after],
  ] as const) {
    const unread = unreadHandles(snapshot);
    if (unread.length > 0)
      throw new Error(
        `the ${side} handle lists were not all read: ${unread.join(", ")}`,
      );
  }
  return handleLists.filter(
    (list) => before[list].stdout !== after[list].stdout,
  );
}

// The run directory is DEC-262 (a29)'s literal path: `~/ward-t26-wcli21`,
// directly under the home directory, persistent because the reboot between the
// phases clears /tmp. Nothing else is accepted, so every guard that follows
// (the mode check, the clean phase's delete) can only ever act on that path.
export const runDirectoryName = "ward-t26-wcli21";

// Whether `child` is `parent` or lies under it. The test is on path segments:
// a sibling whose name merely begins with two dots ("..x") is inside.
export function isInside(parent: string, child: string): boolean {
  const rel = relative(resolve(parent), resolve(child));
  return (
    rel === "" ||
    (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
  );
}

// The real path of something that may not exist yet (a synthetic home in a
// test, a run directory before its first phase).
function realOrResolved(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

export function assertRunDirectory(directory: string, home: string): void {
  if (!isAbsolute(directory))
    throw new Error("the run directory must be an absolute path");
  const resolved = resolve(directory);
  if (resolved !== directory)
    throw new Error("the run directory must be written in its resolved form");
  const realHome = realOrResolved(home);
  if (directory !== join(realHome, runDirectoryName))
    throw new Error(
      `the run directory is ${runDirectoryName} directly under the real home, and nothing else`,
    );
  // The final component is never a link: lstat does not follow it, and the
  // parent is the real home, so no component above it is one either.
  try {
    const stats = lstatSync(directory);
    if (stats.isSymbolicLink())
      throw new Error("the run directory must not be a symlink");
    if (!stats.isDirectory())
      throw new Error("the run directory exists and is not a directory");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  // A reboot clears these, so a run kept there loses the sealed key it is
  // trying to unseal. (The real ~/.ward is no target either: the literal path above is
  // a sibling of it, never inside it.)
  for (const volatile of [
    tmpdir(),
    realOrResolved(tmpdir()),
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
  ])
    if (isInside(volatile, directory))
      throw new Error(`the run directory must not sit under ${volatile}`);
}

// The synthetic vault key. It is derived from a nonce kept in the state file,
// so the second phase can check the unsealed bytes without the key ever being
// written anywhere: only its digest is.
export function deriveKey(nonce: string): Uint8Array {
  return createHash("sha256").update(`ward-qualify-linux:${nonce}`).digest();
}

export function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export interface RunState {
  readonly nonce: string;
  readonly keyDigest: string;
  readonly handlesBefore: HandleSnapshot;
  readonly sealedAt: string;
  readonly bootId: string;
}

export function parseState(text: string): RunState {
  const state = JSON.parse(text) as Partial<RunState>;
  if (
    typeof state.nonce !== "string" ||
    state.nonce === "" ||
    typeof state.keyDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(state.keyDigest) ||
    typeof state.sealedAt !== "string" ||
    typeof state.bootId !== "string" ||
    state.handlesBefore === undefined ||
    handleLists.some((list) => !isHandleRead(state.handlesBefore?.[list]))
  )
    throw new Error("the run state is malformed");
  return state as RunState;
}

// What the scan looks for under the run's stores: the synthetic key and the
// nonce it is derived from. The nonce is key-equivalent, so it is searched for
// as a secret, kept only in the state file (which the mode check covers), and
// never logged. The state file itself is outside the scanned trees.
export function secretNeedles(nonce: string): Uint8Array[] {
  return [deriveKey(nonce), new TextEncoder().encode(nonce)];
}

// Everything under `directory` that is group- or world-accessible or not owned
// by `uid`: a file is private at 0600 and a directory at 0700, and a tool may
// have written wider (tpm2-tools wrote 0660 despite umask 077, measured).
export function modeProblems(
  directory: string,
  uid: number | undefined = process.getuid?.(),
): string[] {
  const problems: string[] = [];
  const walk = (path: string): void => {
    const stats: Stats = lstatSync(path);
    const name = relative(directory, path) || ".";
    if (stats.isSymbolicLink()) {
      problems.push(`${name}: symlink`);
      return;
    }
    const wanted = stats.isDirectory() ? 0o700 : 0o600;
    if ((stats.mode & 0o777) !== wanted)
      problems.push(`${name}: ${(stats.mode & 0o777).toString(8)}`);
    if (uid !== undefined && stats.uid !== uid)
      problems.push(`${name}: owner ${stats.uid}`);
    if (stats.isDirectory())
      for (const entry of readdirSync(path)) walk(join(path, entry));
  };
  walk(directory);
  return problems;
}

export interface ScanResult {
  // Files under the directory that hold a needle, as is, in hex or in base64.
  readonly matches: string[];
  // How many files were read: a scan that read none found nothing because it
  // looked at nothing, and the caller checks this against a positive control.
  readonly filesRead: number;
}

// The run's T05 on the packaged form: whether any file under `directory` holds
// any of `needles`, as raw bytes, hex or base64.
export function containing(
  directory: string,
  needles: readonly Uint8Array[],
): ScanResult {
  const forms = needles.flatMap((needle) => {
    const bytes = Buffer.from(needle);
    return [
      bytes,
      Buffer.from(bytes.toString("hex")),
      Buffer.from(bytes.toString("base64")),
    ];
  });
  const files = readdirSync(directory, { recursive: true })
    .map(String)
    .filter((name) => lstatSync(join(directory, name)).isFile());
  const matches = files.filter((name) => {
    const content = readFileSync(join(directory, name));
    return forms.some((form) => content.includes(form));
  });
  return { matches, filesRead: files.length };
}

// The last JSON line of a command's stdout, or {} when there is none.
export function lastJsonLine(stdout: string): Record<string, unknown> {
  const line = stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("{"))
    .pop();
  try {
    return JSON.parse(line ?? "{}") as Record<string, unknown>;
  } catch {
    return {};
  }
}

// The checks a run must hold before it can read PASSED: DEC-262 (a29)'s
// conditions and the T26 acceptance criteria that every phase measures. A
// phase adds its own (the unseal phase, for one, a different boot id); a name
// missing from the result is a FAILED run, so a check that never ran cannot be
// mistaken for one that passed.
export const requiredChecks = [
  "tcti-is-device-tpmrm0",
  "synthetic-key-only",
  "no-persistent-handles",
  "handle-lists-unchanged",
  "real-ward-untouched",
  "run-directory-private",
  "effective-groups-recorded",
  "session-printout-decrypt-encrypt",
  "unseal-matches-sealed",
  "secret-scan-clean",
] as const;

export interface Check {
  readonly name: string;
  readonly ok: boolean;
}

// PASSED only when every required check is present and ok, no check anywhere
// is failed, and nothing outside the checks failed. An empty requirement list
// is itself FAILED: a verdict with nothing required proves nothing.
export function verdict(
  checks: readonly Check[],
  required: readonly string[],
  extraFailures: readonly string[] = [],
): "PASSED" | "FAILED" {
  const present = new Map<string, boolean>();
  for (const check of checks)
    present.set(check.name, (present.get(check.name) ?? true) && check.ok);
  return required.length > 0 &&
    required.every((name) => present.get(name) === true) &&
    checks.every((c) => c.ok) &&
    extraFailures.length === 0
    ? "PASSED"
    : "FAILED";
}
