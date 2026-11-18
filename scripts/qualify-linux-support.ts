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
// phases clears /tmp. Nothing else is accepted. This is a check at one moment,
// not a lock: the harness calls assertRunDirectory again immediately before
// each use, the clean phase's delete included (WCLI-21 carries that as owed).
export const runDirectoryName = "ward-t26-wcli21";

// Where a reboot clears the filesystem: a run kept there loses the sealed key it
// is trying to unseal.
export const volatileRoots: readonly string[] = [
  "/tmp",
  "/var/tmp",
  "/dev/shm",
  "/run",
];

// Whether `child` is `parent` or lies under it. The test is on path segments:
// a sibling whose name merely begins with two dots ("..x") is inside.
export function isInside(parent: string, child: string): boolean {
  const rel = relative(resolve(parent), resolve(child));
  return (
    rel === "" ||
    (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
  );
}

// The real path of something that may legitimately not exist (/dev/shm on a
// host without it). Only a missing path falls back to its lexical form: a
// permission error or a symlink loop is an unknown, and an unknown refuses.
function realpathOrAbsent(path: string): string {
  try {
    return realpathSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      return resolve(path);
    throw error;
  }
}

export function assertRunDirectory(
  directory: string,
  home: string,
  volatile: readonly string[] = [tmpdir(), ...volatileRoots],
): void {
  if (!isAbsolute(directory))
    throw new Error("the run directory must be an absolute path");
  const resolved = resolve(directory);
  if (resolved !== directory)
    throw new Error("the run directory must be written in its resolved form");
  // The home must exist and resolve: a dangling or looping link, or one this
  // user cannot read, is refused rather than read as its lexical self.
  let realHome: string;
  try {
    realHome = realpathSync(home);
  } catch (error) {
    throw new Error(
      `the home directory cannot be resolved (${(error as NodeJS.ErrnoException).code ?? "unknown"})`,
    );
  }
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
  // Each volatile root is compared as written and by its real path, so a root
  // that is itself a link (macOS /tmp is /private/tmp) cannot hide a home. The
  // real ~/.ward is no target either: the literal path above is a sibling of
  // it, never inside it.
  for (const root of volatile)
    for (const form of [root, realpathOrAbsent(root)])
      if (isInside(form, directory))
        throw new Error(`the run directory must not sit under ${root}`);
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

// The reboot proof rests on these two fields, so each is held to its real shape:
// a boot id is a lowercase UUID as /proc/sys/kernel/random/boot_id prints it,
// and a timestamp is ISO 8601 in UTC. An empty or failed read is not an id that
// "differs from every real one".
const bootIdShape =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

export function parseState(text: string): RunState {
  const state = JSON.parse(text) as Partial<RunState>;
  if (
    typeof state.nonce !== "string" ||
    state.nonce === "" ||
    typeof state.keyDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(state.keyDigest) ||
    typeof state.sealedAt !== "string" ||
    !isoTimestamp.test(state.sealedAt) ||
    Number.isNaN(Date.parse(state.sealedAt)) ||
    typeof state.bootId !== "string" ||
    !bootIdShape.test(state.bootId) ||
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

// The uid this process runs as. Without one the owner check cannot run, and a
// check that cannot run refuses instead of passing.
function currentUid(): number {
  const uid = process.getuid?.();
  if (uid === undefined)
    throw new Error("the owner check needs a uid and this host gives none");
  return uid;
}

// Everything under `directory` that is group- or world-accessible or not owned
// by `uid`: a file is private at 0600 and a directory at 0700, and a tool may
// have written wider (tpm2-tools wrote 0660 despite umask 077, measured).
// The mode, in octal, when it is not the private one (0600 file, 0700
// directory). The mask keeps setuid, setgid and sticky: any of them is a
// problem, and a filesystem that drops them cannot hide one.
export function wideMode(
  mode: number,
  isDirectory: boolean,
): string | undefined {
  const wanted = isDirectory ? 0o700 : 0o600;
  return (mode & 0o7777) === wanted ? undefined : (mode & 0o7777).toString(8);
}

export function modeProblems(
  directory: string,
  uid: number = currentUid(),
): string[] {
  const problems: string[] = [];
  const walk = (path: string): void => {
    const stats: Stats = lstatSync(path);
    const name = relative(directory, path) || ".";
    if (stats.isSymbolicLink()) {
      problems.push(`${name}: symlink`);
      return;
    }
    const wide = wideMode(stats.mode, stats.isDirectory());
    if (wide !== undefined) problems.push(`${name}: ${wide}`);
    if (stats.uid !== uid) problems.push(`${name}: owner ${stats.uid}`);
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
// Every form a needle takes in a file: raw, hex in both cases, and base64 and
// base64url without padding at each of the three alignments a stream can put it
// at (a padded form never matches inside a longer stream, and the first and last
// characters of a shifted form depend on the neighbouring bytes, so they are
// dropped).
function forms(needle: Uint8Array): Buffer[] {
  const bytes = Buffer.from(needle);
  const out: Buffer[] = [
    bytes,
    Buffer.from(bytes.toString("hex")),
    Buffer.from(bytes.toString("hex").toUpperCase()),
  ];
  for (const shift of [0, 1, 2]) {
    let text = Buffer.concat([Buffer.alloc(shift), bytes])
      .toString("base64")
      .replace(/=+$/, "");
    if ((shift + bytes.length) % 3 !== 0) text = text.slice(0, -1);
    if (shift > 0) text = text.slice(shift + 1);
    if (text === "") continue;
    out.push(Buffer.from(text));
    out.push(Buffer.from(text.replace(/\+/g, "-").replace(/\//g, "_")));
  }
  return out;
}

// The run's T05 on the packaged form: whether any file under `directory` holds
// any of `needles`, in any form above.
export function containing(
  directory: string,
  needles: readonly Uint8Array[],
): ScanResult {
  if (needles.length === 0 || needles.some((needle) => needle.length === 0))
    throw new Error("the scan needs at least one needle and none may be empty");
  const searched = needles.flatMap(forms);
  const files = readdirSync(directory, { recursive: true })
    .map(String)
    .filter((name) => lstatSync(join(directory, name)).isFile());
  const matches = files.filter((name) => {
    const content = readFileSync(join(directory, name));
    return searched.some((form) => content.includes(form));
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

// What each phase must show before it can read PASSED, from DEC-262 (a29)'s
// conditions and the T26 acceptance criteria. A phase's list is its own: the
// read-only facts phase measures little, the unseal phase after the reboot adds
// the boot-id proof. verdict takes the phase, not a list, so no caller can
// narrow what a phase requires, and a name missing from the result is a FAILED
// run, so a check that never ran cannot be mistaken for one that passed.
// None of these names claims the wire was measured: ADR 0028 keeps it
// UNMEASURED (a29 Q1), and the printout check says only what the printout shows.
export type Phase = "facts" | "deliver" | "seal" | "unseal" | "clean";

const stored = [
  "run-directory-is-ruled-literal-path",
  "run-directory-private",
  "handle-lists-unchanged",
  "real-ward-untouched",
] as const;
const keyHandling = [
  "tcti-is-device-tpmrm0",
  "synthetic-key-only",
  "no-persistent-handles",
  "effective-groups-recorded",
  "session-printout-decrypt-encrypt",
  "session-printout-is-the-unseal-session",
  "unseal-matches-sealed",
  "secret-scan-clean",
  "key-not-in-argv-environment-or-temp-file",
] as const;

export const requiredChecks: Readonly<Record<Phase, readonly string[]>> = {
  facts: [
    "effective-groups-recorded",
    "tpm-device-present",
    "tpm2-tools-present",
    "python3-recorded",
  ],
  deliver: [
    "run-directory-is-ruled-literal-path",
    "run-directory-private",
    "binaries-sha256-match-both-ends",
  ],
  seal: [...stored, ...keyHandling],
  unseal: [...stored, ...keyHandling, "boot-id-differs-from-seal"],
  clean: [
    "run-directory-is-ruled-literal-path",
    "run-directory-removed",
    "real-ward-untouched",
  ],
};

export interface Check {
  readonly name: string;
  readonly ok: boolean;
}

// PASSED only when every check the phase requires is present and ok, every
// check at all is strictly ok (a string "false" is not true), and nothing
// outside the checks failed.
export function verdict(
  phase: Phase,
  checks: readonly Check[],
  extraFailures: readonly string[] = [],
): "PASSED" | "FAILED" {
  const required = requiredChecks[phase];
  const present = new Map<string, boolean>();
  for (const check of checks)
    present.set(
      check.name,
      (present.get(check.name) ?? true) && check.ok === true,
    );
  return required !== undefined &&
    required.length > 0 &&
    required.every((name) => present.get(name) === true) &&
    checks.every((c) => c.ok === true) &&
    extraFailures.length === 0
    ? "PASSED"
    : "FAILED";
}
