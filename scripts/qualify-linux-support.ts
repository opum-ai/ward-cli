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
  // Defence in depth: a home that is itself under a Ward store is never a run.
  if (realHome.split(sep).includes(".ward"))
    throw new Error("the home directory has a .ward component");
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

// The reboot proof rests on the boot ids, so each is held to its real shape: a
// lowercase UUID as /proc/sys/kernel/random/boot_id prints it. An empty or failed
// read is not an id that "differs from every real one", on the sealed side
// (parseState) or the current side (bootIdChanged).
const bootIdShape =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

// Whether the boot after the reboot is a different one from the boot that
// sealed. Both ids are shape-checked first and an invalid one refuses: a
// failed read must never count as "different".
export function bootIdChanged(sealed: string, current: string): boolean {
  for (const [side, id] of [
    ["sealed", sealed],
    ["current", current],
  ] as const)
    if (typeof id !== "string" || !bootIdShape.test(id))
      throw new Error(`the ${side} boot id is not a lowercase UUID`);
  return sealed !== current;
}

// The nonce is 64 lowercase hex characters: 256 bits for the synthetic key, and
// long enough that the scan's forms of it cannot match unrelated files.
const nonceShape = /^[0-9a-f]{64}$/;

// A timestamp is ISO 8601 UTC and a real date: Date.parse rolls 2026-02-30 over
// to March 2 instead of refusing it (measured on Bun 1.3.14), so the date
// parts must survive a round trip. sealedAt is DESCRIPTIVE ONLY: it is recorded
// for the report and no check reads it, so it adds nothing to the reboot proof,
// which rests on the boot ids.
function isRealTimestamp(text: string): boolean {
  if (!isoTimestamp.test(text) || Number.isNaN(Date.parse(text))) return false;
  return new Date(text).toISOString().slice(0, 19) === text.slice(0, 19);
}

export function parseState(text: string): RunState {
  let state: Partial<RunState>;
  try {
    state = JSON.parse(text) as Partial<RunState>;
  } catch {
    // No cause is carried: the text holds the nonce, and a SyntaxError can
    // quote part of it.
    throw new Error("the run state is malformed");
  }
  if (
    typeof state !== "object" ||
    state === null ||
    typeof state.nonce !== "string" ||
    !nonceShape.test(state.nonce) ||
    typeof state.keyDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(state.keyDigest) ||
    typeof state.sealedAt !== "string" ||
    !isRealTimestamp(state.sealedAt) ||
    typeof state.bootId !== "string" ||
    !bootIdShape.test(state.bootId) ||
    typeof state.handlesBefore !== "object" ||
    state.handlesBefore === null ||
    handleLists.some((list) => !isHandleRead(state.handlesBefore?.[list]))
  )
    throw new Error("the run state is malformed");
  return state as RunState;
}

// What the scan looks for under the run's stores: the synthetic key and the
// nonce it is derived from. The nonce is key-equivalent, so it is searched for
// as a secret, kept only in the state file (which the mode check covers), and
// never logged. The state file therefore lives OUTSIDE the scanned tree: the
// run directory holds state.json beside a store/ directory, and the scan is
// rooted at store/ (WCLI-21 carries that layout as owed to 4a-2).
export function secretNeedles(nonce: string): Uint8Array[] {
  if (!nonceShape.test(nonce))
    throw new Error("the nonce is 64 lowercase hex characters");
  return [
    deriveKey(nonce),
    new TextEncoder().encode(nonce),
    // The nonce's own 32 bytes are as key-equivalent as its text.
    Buffer.from(nonce, "hex"),
  ];
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
    // A second link to a private file can expose it from outside the tree.
    if (!stats.isDirectory() && stats.nlink > 1)
      problems.push(`${name}: ${stats.nlink} links`);
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
  const hex = bytes.toString("hex");
  const out: Buffer[] = [
    bytes,
    Buffer.from(hex),
    Buffer.from(hex.toUpperCase()),
  ];
  // The likeliest leaks into a log: a byte array printed as decimals
  // (JSON.stringify of a Buffer, Bun.inspect or util.inspect of a Uint8Array)
  // and hex printed with a separator (od -An -tx1, xxd -p -c1, a Buffer's
  // inspect, a colon-joined fingerprint). A run of whitespace in the file,
  // newlines and util.inspect's padding included, is searched as one space (see
  // containing), which is what lets a wrapped listing match. Listings that carry
  // offsets (xxd's default, od without -An) or characters between the bytes are
  // not searched.
  for (const separator of [",", ", ", " ", ":", "-"]) {
    out.push(Buffer.from([...bytes].join(separator)));
    const pairs = hex.match(/../g) ?? [];
    out.push(Buffer.from(pairs.join(separator)));
    out.push(Buffer.from(pairs.join(separator).toUpperCase()));
  }
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
  if (
    needles.length === 0 ||
    needles.some((needle) => needle.length < minimumNeedleBytes)
  )
    throw new Error(
      `the scan needs at least one needle and each is at least ${minimumNeedleBytes} bytes`,
    );
  const searched = needles.flatMap(forms);
  const files = regularFiles(directory);
  const matches = files.filter((name) => {
    return holdsAny(readFileSync(join(directory, name)), searched);
  });
  return { matches, filesRead: files.length };
}

// Whether `content` holds any of the already-expanded forms, as is or with every
// whitespace run read as one space: a listing wrapped over lines, or padded to
// align its columns, then matches the single-space forms.
export function holdsAny(
  content: Buffer,
  searched: readonly Buffer[],
): boolean {
  const collapsed = Buffer.from(
    content.toString("latin1").replace(/\s+/g, " "),
    "latin1",
  );
  return searched.some(
    (form) => content.includes(form) || collapsed.includes(form),
  );
}

// Every form of each needle (see forms), for a scan that reads files itself.
export function needleForms(needles: readonly Uint8Array[]): Buffer[] {
  if (
    needles.length === 0 ||
    needles.some((needle) => needle.length < minimumNeedleBytes)
  )
    throw new Error(
      `the scan needs at least one needle and each is at least ${minimumNeedleBytes} bytes`,
    );
  return needles.flatMap(forms);
}

// A shorter needle matches unrelated files in some form of it, which would fail
// a clean run.
export const minimumNeedleBytes = 8;

// The regular files under `directory`, by path relative to it. Symlinks are
// neither followed nor read: a link to a directory outside the tree is not part
// of it, and a link to a FIFO would block the read.
function regularFiles(directory: string): string[] {
  const found: string[] = [];
  const walk = (relativePath: string): void => {
    for (const entry of readdirSync(join(directory, relativePath), {
      withFileTypes: true,
    })) {
      const name = join(relativePath, entry.name);
      // A directory entry that names none of the kinds (DT_UNKNOWN on a
      // filesystem that does not fill it in) is lstat'd instead.
      const kind =
        entry.isFile() ||
        entry.isDirectory() ||
        entry.isSymbolicLink() ||
        entry.isFIFO() ||
        entry.isSocket() ||
        entry.isBlockDevice() ||
        entry.isCharacterDevice()
          ? entry
          : lstatSync(join(directory, name));
      if (kind.isDirectory()) walk(name);
      else if (kind.isFile()) found.push(name);
      else if (!kind.isSymbolicLink())
        // A FIFO, a socket or a device: not read (a FIFO would block) and not
        // skipped in silence, so a tree the scan could not fully read is not a
        // clean tree.
        throw new Error(
          `the scan cannot read ${name}: it is not a file, a directory or a link`,
        );
    }
  };
  walk("");
  return found;
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

// The rows every phase that runs a TPM tool owes (DEC-262 a29 and a33): the TPM
// is only ever reached through the ruled TCTI, and each such phase (P2 seal, P3
// unseal, P4 clean) takes its own before and after handle lists. The facts phase
// (P0) takes no baseline and owes none of these. The ward-metadata row is owed
// by P1 to P4 (deliver lists it itself), against a baseline taken at the start
// of P1.
const runWide = [
  "tcti-is-device-tpmrm0",
  "handle-lists-unchanged",
  "real-ward-metadata-unchanged",
] as const;
// The rows the logging shim adds (DEC-262 a30): what the interposers saw of the
// environment and the arguments, the report statement, and that the calls the
// phase must make were logged. Without them in this list a run that never
// produced one would still read PASSED.
const shimCalls = [
  "key-not-in-tool-environment",
  "key-not-in-tool-argv",
  "report-states-the-logging-shim",
  "expected-tool-calls-made",
  "interposer-env-matches-tool-env",
] as const;
// The listing of the places a key could be left. The clean phase takes none: it
// handles no key and runs only tpm2_getcap, and the run directory it works in is
// deleted by the end of it, so a window over it has nothing to compare.
const shimWindow = ["key-not-in-files-present-at-the-after-listing"] as const;
const stored = [
  "run-directory-is-ruled-literal-path",
  "run-directory-private",
  ...runWide,
] as const;
const keyHandling = [
  "synthetic-key-only",
  "no-persistent-handles",
  "effective-groups-recorded",
  "session-printout-decrypt-encrypt",
  "session-printout-is-the-unseal-session",
  "session-salted-to-primary",
  "unseal-matches-sealed",
  "secret-scan-clean",
  "key-not-in-store-or-tool-log",
] as const;

export const requiredChecks: Readonly<Record<Phase, readonly string[]>> = {
  // P0 is read-only and runs no interposer (DEC-262 a32): it handles no key, so
  // it owes neither the shim rows nor the window row. It owes only what its four
  // (a29) Q2 commands (id -G, uname -a, tpm2_getcap --version, ls -l
  // /dev/tpmrm0) can produce, so none of the run-wide rows either (a33): it runs
  // no ward binary, reads no ward metadata, and takes no handle list or TCTI.
  // python3-recorded is not here either (a34): P0 runs no fifth command.
  facts: [
    "effective-groups-recorded",
    "tpm-device-present",
    "tpm2-tools-present",
  ],
  // The delivery phase runs no TPM tool, so it owes neither the TCTI nor the
  // handle rows, only that the home directory was left alone.
  deliver: [
    "run-directory-is-ruled-literal-path",
    "run-directory-private",
    "real-ward-metadata-unchanged",
    "binaries-sha256-match-both-ends",
  ],
  seal: [...stored, ...keyHandling, ...shimCalls, ...shimWindow],
  unseal: [
    ...stored,
    ...keyHandling,
    ...shimCalls,
    ...shimWindow,
    "boot-id-differs-from-seal",
    // The packaged python3 pty smoke is to run at P3 (DEC-262 a34), so P3 OWES the
    // interpreter it actually ran, its path and version; nothing produces that
    // row yet (part B builds it), so until then P3 fails closed. P0 runs no
    // python3.
    "python3-recorded",
  ],
  clean: [
    ...runWide,
    ...shimCalls,
    "run-directory-is-ruled-literal-path",
    "run-directory-removed",
  ],
};

export interface Check {
  readonly name: string;
  readonly ok: boolean;
  // What the row measured, for the report; verdict never reads it. It must not
  // carry the nonce, the key or a passphrase.
  readonly detail?: unknown;
}

// PASSED only when every check the phase requires is present and ok, every
// check at all is strictly ok (a string "false" is not true), and nothing
// outside the checks failed.
export function verdict(
  phase: Phase,
  checks: readonly Check[],
  extraFailures: readonly string[] = [],
): "PASSED" | "FAILED" {
  const required = Object.hasOwn(requiredChecks, phase)
    ? requiredChecks[phase]
    : undefined;
  const named = new Set(checks.map((check) => check.name));
  return required !== undefined &&
    required.length > 0 &&
    required.every((name) => named.has(name)) &&
    checks.every((check) => check.ok === true) &&
    extraFailures.length === 0
    ? "PASSED"
    : "FAILED";
}

// A lexical tripwire, not a guarantee (DEC-262: the operator reboots, Ward never
// does). It takes any source string and reads it as code with comments removed,
// so a comment saying "never reboot" is not a finding. Which file it is pointed at
// is the test's choice (today only qualify-linux.ts); it does not see modules the
// caller does not hand it, or an evasion it does not list.
export const forbiddenSpawnWords = [
  "reboot",
  "shutdown",
  "systemctl",
  "poweroff",
  "halt",
  "init",
] as const;

export function harnessSourceProblems(source: string): string[] {
  const code = new Bun.Transpiler({ loader: "ts" }).transformSync(source);
  const problems: string[] = forbiddenSpawnWords
    .filter((word) => new RegExp(`\\b${word}\\b`).test(code))
    .map((word) => `names ${word}`);
  if (/\bsh\b[^\n]*["'`]-c["'`]|["'`]sh -c/.test(code)) problems.push("sh -c");
  if (/\bshell\s*:\s*(?!\s)(?!false\b|!1(?![\w.]))/.test(code))
    problems.push("shell option");
  if (/\bexecSync\b|(?<![.\w])exec\(|\bexecFile/.test(code))
    problems.push("exec");
  return problems;
}
