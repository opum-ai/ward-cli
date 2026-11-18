// The pure parts of the Linux T26 harness (WCLI-21 slice 4a): everything that
// can be proved without a TPM, so `bun test` measures it and the hardware run
// only has to trust it. Nothing here touches a TPM or a credential store.
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, type Stats } from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";

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
export type HandleSnapshot = Readonly<Record<HandleList, string>>;

export function diffHandles(
  before: HandleSnapshot,
  after: HandleSnapshot,
): HandleList[] {
  return handleLists.filter((list) => before[list] !== after[list]);
}

// The run directory is persistent on purpose, because the reboot between the
// phases clears /tmp, and every guard that follows is about not deleting or
// writing anything that is not this run's. Its basename carries a prefix, and
// the clean phase also requires the marker file below.
export const runDirectoryPrefix = "ward-qualify-linux-";
export const markerName = ".ward-qualify-linux";

export function assertRunDirectory(directory: string, home: string): void {
  if (!isAbsolute(directory))
    throw new Error("the run directory must be an absolute path");
  const resolved = resolve(directory);
  if (resolved !== directory)
    throw new Error("the run directory must be written in its resolved form");
  if (!basename(resolved).startsWith(runDirectoryPrefix))
    throw new Error(`the run directory's name begins ${runDirectoryPrefix}`);
  const inside = (parent: string): boolean => {
    const rel = relative(resolve(parent), resolved);
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
  };
  // A reboot clears these, so a run kept there loses the sealed key it is
  // trying to unseal; and the developer's real Ward store is never a target.
  for (const volatile of [tmpdir(), "/tmp", "/var/tmp", "/dev/shm", "/run"])
    if (inside(volatile))
      throw new Error(`the run directory must not sit under ${volatile}`);
  if (inside(join(home, ".ward")))
    throw new Error("the run directory must not sit under the real ~/.ward");
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
    typeof state.keyDigest !== "string" ||
    typeof state.sealedAt !== "string" ||
    typeof state.bootId !== "string" ||
    state.handlesBefore === undefined ||
    handleLists.some((list) => typeof state.handlesBefore?.[list] !== "string")
  )
    throw new Error("the run state is malformed");
  return state as RunState;
}

// Everything under `directory` that is group- or world-accessible: a file is
// private at 0600 and a directory at 0700, and a tool may have written wider
// (tpm2-tools wrote 0660 despite umask 077, measured).
export function modeProblems(directory: string): string[] {
  const problems: string[] = [];
  const walk = (path: string): void => {
    const stats: Stats = lstatSync(path);
    if (stats.isSymbolicLink()) {
      problems.push(`${relative(directory, path)}: symlink`);
      return;
    }
    const wanted = stats.isDirectory() ? 0o700 : 0o600;
    if ((stats.mode & 0o777) !== wanted)
      problems.push(
        `${relative(directory, path) || "."}: ${(stats.mode & 0o777).toString(8)}`,
      );
    if (stats.isDirectory())
      for (const name of readdirSync(path)) walk(join(path, name));
  };
  walk(directory);
  return problems;
}

// Whether any file under `directory` holds `needle`, as is, base64 or hex: the
// run's T05 on the packaged form.
export function containing(directory: string, needle: string): string[] {
  const forms = [
    needle,
    Buffer.from(needle).toString("base64"),
    Buffer.from(needle).toString("hex"),
  ].map((form) => Buffer.from(form));
  return readdirSync(directory, { recursive: true })
    .map(String)
    .filter((name) => lstatSync(join(directory, name)).isFile())
    .filter((name) => {
      const content = readFileSync(join(directory, name));
      return forms.some((form) => content.includes(form));
    });
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

// A result is PASSED only when it holds checks, every one is ok, and nothing
// outside the checks failed: an empty list reads as FAILED, never PASSED.
export function verdict(
  checks: readonly { ok: boolean }[],
  extraFailures: readonly string[] = [],
): "PASSED" | "FAILED" {
  return checks.length > 0 &&
    checks.every((c) => c.ok) &&
    extraFailures.length === 0
    ? "PASSED"
    : "FAILED";
}
