// The subprocess boundary to tpm2-tools for the TPM2-sealed vault key
// (WCLI-21 slice 2, DEC-262 (a9)). tpm2-tools is invoked, never linked.
//
// This module raises Tpm2Error with a reason, not a WardError: mapping a reason
// to a contract error code and a doctor state belongs to the key provider
// (slice 3), so nothing here widens the contract.
import {
  accessSync,
  chmodSync,
  constants as fileConstants,
  lstatSync,
  mkdirSync,
  statSync,
  type Stats,
} from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { isPrivateEntry } from "./sqlite-vault-store.ts";

export const tpmDevicePath = "/dev/tpmrm0";
// Every call to a tool is bounded; a hung tool is killed, not waited for.
export const defaultToolTimeoutMs = 10_000;

// What a seal and an unseal run, by name (condition (iii): the capability is
// the presence of these, never a version).
export const requiredTools = [
  "tpm2_createprimary",
  "tpm2_create",
  "tpm2_load",
  "tpm2_startauthsession",
  "tpm2_sessionconfig",
  "tpm2_unseal",
  "tpm2_flushcontext",
] as const;
export type Tpm2Tool = (typeof requiredTools)[number];

export type Tpm2Reason =
  | "tpm_absent"
  | "tools_absent"
  | "tpm_not_accessible"
  | "blob_not_user_private"
  | "tool_timeout"
  | "tool_failed";

// What each refusal tells the operator to do; the reason names the state.
const remedies: Record<Tpm2Reason, string> = {
  tpm_absent: "no TPM2 resource manager device",
  tools_absent: "install the tpm2-tools package",
  tpm_not_accessible: "join the tss group (the device is not readable)",
  blob_not_user_private: "blob not user-private",
  tool_timeout: "a tpm2 tool did not finish in time",
  tool_failed: "a tpm2 tool failed",
};

export class Tpm2Error extends Error {
  readonly reason: Tpm2Reason;
  readonly detail: string | undefined;
  constructor(reason: Tpm2Reason, detail?: string) {
    super(
      detail === undefined
        ? remedies[reason]
        : `${remedies[reason]}: ${detail}`,
    );
    this.name = "Tpm2Error";
    this.reason = reason;
    this.detail = detail;
  }
}

export interface Tpm2Host {
  // The search path for the tools, as PATH. Defaults to this process's.
  readonly path?: string;
  // The resource manager device. Defaults to /dev/tpmrm0, never /dev/tpm0.
  readonly device?: string;
  // Opens the device for reading and writing, throwing the errno on refusal.
  // Injected by tests, since a character device cannot be made unreadable
  // without root.
  readonly openCheck?: (device: string) => void;
}

export interface Tpm2Presence {
  readonly device: string;
  readonly tools: Readonly<Record<Tpm2Tool, string>>;
  readonly path: string;
}

function errnoCode(error: unknown): unknown {
  return typeof error === "object" && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

function resolveTool(tool: string, path: string): string | undefined {
  for (const directory of path.split(delimiter)) {
    if (!isAbsolute(directory)) continue;
    const candidate = join(directory, tool);
    try {
      if (!statSync(candidate).isFile()) continue;
      accessSync(candidate, fileConstants.X_OK);
      return candidate;
    } catch {
      // Not here; try the next directory.
    }
  }
  return undefined;
}

function defaultOpenCheck(device: string): void {
  accessSync(device, fileConstants.R_OK | fileConstants.W_OK);
}

// Presence, not version. The order of refusals is part of the contract, since
// a host can fail several at once: no TPM2 device first (installing a package
// cannot help, so the host is unsupported), then missing tools, then a device
// this user cannot open.
export function detectTpm2(host: Tpm2Host = {}): Tpm2Presence {
  const device = host.device ?? tpmDevicePath;
  const path = host.path ?? process.env.PATH ?? "";
  let stats: Stats;
  try {
    stats = statSync(device);
  } catch {
    throw new Tpm2Error("tpm_absent");
  }
  if (!stats.isCharacterDevice()) throw new Tpm2Error("tpm_absent");
  const found: Partial<Record<Tpm2Tool, string>> = {};
  const missing: string[] = [];
  for (const tool of requiredTools) {
    const resolved = resolveTool(tool, path);
    if (resolved === undefined) missing.push(tool);
    else found[tool] = resolved;
  }
  if (missing.length > 0)
    throw new Tpm2Error("tools_absent", missing.join(", "));
  try {
    (host.openCheck ?? defaultOpenCheck)(device);
  } catch (error) {
    const code = errnoCode(error);
    if (code === "EACCES" || code === "EPERM")
      throw new Tpm2Error("tpm_not_accessible");
    throw new Tpm2Error("tpm_absent");
  }
  return { device, tools: found as Record<Tpm2Tool, string>, path };
}

export interface ToolRun {
  readonly stdout: Uint8Array;
  readonly stderr: string;
}

// The environment a tool runs in: the search path and the device, nothing
// else. The key never travels here, and an inherited TPM2TOOLS_TCTI cannot
// point the tools at some other TPM.
function toolEnvironment(presence: Tpm2Presence): Record<string, string> {
  return {
    PATH: presence.path,
    TPM2TOOLS_TCTI: `device:${presence.device}`,
  };
}

// Starts a tool by the absolute path detection resolved, with a minimal
// environment, and returns the process so a caller can write to its stdin.
export function spawnTool(
  presence: Tpm2Presence,
  tool: Tpm2Tool,
  args: readonly string[],
  options: { cwd?: string } = {},
) {
  return Bun.spawn([presence.tools[tool], ...args], {
    env: toolEnvironment(presence),
    cwd: options.cwd,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });
}

// Runs one tool to completion within the bound. The bound is a plain
// setTimeout plus an explicit kill, so a test asserts the delay applied.
export async function runTool(
  presence: Tpm2Presence,
  tool: Tpm2Tool,
  args: readonly string[],
  options: { stdin?: Uint8Array; cwd?: string; timeoutMs?: number } = {},
): Promise<ToolRun> {
  const child = spawnTool(presence, tool, args, { cwd: options.cwd });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill(9);
  }, options.timeoutMs ?? defaultToolTimeoutMs);
  try {
    if (options.stdin !== undefined) child.stdin.write(options.stdin);
    child.stdin.end();
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).bytes(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    if (timedOut) throw new Tpm2Error("tool_timeout", tool);
    if (code !== 0) throw new Tpm2Error("tool_failed", tool);
    return { stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
}

function uid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

// Ward's directory for blobs and contexts: created 0700 when absent, and
// refused when it is anything but a 0700 directory of this user.
export function preparePrivateDirectory(directory: string): void {
  if (!isAbsolute(directory)) throw new Tpm2Error("blob_not_user_private");
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (errnoCode(error) !== "EEXIST")
      throw new Tpm2Error("tool_failed", "mkdir");
  }
  requirePrivate(directory, "directory");
}

function requirePrivate(path: string, kind: "directory" | "file"): void {
  let stats: Stats;
  try {
    stats = lstatSync(path);
  } catch {
    throw new Tpm2Error("blob_not_user_private");
  }
  if (!isPrivateEntry(stats, kind, uid()))
    throw new Tpm2Error("blob_not_user_private");
}

// A file already on disk is read only when it is exactly 0600, this user's,
// and not a symlink: wider is refused, never repaired.
export function requirePrivateFile(path: string): void {
  requirePrivate(path, "file");
}

// A file a tool just wrote is made 0600 by Ward and then verified, because
// the tools' own modes cannot be trusted: tpm2-tools wrote a 0660 context
// under umask 077 (WCLI-153). The file must be this user's regular file,
// never a symlink, before it is touched.
export function adoptToolFile(path: string): void {
  let stats: Stats;
  try {
    stats = lstatSync(path);
  } catch {
    throw new Tpm2Error("blob_not_user_private");
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.uid !== uid())
    throw new Tpm2Error("blob_not_user_private");
  try {
    chmodSync(path, 0o600);
  } catch {
    throw new Tpm2Error("blob_not_user_private");
  }
  requirePrivate(path, "file");
}
