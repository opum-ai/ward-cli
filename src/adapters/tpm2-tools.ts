// The subprocess boundary to tpm2-tools for the TPM2-sealed vault key
// (WCLI-21 slice 2, DEC-262 (a9)). tpm2-tools is invoked, never linked.
//
// This module raises Tpm2Error with a reason, not a WardError: mapping a reason
// to a contract error code and a doctor state belongs to the key provider
// (slice 3), so nothing here widens the contract.
import {
  accessSync,
  closeSync,
  constants as fileConstants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  type Stats,
} from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { isPrivateEntry } from "./sqlite-vault-store.ts";

export const tpmDevicePath = "/dev/tpmrm0";
// Every call to a tool is bounded; a hung tool is killed, not waited for.
export const defaultToolTimeoutMs = 10_000;
// A tool's output is a few bytes (an unsealed key is 32); a stream past this is
// a wrong or rogue tool, refused rather than buffered.
export const maxToolOutputBytes = 4096;

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
  | "tpm_unusable"
  | "directory_unusable"
  | "platform_unsupported"
  | "blob_not_user_private"
  | "tool_timeout"
  | "tool_output_too_large"
  | "tool_failed";

// What each refusal says; a detail adds the step to take.
const remedies: Record<Tpm2Reason, string> = {
  tpm_absent: "no TPM2 resource manager device",
  tools_absent: "install the tpm2-tools package",
  tpm_not_accessible: "the TPM2 device is not accessible to this user",
  tpm_unusable: "the TPM2 device could not be opened",
  directory_unusable: "the blob directory could not be created",
  platform_unsupported: "this platform cannot open a blob file safely",
  blob_not_user_private: "blob not user-private",
  tool_timeout: "a tpm2 tool did not finish in time",
  tool_output_too_large: "a tpm2 tool wrote more output than any tool should",
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
  // The default really opens it (O_RDWR, no O_CREAT) and closes it at once:
  // access(2) would pass where a mandatory-access profile refuses the open.
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

// A tool is the first executable regular file on an absolute PATH entry. The
// stat follows symlinks on purpose: tpm2-tools 5.x installs tpm2_* as symlinks
// to one multicall binary that dispatches on argv[0].
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

export function defaultOpenCheck(device: string): void {
  closeSync(openSync(device, fileConstants.O_RDWR));
}

function groupName(gid: number): string {
  try {
    for (const line of readFileSync("/etc/group", "utf8").split("\n")) {
      const [name, , id] = line.split(":");
      if (name !== undefined && id === String(gid)) return name;
    }
  } catch {
    // No group database: fall through to the number.
  }
  return `gid ${gid}`;
}

// The step that fixes an unopenable device, from the device's own owner group
// and mode. A device that grants its group nothing cannot be fixed by joining
// any group, so that case says it is a host configuration change.
export function accessRemedy(
  stats: Pick<Stats, "gid" | "mode">,
  nameOf: (gid: number) => string = groupName,
): string {
  if ((stats.mode & 0o060) === 0o060)
    return `join the ${nameOf(stats.gid)} group`;
  return "a host configuration change is needed (the device mode grants no group access)";
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
      throw new Tpm2Error("tpm_not_accessible", accessRemedy(stats));
    throw new Tpm2Error("tpm_unusable", String(code ?? "unknown"));
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

async function readCapped(
  stream: ReadableStream<Uint8Array>,
  tool: string,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > maxToolOutputBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Tpm2Error("tool_output_too_large", tool);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

// Runs one tool to completion within the bound. The bound is a plain
// setTimeout that kills the tool and returns at once: it does not wait for the
// exit or for EOF, which a process stuck in the driver or a grandchild holding
// a pipe would never give. A test asserts the delay applied.
export async function runTool(
  presence: Tpm2Presence,
  tool: Tpm2Tool,
  args: readonly string[],
  options: { stdin?: Uint8Array; cwd?: string; timeoutMs?: number } = {},
): Promise<ToolRun> {
  const child = spawnTool(presence, tool, args, { cwd: options.cwd });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      child.kill(9);
      reject(new Tpm2Error("tool_timeout", tool));
    }, options.timeoutMs ?? defaultToolTimeoutMs);
  });
  const work = (async (): Promise<ToolRun> => {
    // A tool that exits before reading its stdin makes the write fail with a
    // broken pipe; its exit status, not that, says whether it worked.
    try {
      if (options.stdin !== undefined) child.stdin.write(options.stdin);
      await child.stdin.end();
    } catch {
      // Judged by the exit status below.
    }
    try {
      const [stdout, stderr, code] = await Promise.all([
        readCapped(child.stdout, tool),
        readCapped(child.stderr, tool),
        child.exited,
      ]);
      if (code !== 0) throw new Tpm2Error("tool_failed", tool);
      return { stdout, stderr: Buffer.from(stderr).toString("utf8") };
    } catch (error) {
      child.kill(9);
      throw error;
    }
  })();
  // Whichever loses the race must not become an unhandled rejection.
  work.catch(() => undefined);
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
    timeout.catch(() => undefined);
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
      throw new Tpm2Error("directory_unusable", String(errnoCode(error)));
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

// The open flags adoptToolFile depends on. An undefined one would be dropped
// silently by the bitwise or (a symlink followed, a FIFO blocking the open),
// so a runtime lacking any of them refuses instead of opening.
export function safeOpenFlags(
  constants: Partial<Record<string, number>> = fileConstants,
): number {
  const flags = [
    constants.O_RDONLY,
    constants.O_NOFOLLOW,
    constants.O_NONBLOCK,
    constants.O_NOCTTY,
  ];
  let combined = 0;
  for (const flag of flags) {
    if (typeof flag !== "number") throw new Tpm2Error("platform_unsupported");
    combined |= flag;
  }
  return combined;
}

// A file a tool just wrote is made 0600 by Ward and then verified, because
// the tools' own modes cannot be trusted: tpm2-tools wrote a 0660 context
// under umask 077 (WCLI-153). Everything runs on one descriptor opened
// O_NOFOLLOW, so a symlink swapped in after the check is refused and a path
// swap cannot redirect the chmod.
export function adoptToolFile(path: string): void {
  // O_NOFOLLOW refuses a symlink; O_NONBLOCK and O_NOCTTY keep a FIFO or device
  // at the path from blocking the open or gaining a terminal. The fstat below
  // refuses anything that is not a regular file.
  const flags = safeOpenFlags();
  let fd: number;
  try {
    fd = openSync(path, flags);
  } catch {
    throw new Tpm2Error("blob_not_user_private");
  }
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.uid !== uid())
      throw new Tpm2Error("blob_not_user_private");
    fchmodSync(fd, 0o600);
    if (!isPrivateEntry(fstatSync(fd), "file", uid()))
      throw new Tpm2Error("blob_not_user_private");
  } catch (error) {
    if (error instanceof Tpm2Error) throw error;
    throw new Tpm2Error("blob_not_user_private");
  } finally {
    closeSync(fd);
  }
}
