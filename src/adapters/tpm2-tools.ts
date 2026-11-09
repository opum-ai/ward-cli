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
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readlinkSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  type Stats,
  unlinkSync,
} from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join } from "node:path";
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
  | "key_not_sealed"
  | "session_not_encrypted"
  | "tool_untrusted"
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
  key_not_sealed: "no sealed vault key is present",
  session_not_encrypted:
    "the TPM session does not encrypt the unsealed key in transit",
  tool_untrusted: "a tpm2 tool is not trusted to receive the vault key",
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

const maxLinkHops = 40;

function modeText(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

// DEC-262 (a10): a tool receives the vault key on its stdin, so a tool is
// trusted only after a walk of everything that decides which file runs. Every
// element on the way from the resolved tpm2_* path to the final regular file is
// checked: each directory component, each symlink hop and the final file, with
// every symlink's target resolved component by component (a relative target
// against its link's directory). Each must be owned by a trusted uid and must
// not be group- or other-writable; a sticky bit does NOT excuse a writable
// directory. A symlink is checked for its owner only, since its own mode is
// meaningless (Linux always reports 0777): who can replace it is decided by
// the directory that holds it, which is checked. A failure refuses by name
// before any spawn, and is never answered by trying a later PATH entry.
export function assertToolTrusted(toolPath: string): void {
  checkExecutable(toolPath, {});
}

// TEST SEAM, not a production entry point: the only way to narrow the walk.
// trustedUids replaces the trusted owners (production: root and the invoking
// user); trustRoot starts the ancestor check at a test's private directory,
// since a temp directory is sticky and world-writable. Nothing in src/ may
// call a ForTest or walkToolTrust name outside this file; a test enforces it.
export interface ToolTrustPolicy {
  readonly trustedUids?: readonly number[];
  readonly trustRoot?: string;
  // Replaces /usr/bin and /bin in the walked search path, so a test can make
  // one of them unclean. Production never sets it.
  readonly systemDirectories?: readonly string[];
}

export function walkToolTrustForTest(
  toolPath: string,
  policy: ToolTrustPolicy,
): void {
  checkExecutable(toolPath, policy);
}

// The first line after "#!", or undefined for a file that does not start with
// one. A file this process cannot read (an execute-only tool, an I/O error) is
// refused: the check fails closed rather than skipping the shebang.
function shebangLine(label: string, path: string): string | undefined {
  const buffer = Buffer.alloc(256);
  let read: number;
  try {
    const descriptor = openSync(path, "r");
    try {
      read = readSync(descriptor, buffer, 0, buffer.length, 0);
    } finally {
      closeSync(descriptor);
    }
  } catch (error) {
    throw new Tpm2Error(
      "tool_untrusted",
      `${label}: ${path} cannot be read (${String(errnoCode(error) ?? "unknown")})`,
    );
  }
  if (read < 2 || buffer[0] !== 0x23 || buffer[1] !== 0x21) return undefined;
  const text = buffer.subarray(2, read).toString("latin1");
  const end = text.indexOf("\n");
  if (end < 0 && read === buffer.length)
    throw new Tpm2Error(
      "tool_untrusted",
      `${label}: ${path} has a shebang line longer than the kernel reads`,
    );
  return end < 0 ? text : text.slice(0, end);
}

// The interpreter as the kernel reads it: after any spaces and tabs, up to the
// next space, tab or the end of the line; what follows (leading and trailing
// spaces and tabs trimmed, as Linux does) is passed as ONE argument. A "\r" is
// not stripped; it is outside printable ASCII, so a CRLF script is refused by
// that check, which refuses any such byte rather than interpreting it.
function shebangParts(
  toolPath: string,
  line: string,
): { interpreter: string; argument: string } {
  const match = /^[ \t]*([^ \t]*)/.exec(line);
  const interpreter = match?.[1] ?? "";
  if (!/^[\x21-\x7e]*$/.test(interpreter))
    throw new Tpm2Error(
      "tool_untrusted",
      `${toolPath}: its shebang interpreter ${JSON.stringify(interpreter)} has a byte outside printable ASCII`,
    );
  if (!isAbsolute(interpreter))
    throw new Tpm2Error(
      "tool_untrusted",
      `${toolPath}: its shebang interpreter ${JSON.stringify(interpreter)} is not an absolute path`,
    );
  const argument = line
    .slice(match?.[0].length ?? 0)
    .replace(/^[ \t]+/, "")
    .replace(/[ \t]+$/, "");
  return { interpreter, argument };
}

// DEC-262 (a12), (a13), (a14): an executable is the walked file plus what its
// shebang names. The interpreter must be an absolute path that passes the same
// walk, and is judged by its final file, which must not itself start with
// "#!" (refused, never followed). Shared libraries are a recorded residual.
// When the interpreter is env, by the name written or by the final file (a
// multicall install, an alias), the rest of the line is ONE argument and must
// be a single bare command name, which env resolves on the child's confined
// PATH (toolSearchPath); anything else could move the search or add a program.
function checkExecutable(toolPath: string, policy: ToolTrustPolicy): void {
  const line = shebangLine(toolPath, walkToolTrust(toolPath, policy, "file"));
  if (line === undefined) return;
  const { interpreter, argument } = shebangParts(toolPath, line);
  let final: string;
  try {
    final = walkToolTrust(interpreter, policy, "file");
  } catch (error) {
    if (!(error instanceof Tpm2Error)) throw error;
    throw new Tpm2Error(
      "tool_untrusted",
      `${toolPath}: its shebang interpreter: ${error.detail}`,
    );
  }
  if (shebangLine(`${toolPath}: its shebang interpreter`, final) !== undefined)
    throw new Tpm2Error(
      "tool_untrusted",
      `${toolPath}: its shebang interpreter ${interpreter} (${final}) is itself a "#!" script`,
    );
  if (basename(interpreter) !== "env" && basename(final) !== "env") return;
  if (
    !/^[\x21-\x7e]+$/.test(argument) ||
    /[/=]/.test(argument) ||
    argument.startsWith("-")
  )
    throw new Tpm2Error(
      "tool_untrusted",
      `${toolPath}: its shebang line ${JSON.stringify(line)} runs env with something other than one bare command name`,
    );
}

// The directories a child may search, and the only ones: the tool's own, then
// /usr/bin and /bin. Each passes the walk before anything runs.
function toolSearchPath(
  toolPath: string,
  system: readonly string[] = ["/usr/bin", "/bin"],
): string[] {
  return [...new Set([dirname(toolPath), ...system])];
}

// Returns the final regular file (or, for kind "dir", the final directory)
// the path resolves to.
function walkToolTrust(
  toolPath: string,
  policy: ToolTrustPolicy,
  kind: "file" | "dir" = "file",
): string {
  const trusted = policy.trustedUids ?? [0, uid() ?? 0];
  const root =
    policy.trustRoot === undefined ? undefined : realpathSync(policy.trustRoot);
  const remedy =
    "the owner must be root or this user, and the mode neither group- nor world-writable; fix the install, or put a trusted tpm2-tools first on PATH";
  const refuse = (element: string, stats: Stats, why: string): never => {
    throw new Tpm2Error(
      "tool_untrusted",
      `${toolPath}: ${element} is owned by uid ${stats.uid} with mode ${modeText(stats.mode)} (${why}); ${remedy}`,
    );
  };
  // Directories that are strict ancestors of the trust root are not examined.
  const above = (path: string): boolean =>
    root !== undefined &&
    (path === "/" || (root !== path && root.startsWith(`${path}/`)));
  const check = (path: string, stats: Stats): void => {
    if (above(path)) return;
    if (!trusted.includes(stats.uid)) refuse(path, stats, "untrusted owner");
    if (!stats.isSymbolicLink() && (stats.mode & 0o022) !== 0)
      refuse(path, stats, "group- or world-writable");
  };

  if (!isAbsolute(toolPath)) throw new Tpm2Error("tool_untrusted", toolPath);
  let resolved = "/";
  check("/", lstatSync("/"));
  let pending = toolPath.split("/").filter((part) => part !== "");
  let hops = 0;
  while (pending.length > 0) {
    const [part, ...rest] = pending;
    pending = rest;
    if (part === ".") continue;
    if (part === "..") {
      resolved = dirname(resolved);
      continue;
    }
    const candidate = join(resolved, part as string);
    let stats: Stats;
    try {
      stats = lstatSync(candidate);
    } catch (error) {
      throw new Tpm2Error(
        "tool_untrusted",
        `${toolPath}: ${candidate} cannot be examined (${String(errnoCode(error) ?? "unknown")})`,
      );
    }
    check(candidate, stats);
    if (stats.isSymbolicLink()) {
      if (++hops > maxLinkHops)
        throw new Tpm2Error("tool_untrusted", `${toolPath}: too many symlinks`);
      let target: string;
      try {
        target = readlinkSync(candidate);
      } catch (error) {
        throw new Tpm2Error(
          "tool_untrusted",
          `${toolPath}: ${candidate} cannot be read as a link (${String(errnoCode(error) ?? "unknown")})`,
        );
      }
      if (isAbsolute(target)) resolved = "/";
      pending = [...target.split("/").filter((p) => p !== ""), ...pending];
      continue;
    }
    if (pending.length > 0 && !stats.isDirectory())
      throw new Tpm2Error(
        "tool_untrusted",
        `${toolPath}: ${candidate} is not a directory`,
      );
    if (pending.length === 0 && kind === "file" && !stats.isFile())
      throw new Tpm2Error(
        "tool_untrusted",
        `${toolPath}: ${candidate} is not a regular file`,
      );
    if (pending.length === 0 && kind === "dir" && !stats.isDirectory())
      throw new Tpm2Error(
        "tool_untrusted",
        `${toolPath}: ${candidate} is not a directory`,
      );
    resolved = candidate;
  }
  return resolved;
}

// Presence, not version. The order of refusals is part of the contract, since
// a host can fail several at once: no TPM2 device first (installing a package
// cannot help, so the host is unsupported), then missing tools, then a device
// this user cannot open. Between the last two, every tool must pass the trust
// walk (assertToolTrusted).
export function detectTpm2(host: Tpm2Host = {}): Tpm2Presence {
  return detectWith(host, {});
}

// TEST SEAM: detectTpm2 with a narrowed trust policy (see ToolTrustPolicy).
export function detectTpm2ForTest(
  host: Tpm2Host,
  policy: ToolTrustPolicy,
): Tpm2Presence {
  return detectWith(host, policy);
}

function detectWith(host: Tpm2Host, policy: ToolTrustPolicy): Tpm2Presence {
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
  // The trust walk comes after presence and before the device check: a tool
  // that fails it is refused whatever else is true of the host, and a later
  // PATH entry is never tried in its place.
  // Each tool, then each directory its child may search, once per detection.
  const directories = new Set<string>();
  for (const tool of requiredTools) {
    checkExecutable(found[tool] as string, policy);
    for (const directory of toolSearchPath(
      found[tool] as string,
      policy.systemDirectories,
    ))
      directories.add(directory);
  }
  for (const directory of directories) walkToolTrust(directory, policy, "dir");
  try {
    (host.openCheck ?? defaultOpenCheck)(device);
  } catch (error) {
    const code = errnoCode(error);
    if (code === "EACCES" || code === "EPERM")
      throw new Tpm2Error("tpm_not_accessible", accessRemedy(stats));
    throw new Tpm2Error("tpm_unusable", String(code ?? "unknown"));
  }
  return { device, tools: found as Record<Tpm2Tool, string> };
}

export interface ToolRun {
  readonly stdout: Uint8Array;
  readonly stderr: string;
}

// DEC-262 (a12): the environment a tool runs in is built, never inherited:
// the confined search path, the device Ward chose and a C locale. No LD_*,
// DYLD_*, HOME or parent PATH reaches it, so a trusted tool that runs a helper
// by name finds it only in a directory the walk examined. The key never
// travels here, and an inherited TPM2TOOLS_TCTI cannot point the tools at
// some other TPM.
function toolEnvironment(
  presence: Tpm2Presence,
  tool: Tpm2Tool,
): Record<string, string> {
  return {
    PATH: toolSearchPath(presence.tools[tool]).join(delimiter),
    TPM2TOOLS_TCTI: `device:${presence.device}`,
    LANG: "C",
    LC_ALL: "C",
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
    env: toolEnvironment(presence, tool),
    cwd: options.cwd,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });
}

// stdout is the tool's result, so a stream past the cap is refused. stderr is
// diagnostic only (verbose TSS2 logging can pass the cap on a failing or noisy
// tool, WCLI-157): it is truncated to the cap and drained, never refused.
async function readCapped(
  stream: ReadableStream<Uint8Array>,
  tool: string,
  overflow: "refuse" | "truncate" = "refuse",
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (size + value.length > maxToolOutputBytes) {
      if (overflow === "refuse") {
        await reader.cancel().catch(() => undefined);
        throw new Tpm2Error("tool_output_too_large", tool);
      }
      if (size < maxToolOutputBytes)
        chunks.push(value.subarray(0, maxToolOutputBytes - size));
      size = maxToolOutputBytes;
      continue;
    }
    size += value.length;
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
        readCapped(child.stderr, tool, "truncate"),
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
    // The file's contents are on disk before anything is published by name.
    fsyncSync(fd);
  } catch (error) {
    if (error instanceof Tpm2Error) throw error;
    throw new Tpm2Error("blob_not_user_private");
  } finally {
    closeSync(fd);
  }
}

// DEC-262 (a9): sealing. The 32-byte vault key reaches tpm2_create only on its
// stdin ("-i -"); it is never in argv, a file or the environment. The primary
// is recreated from one pinned template at each use (a saved context does not
// survive a reboot, and a changed tpm2-tools default would orphan the blob),
// and the sealed object has no PCR binding (a policy would stop it unsealing
// after the host restarts with nobody present). -Q keeps the tools' YAML off
// stdout (WCLI-157). The template and the attributes are part of the on-disk
// contract: the blob loads only under the primary it was created under.
export const vaultKeyBytes = 32;
export const sealedPublicName = "vault-key.pub";
export const sealedPrivateName = "vault-key.priv";
const primaryName = "primary.ctx";
const partialSuffix = ".partial";
export const primaryArgs = (context: string): string[] => [
  "-C",
  "o",
  "-g",
  "sha256",
  "-G",
  "ecc256:aes128cfb",
  "-a",
  "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda",
  "-c",
  context,
  "-Q",
];
export const sealedObjectAttributes = "fixedtpm|fixedparent|noda|userwithauth";

export interface SealedKey {
  readonly publicBlob: string;
  readonly privateBlob: string;
}

function removeIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if (errnoCode(error) !== "ENOENT")
      throw new Tpm2Error("directory_unusable", String(errnoCode(error)));
  }
}

export function fsyncDirectory(directory: string): void {
  let fd: number;
  try {
    fd = openSync(directory, fileConstants.O_RDONLY);
  } catch (error) {
    throw new Tpm2Error("directory_unusable", String(errnoCode(error)));
  }
  try {
    fsyncSync(fd);
  } catch (error) {
    throw new Tpm2Error("directory_unusable", String(errnoCode(error)));
  } finally {
    closeSync(fd);
  }
}

// Creates the storage primary into a user-private context file in directory
// and returns its path. Seal and unseal both use it, so the template is one,
// and it needs no preamble from its caller.
export async function createPrimary(
  presence: Tpm2Presence,
  directory: string,
  options: { timeoutMs?: number } = {},
): Promise<string> {
  preparePrivateDirectory(directory);
  const context = join(directory, primaryName);
  removeIfPresent(context);
  await runTool(presence, "tpm2_createprimary", primaryArgs(context), {
    cwd: directory,
    timeoutMs: options.timeoutMs,
  });
  adoptToolFile(context);
  return context;
}

function exists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return false;
    throw new Tpm2Error("directory_unusable", String(errnoCode(error)));
  }
}

// Seals the vault key to the TPM into directory (0700, this user's). These
// blobs are the only copy of the key, so the order is the safety: both are
// written under partial names, made 0600, verified and fsynced, then
// published by name with link(2), which refuses to replace, the public blob
// first and the private blob LAST. The private blob is the single commit
// marker: it is present only when the whole seal completed. A lone public
// blob is an interrupted earlier seal (a public area holds no key) and is
// removed; a private blob is a sealed key and is never replaced. A failure
// removes only what this call created.
//
// Caller contract: the caller holds the setup lock (SetupSession), so only one
// seal runs in the directory; the exclusive link(2) is the backstop, not the
// lock. A throw means NOT sealed, and nothing may be encrypted under the key
// until sealKey has returned.
export async function sealKey(
  presence: Tpm2Presence,
  key: Uint8Array,
  directory: string,
  options: { timeoutMs?: number } = {},
): Promise<SealedKey> {
  if (key.length !== vaultKeyBytes)
    throw new RangeError(`the vault key is ${vaultKeyBytes} bytes`);
  preparePrivateDirectory(directory);
  const publicBlob = join(directory, sealedPublicName);
  const privateBlob = join(directory, sealedPrivateName);
  if (exists(privateBlob))
    throw new Tpm2Error(
      "directory_unusable",
      `${privateBlob} already holds a sealed key; it is not replaced`,
    );
  // The commit marker is absent, so a public blob is a leftover.
  removeIfPresent(publicBlob);
  const partials = [
    `${publicBlob}${partialSuffix}`,
    `${privateBlob}${partialSuffix}`,
  ];
  const [publicPartial, privatePartial] = partials as [string, string];
  for (const path of partials) removeIfPresent(path);
  const published: string[] = [];
  try {
    const primary = await createPrimary(presence, directory, options);
    await runTool(
      presence,
      "tpm2_create",
      [
        "-C",
        primary,
        "-g",
        "sha256",
        "-a",
        sealedObjectAttributes,
        "-i",
        "-",
        "-u",
        publicPartial,
        "-r",
        privatePartial,
        "-Q",
      ],
      { cwd: directory, stdin: key, timeoutMs: options.timeoutMs },
    );
    for (const path of partials) adoptToolFile(path);
    for (const [partial, final] of [
      [publicPartial, publicBlob],
      [privatePartial, privateBlob],
    ] as const) {
      try {
        linkSync(partial, final);
      } catch (error) {
        const code = errnoCode(error);
        throw new Tpm2Error(
          "directory_unusable",
          `${final} could not be published (${String(code ?? "unknown")})${code === "EEXIST" ? "; another writer may be sealing here" : ""}`,
        );
      }
      published.push(final);
      try {
        unlinkSync(partial);
      } catch (error) {
        throw new Tpm2Error(
          "directory_unusable",
          `${partial} could not be removed after publication (${String(errnoCode(error) ?? "unknown")})`,
        );
      }
      // The public blob is durable before the private one can name the seal.
      fsyncDirectory(directory);
    }
  } catch (error) {
    for (const path of [...partials, ...published]) {
      try {
        unlinkSync(path);
      } catch {
        // Best effort: nothing here may mask the original failure.
      }
    }
    throw error;
  }
  return { publicBlob, privateBlob };
}

export interface LoadedKey {
  // A scratch directory private to this call, holding both contexts.
  readonly directory: string;
  readonly primary: string;
  readonly keyContext: string;
}

// Loads the sealed key object under the pinned primary and hands the contexts
// to use(); the session and the unseal itself are not here (they wait on the
// salted-session measurement). The sealed blobs are read only when they are
// exactly 0600 and this user's. Every call works in its own scratch directory,
// because unseals run concurrently (each Ward command needs the key) and must
// not share a context file; the scratch holds contexts only, never the key,
// and is removed when use() returns or throws. No seal lock is taken: a seal
// publishes the private blob last, so a key is either absent or complete.
export async function withLoadedKey<T>(
  presence: Tpm2Presence,
  directory: string,
  use: (loaded: LoadedKey) => Promise<T>,
  options: { timeoutMs?: number } = {},
): Promise<T> {
  if (!isAbsolute(directory)) throw new Tpm2Error("blob_not_user_private");
  requirePrivate(directory, "directory");
  const publicBlob = join(directory, sealedPublicName);
  const privateBlob = join(directory, sealedPrivateName);
  if (!exists(privateBlob) || !exists(publicBlob))
    throw new Tpm2Error("key_not_sealed", directory);
  requirePrivateFile(publicBlob);
  requirePrivateFile(privateBlob);
  let scratch: string;
  try {
    scratch = mkdtempSync(join(directory, "unseal-"));
  } catch (error) {
    throw new Tpm2Error("directory_unusable", String(errnoCode(error)));
  }
  try {
    const primary = await createPrimary(presence, scratch, options);
    const keyContext = join(scratch, "key.ctx");
    await runTool(
      presence,
      "tpm2_load",
      [
        "-C",
        primary,
        "-u",
        publicBlob,
        "-r",
        privateBlob,
        "-c",
        keyContext,
        "-Q",
      ],
      { cwd: scratch, timeoutMs: options.timeoutMs },
    );
    adoptToolFile(keyContext);
    return await use({ directory: scratch, primary, keyContext });
  } finally {
    try {
      rmSync(scratch, { recursive: true, force: true });
    } catch {
      // A leftover key.ctx can be unsealed, with the empty auth, by anyone who
      // can open /dev/tpmrm0 as this user, until a TPM reset. That is no more
      // than the blobs beside it in this same 0700 directory already allow. Re-check
      // this when 2b-2 adds session files to the scratch.
    }
  }
}

// True when the session-config printout shows the named attribute on. The real
// printout's format is unmeasured on hardware (T26 pins it), so this accepts
// the attribute named in a list or as "name: value" and fails closed on
// anything else: a missing name, or a value that reads as off, is not on.
function sessionAttributeOn(printout: string, name: string): boolean {
  const match = new RegExp(
    `(?<![a-z])${name}(?![a-z])\\s*(?::\\s*([^\\s|,]+))?`,
    "i",
  ).exec(printout);
  if (match === null) return false;
  const value = match[1]?.toLowerCase();
  return !(
    value === "0" ||
    value === "false" ||
    value === "no" ||
    value === "off" ||
    value === "clear" ||
    value === "clr"
  );
}

// Unseals the vault key (DEC-262 a9, opum-doc's slice-2 rules). Every call
// loads the key in its own scratch (withLoadedKey), starts a FRESH salted HMAC
// session (never a saved or reused one), requires the session's encrypt and
// decrypt attributes on before the unseal (off is the AC2 stop:
// session_not_encrypted), reads the 32 bytes from tpm2_unseal's stdout and
// nowhere else, and flushes the session at the end. Ward sets and verifies
// 0600 on the session file itself: the tools write it wider. stderr is never
// surfaced. The caller owns the returned bytes and should zero them after use.
export async function unsealKey(
  presence: Tpm2Presence,
  directory: string,
  options: { timeoutMs?: number } = {},
): Promise<Uint8Array> {
  return await withLoadedKey(
    presence,
    directory,
    async (loaded) => {
      const session = join(loaded.directory, "session.ctx");
      const run = (tool: Tpm2Tool, args: readonly string[]) =>
        runTool(presence, tool, args, {
          cwd: loaded.directory,
          timeoutMs: options.timeoutMs,
        });
      // A fresh session in a fresh scratch: nothing to reuse and nothing to
      // replace, so a leftover file is refused rather than overwritten.
      if (exists(session)) throw new Tpm2Error("directory_unusable", "session");
      await run("tpm2_startauthsession", [
        "--hmac-session",
        "-c",
        loaded.primary,
        "-S",
        session,
        "-Q",
      ]);
      try {
        adoptToolFile(session);
        await run("tpm2_sessionconfig", [
          "--enable-decrypt",
          "--enable-encrypt",
          session,
        ]);
        adoptToolFile(session);
        const printout = Buffer.from(
          (await run("tpm2_sessionconfig", [session])).stdout,
        ).toString("utf8");
        if (
          !sessionAttributeOn(printout, "decrypt") ||
          !sessionAttributeOn(printout, "encrypt")
        )
          throw new Tpm2Error("session_not_encrypted", "session");
        // Verified, never repaired, at the moment before the tool reads it.
        requirePrivateFile(session);
        const result = await run("tpm2_unseal", [
          "-c",
          loaded.keyContext,
          "-p",
          `session:${session}`,
        ]);
        const output = result.stdout;
        try {
          if (output.length !== vaultKeyBytes)
            throw new Tpm2Error("tool_failed", "tpm2_unseal");
          return Uint8Array.from(output);
        } finally {
          output.fill(0);
        }
      } finally {
        try {
          // Best effort: the kernel resource manager also drops the session
          // when this process's connection closes.
          await run("tpm2_flushcontext", [session]);
        } catch {
          // Nothing here may mask the unseal's own outcome.
        }
      }
    },
    options,
  );
}
