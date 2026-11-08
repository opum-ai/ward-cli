// WCLI-21 slice 2a: the tpm2-tools subprocess boundary's presence detection,
// bounded spawning, 0600/0700 handling and lock-fd hygiene. Fake tpm2_*
// executables on a controlled PATH stand in for the tools: nothing here
// touches a real TPM, so the pipe and encryption properties against hardware
// stay with T26 (WCLI-21 AC2). Synthetic bytes and a temporary root only.
import "./support/no-real-keychain.ts";
import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { dlopen } from "bun:ffi";
import { acquireSetupSession } from "../src/adapters/setup-session.ts";
import {
  adoptToolFile,
  defaultToolTimeoutMs,
  detectTpm2,
  preparePrivateDirectory,
  requiredTools,
  requirePrivateFile,
  runTool,
  spawnTool,
  Tpm2Error,
  tpmDevicePath,
} from "../src/adapters/tpm2-tools.ts";
import { installFakeTools } from "./fixtures/fake-tpm2/install.ts";
import { createImmediateTimers } from "./support/immediate-timers.ts";
import { createTempRoot } from "./support/temp-root.ts";

const root = createTempRoot("ward-tpm2-");
let cases = 0;
function fresh() {
  const base = join(root, `case-${++cases}`);
  mkdirSync(base);
  return {
    base,
    bin: join(base, "bin"),
    records: join(base, "records"),
  };
}
// A real character device that is world readable and writable.
const DEVICE = "/dev/null";

function reasonOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    if (error instanceof Tpm2Error) return error.reason;
    throw error;
  }
  throw new Error("expected a Tpm2Error");
}

function record(records: string, tool: string) {
  return JSON.parse(readFileSync(join(records, `${tool}.json`), "utf8")) as {
    args: string[];
    env: Record<string, string>;
    stdinHex: string;
  };
}

describe("presence is detected, not versioned, and refuses by name", () => {
  test("every required tool resolves to an absolute path", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const presence = detectTpm2({ path: bin, device: DEVICE });
    expect(Object.keys(presence.tools).sort()).toEqual(
      [...requiredTools].sort(),
    );
    for (const tool of requiredTools)
      expect(presence.tools[tool]).toBe(join(bin, tool));
  });

  test("the device is /dev/tpmrm0 unless a host says otherwise", () => {
    expect(tpmDevicePath).toBe("/dev/tpmrm0");
  });

  test("a missing device is TPM absent, even with every tool missing too", () => {
    const { base } = fresh();
    expect(
      reasonOf(() =>
        detectTpm2({ path: base, device: join(base, "no-such-device") }),
      ),
    ).toBe("tpm_absent");
  });

  test("a regular file planted at the device path is not a TPM", () => {
    const { bin, records, base } = fresh();
    installFakeTools(bin, records);
    const planted = join(base, "tpmrm0");
    writeFileSync(planted, "");
    expect(reasonOf(() => detectTpm2({ path: bin, device: planted }))).toBe(
      "tpm_absent",
    );
  });

  test("a missing tool is refused by name, naming the package", () => {
    const { base } = fresh();
    try {
      detectTpm2({ path: base, device: DEVICE });
      throw new Error("expected a refusal");
    } catch (error) {
      expect(error).toBeInstanceOf(Tpm2Error);
      const refusal = error as Tpm2Error;
      expect(refusal.reason).toBe("tools_absent");
      expect(refusal.message).toContain("tpm2-tools");
      for (const tool of requiredTools) expect(refusal.detail).toContain(tool);
    }
  });

  test("only the absent tool is named, and a non-executable one is absent", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    chmodSync(join(bin, "tpm2_unseal"), 0o644);
    try {
      detectTpm2({ path: bin, device: DEVICE });
      throw new Error("expected a refusal");
    } catch (error) {
      expect((error as Tpm2Error).detail).toBe("tpm2_unseal");
    }
  });

  test("a relative PATH entry is never searched", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const previous = process.cwd();
    process.chdir(bin);
    try {
      expect(reasonOf(() => detectTpm2({ path: ".", device: DEVICE }))).toBe(
        "tools_absent",
      );
    } finally {
      process.chdir(previous);
    }
  });

  test("a device this user cannot open names the tss group", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const denied = () => {
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    };
    try {
      detectTpm2({ path: bin, device: DEVICE, openCheck: denied });
      throw new Error("expected a refusal");
    } catch (error) {
      expect((error as Tpm2Error).reason).toBe("tpm_not_accessible");
      expect((error as Tpm2Error).message).toContain("tss");
    }
  });

  test("the order is TPM absent, then tools absent, then not accessible", () => {
    const { base, bin, records } = fresh();
    const denied = () => {
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    };
    // Tools missing and the device unopenable: the tools are named first.
    expect(
      reasonOf(() =>
        detectTpm2({ path: base, device: DEVICE, openCheck: denied }),
      ),
    ).toBe("tools_absent");
    installFakeTools(bin, records);
    expect(
      reasonOf(() =>
        detectTpm2({ path: bin, device: DEVICE, openCheck: denied }),
      ),
    ).toBe("tpm_not_accessible");
  });

  test("no fallback to a file, the keyring or systemd-creds exists in the module", () => {
    const source = readFileSync(
      join(import.meta.dir, "..", "src", "adapters", "tpm2-tools.ts"),
      "utf8",
    );
    expect(source.length).toBeGreaterThan(1_000);
    expect(source).not.toMatch(/keyutils|systemd-creds|writeFileSync|keyring/i);
  });
});

describe("a tool runs bounded, by absolute path, in a minimal environment", () => {
  test("the child sees the search path and the device and nothing else", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const key = "WARD_PROBE_ENV_SECRET";
    process.env[key] = "synthetic-env-value";
    process.env.TPM2TOOLS_TCTI = "swtpm:host=attacker";
    try {
      await runTool(presence, "tpm2_create", ["-i", "-"]);
    } finally {
      delete process.env[key];
      delete process.env.TPM2TOOLS_TCTI;
    }
    const { env } = record(records, "tpm2_create");
    expect(env.PATH).toBe(bin);
    expect(env.TPM2TOOLS_TCTI).toBe(`device:${DEVICE}`);
    expect(env).not.toHaveProperty(key);
    expect(env).not.toHaveProperty("HOME");
  });

  test("stdin carries bytes to the tool and argv carries none of them", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
    await runTool(presence, "tpm2_create", ["-i", "-"], { stdin: bytes });
    const seen = record(records, "tpm2_create");
    expect(seen.stdinHex).toBe(Buffer.from(bytes).toString("hex"));
    expect(seen.args).toEqual(["-i", "-"]);
  });

  test("a failing tool is tool_failed", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_load: "fail" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    expect(
      await runTool(presence, "tpm2_load", []).catch((e) => e.reason),
    ).toBe("tool_failed");
  });

  test("a hung tool is killed at the bound and refused as tool_timeout", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_unseal: "hang" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const timers = createImmediateTimers();
    try {
      const reason = await runTool(presence, "tpm2_unseal", [], {
        timeoutMs: 150,
      }).catch((e) => e.reason);
      expect(reason).toBe("tool_timeout");
      expect(timers.delays).toEqual([150]);
    } finally {
      timers.restore();
    }
  });

  test("the default bound is 10 s and is the one applied", async () => {
    expect(defaultToolTimeoutMs).toBe(10_000);
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_unseal: "hang" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const timers = createImmediateTimers();
    try {
      await runTool(presence, "tpm2_unseal", []).catch(() => undefined);
      expect(timers.delays).toEqual([10_000]);
    } finally {
      timers.restore();
    }
  });
});

describe("Ward sets and verifies user-private modes itself", () => {
  test("the directory is created 0700 and an existing 0700 one is accepted", () => {
    const { base } = fresh();
    const directory = join(base, "tpm");
    preparePrivateDirectory(directory);
    expect(statSync(directory).mode & 0o777).toBe(0o700);
    preparePrivateDirectory(directory);
  });

  test("a wider directory, a symlink and a relative path are refused", () => {
    const { base } = fresh();
    const wide = join(base, "wide");
    mkdirSync(wide, { mode: 0o755 });
    chmodSync(wide, 0o755);
    expect(reasonOf(() => preparePrivateDirectory(wide))).toBe(
      "blob_not_user_private",
    );
    const real = join(base, "real");
    mkdirSync(real, { mode: 0o700 });
    const link = join(base, "link");
    symlinkSync(real, link);
    expect(reasonOf(() => preparePrivateDirectory(link))).toBe(
      "blob_not_user_private",
    );
    expect(reasonOf(() => preparePrivateDirectory("relative/dir"))).toBe(
      "blob_not_user_private",
    );
  });

  test("a file a tool wrote 0660 is made 0600 and verified", async () => {
    const { bin, records, base } = fresh();
    installFakeTools(bin, records, { tpm2_create: "touch-wide" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const blob = join(base, "seal.priv");
    await runTool(presence, "tpm2_create", [blob]);
    expect(statSync(blob).mode & 0o777).toBe(0o660);
    adoptToolFile(blob);
    expect(statSync(blob).mode & 0o777).toBe(0o600);
    requirePrivateFile(blob);
  });

  test("a wider existing blob refuses as not user-private and is not repaired", () => {
    const { base } = fresh();
    const blob = join(base, "seal.pub");
    writeFileSync(blob, "blob");
    chmodSync(blob, 0o644);
    try {
      requirePrivateFile(blob);
      throw new Error("expected a refusal");
    } catch (error) {
      expect((error as Tpm2Error).reason).toBe("blob_not_user_private");
      expect((error as Tpm2Error).message).toBe("blob not user-private");
    }
    expect(statSync(blob).mode & 0o777).toBe(0o644);
    expect(reasonOf(() => requirePrivateFile(join(base, "absent")))).toBe(
      "blob_not_user_private",
    );
  });

  test("a symlink is never adopted, and its target is left alone", () => {
    const { base } = fresh();
    const target = join(base, "target");
    writeFileSync(target, "x");
    chmodSync(target, 0o644);
    const link = join(base, "link");
    symlinkSync(target, link);
    expect(reasonOf(() => adoptToolFile(link))).toBe("blob_not_user_private");
    expect(reasonOf(() => requirePrivateFile(link))).toBe(
      "blob_not_user_private",
    );
    expect(statSync(target).mode & 0o777).toBe(0o644);
  });
});

// Round-1 finding 7 of #294: a tool spawned while the setup lock is held must
// not keep the lock after the parent releases it. The lock lives on the open
// file description, so an inherited descriptor would hold it.
describe("the setup lock is not inherited by a spawned tool", () => {
  const libc = dlopen(
    process.platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : "libc.so.6",
    { flock: { args: ["int", "int"], returns: "int" } },
  ).symbols.flock as (fd: number, operation: number) => number;
  const LOCK_EX_NB = 2 | 4;

  test("control: a lock that a child really holds is seen by the acquirer", async () => {
    const { base } = fresh();
    const directory = join(base, "ward");
    mkdirSync(directory, { mode: 0o700 });
    const lockPath = join(directory, "setup.lock");
    const fd = openSync(lockPath, "w+", 0o600);
    expect(libc(fd, LOCK_EX_NB)).toBe(0);
    // The child gets the descriptor as its stdin, so it shares the open file
    // description and holds the flock after this process closes its copy.
    const child = Bun.spawn(["/bin/sleep", "30"], { stdin: fd });
    closeSync(fd);
    try {
      expect(() => acquireSetupSession(directory)).toThrow(
        expect.objectContaining({ code: "setup_in_progress" }),
      );
    } finally {
      child.kill(9);
      await child.exited;
    }
    acquireSetupSession(directory).release();
  });

  test("a tool spawned through the adapter does not hold a released lock", async () => {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_unseal: "hang" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const directory = join(base, "ward");
    const session = acquireSetupSession(directory);
    const child = spawnTool(presence, "tpm2_unseal", []);
    try {
      session.release();
      expect(child.exitCode).toBeNull();
      // The tool is alive, and the lock is free for the next setup.
      acquireSetupSession(directory).release();
    } finally {
      child.kill(9);
      await child.exited;
    }
  });
});
