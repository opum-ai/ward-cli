// WCLI-21 slice 2a: the tpm2-tools subprocess boundary's presence detection,
// bounded spawning, 0600/0700 handling and lock-fd hygiene. Fake tpm2_*
// executables on a controlled PATH stand in for the tools: nothing here
// touches a real TPM, so the pipe and encryption properties against hardware
// stay with T26 (WCLI-21 AC2). Synthetic bytes and a temporary root only.
import "./support/no-real-keychain.ts";
import { dlopen } from "bun:ffi";
import { describe, expect, test } from "bun:test";
import {
  accessSync,
  chmodSync,
  closeSync,
  constants,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { acquireSetupSession } from "../src/adapters/setup-session.ts";
import {
  accessRemedy,
  adoptToolFile,
  defaultOpenCheck,
  defaultToolTimeoutMs,
  detectTpm2,
  maxToolOutputBytes,
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
const denied = () => {
  throw Object.assign(new Error("denied"), { code: "EACCES" });
};

function reasonOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    if (error instanceof Tpm2Error) return error.reason;
    throw error;
  }
  throw new Error("expected a Tpm2Error");
}

function refusal(action: () => unknown): Tpm2Error {
  try {
    action();
  } catch (error) {
    if (error instanceof Tpm2Error) return error;
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

  test("symlinked tools, as tpm2-tools 5.x installs them, resolve and run", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, {}, { multicall: true });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    expect(presence.tools.tpm2_unseal).toBe(join(bin, "tpm2_unseal"));
    await runTool(presence, "tpm2_unseal", ["-c", "x"]);
    // The multicall binary dispatched on the name it was spawned as.
    expect(record(records, "tpm2_unseal").args).toEqual(["-c", "x"]);
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
    const error = refusal(() => detectTpm2({ path: base, device: DEVICE }));
    expect(error.reason).toBe("tools_absent");
    expect(error.message).toContain("tpm2-tools");
    for (const tool of requiredTools) expect(error.detail).toContain(tool);
  });

  test("only the absent tool is named, and a non-executable one is absent", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    chmodSync(join(bin, "tpm2_unseal"), 0o644);
    expect(
      refusal(() => detectTpm2({ path: bin, device: DEVICE })).detail,
    ).toBe("tpm2_unseal");
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

  test("a device this user cannot open is not accessible, with the step to take", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const error = refusal(() =>
      detectTpm2({ path: bin, device: DEVICE, openCheck: denied }),
    );
    expect(error.reason).toBe("tpm_not_accessible");
    // /dev/null grants its group read and write, so the step is a group, read
    // from the device's own gid and not a fixed name.
    expect(error.detail).toMatch(/^join the .+ group$/);
  });

  test("the group is the device's own, and a mode without group access says host configuration", () => {
    const nameOf = (gid: number) => (gid === 77 ? "tpmgrp" : `gid ${gid}`);
    expect(accessRemedy({ gid: 77, mode: 0o20660 }, nameOf)).toBe(
      "join the tpmgrp group",
    );
    for (const mode of [0o20600, 0o20640, 0o20620]) {
      const remedy = accessRemedy({ gid: 0, mode }, nameOf);
      expect(remedy).toContain("host configuration");
      expect(remedy).not.toContain("join");
    }
  });

  test("an open that fails for another reason is not reported as absence", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const readOnly = () => {
      throw Object.assign(new Error("ro"), { code: "EROFS" });
    };
    const error = refusal(() =>
      detectTpm2({ path: bin, device: DEVICE, openCheck: readOnly }),
    );
    expect(error.reason).toBe("tpm_unusable");
    expect(error.detail).toBe("EROFS");
  });

  test("the order is TPM absent, then tools absent, then not accessible", () => {
    const { base, bin, records } = fresh();
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
});

// The default check really opens the device. access(2) would pass where a
// mandatory-access profile refuses the open, so the test needs a device this
// user truly cannot open. Candidates come from an explicit list of nodes whose
// open has no side effect when it is refused, never from a sweep of /dev: an
// open that an ACL or a capability lets through on /dev/watchdog arms a
// hardware timer, and a tty opened without O_NOCTTY can steal the terminal.
// Each must also fail by its mode for this user: owned by someone else, and
// granting us neither as other nor through a group of ours.
describe("the default device check really opens the device", () => {
  const root0 = process.getuid?.() === 0;
  const inertDevices = ["/dev/mem", "/dev/port", "/dev/kmsg", "/dev/bpf0"];
  function unopenableDevices(): string[] {
    const me = process.getuid?.();
    const groups = new Set(process.getgroups?.() ?? []);
    return inertDevices.filter((path) => {
      try {
        const stats = statSync(path);
        return (
          stats.isCharacterDevice() &&
          stats.uid !== me &&
          (stats.mode & 0o006) !== 0o006 &&
          !(groups.has(stats.gid) && (stats.mode & 0o060) === 0o060)
        );
      } catch {
        return false;
      }
    });
  }

  test("a world-writable device opens (the positive control)", () => {
    expect(() => defaultOpenCheck(DEVICE)).not.toThrow();
  });

  test("the check opens, not merely accesses: a directory passes access(2) and fails open(2)", () => {
    const { base } = fresh();
    expect(() =>
      accessSync(base, constants.R_OK | constants.W_OK),
    ).not.toThrow();
    expect(() => defaultOpenCheck(base)).toThrow(
      expect.objectContaining({ code: "EISDIR" }),
    );
  });

  test.skipIf(root0)(
    "a device this user cannot open is refused by the default path",
    () => {
      const candidates = unopenableDevices();
      // Linux CI must have one (/dev/mem and /dev/kmsg are root-only):
      // finding none there means the check proved nothing, so it fails.
      if (candidates.length === 0 && process.platform !== "linux") return;
      expect(candidates.length).toBeGreaterThan(0);
      const { bin, records } = fresh();
      installFakeTools(bin, records);
      let refused = 0;
      for (const device of candidates) {
        try {
          defaultOpenCheck(device);
        } catch {
          refused++;
          // A mode-denied device is always refused with EACCES.
          expect(reasonOf(() => detectTpm2({ path: bin, device }))).toBe(
            "tpm_not_accessible",
          );
        }
      }
      expect(refused).toBeGreaterThan(0);
    },
  );
});

// The module is the only place a key could fall back to something weaker, so
// its imports are an allow-list: nothing that writes a file, nothing from a
// keyring or a credential helper. A grep for a few write calls would not see
// Bun.write, appendFile or fs.promises.
describe("the module has no fallback path to disk, the keyring or systemd-creds", () => {
  const allowedFs = new Set([
    "accessSync",
    "closeSync",
    "constants",
    "fchmodSync",
    "fstatSync",
    "lstatSync",
    "mkdirSync",
    "openSync",
    "readFileSync",
    "statSync",
    "type Stats",
  ]);
  const allowedModules = new Set([
    "node:fs",
    "node:path",
    "./sqlite-vault-store.ts",
  ]);

  function violations(source: string): string[] {
    const found: string[] = [];
    for (const match of source.matchAll(
      /import\s*\{([^}]*)\}\s*from\s*"([^"]+)"/g,
    )) {
      const [, names = "", from = ""] = match;
      if (!allowedModules.has(from)) found.push(`module ${from}`);
      if (from === "node:fs")
        for (const raw of names.split(",")) {
          const name = raw.trim().replace(/\s+as\s+\w+$/, "");
          if (name !== "" && !allowedFs.has(name)) found.push(`fs ${name}`);
        }
    }
    if (
      /\bBun\.write\b|fs\/promises|\bwriteFile|\bappendFile|\bwriteSync|createWriteStream|keyutils|systemd-creds|keyring/i.test(
        source.replace(/\/\/.*$/gm, ""),
      )
    )
      found.push("write or credential call");
    return found;
  }

  test("the module's imports and calls are on the allow-list", () => {
    const source = readFileSync(
      join(import.meta.dir, "..", "src", "adapters", "tpm2-tools.ts"),
      "utf8",
    );
    expect(source.length).toBeGreaterThan(1_000);
    expect(violations(source)).toEqual([]);
  });

  test("control: the checker sees each way a fallback could be written", () => {
    expect(violations('import { writeSync } from "node:fs";')).toContain(
      "fs writeSync",
    );
    expect(violations('import { x } from "node:fs/promises";')).toContain(
      "module node:fs/promises",
    );
    expect(violations("await Bun.write(path, key);")).toHaveLength(1);
    expect(violations("appendFileSync(path, key);")).toHaveLength(1);
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

  test("output past the cap is refused, not buffered", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_unseal: "flood" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    expect(maxToolOutputBytes).toBeLessThan(64 * 1024);
    expect(
      await runTool(presence, "tpm2_unseal", []).catch((e) => e.reason),
    ).toBe("tool_output_too_large");
  });

  test("a tool that exits without reading a large stdin raises nothing unhandled", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_create: "no-read" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const unhandled: unknown[] = [];
    const listener = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", listener);
    try {
      await runTool(presence, "tpm2_create", [], {
        stdin: new Uint8Array(4 * 1024 * 1024),
      });
      await Bun.sleep(50);
    } finally {
      process.off("unhandledRejection", listener);
    }
    expect(unhandled).toEqual([]);
  });

  test("a hung tool is killed at the bound and refused as tool_timeout", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_unseal: "hang" });
    const presence = detectTpm2({ path: bin, device: DEVICE });
    const timers = createImmediateTimers();
    const started = performance.now();
    try {
      const reason = await runTool(presence, "tpm2_unseal", [], {
        timeoutMs: 150,
      }).catch((e) => e.reason);
      expect(reason).toBe("tool_timeout");
      expect(timers.delays).toEqual([150]);
      // The delay assertion cannot see a wait outside setTimeout, so a ceiling
      // stays beside it.
      expect(performance.now() - started).toBeLessThan(2_000);
    } finally {
      timers.restore();
    }
  });

  test(
    "the bound holds when a grandchild keeps the output pipe open",
    async () => {
      const { bin, records } = fresh();
      installFakeTools(bin, records, { tpm2_unseal: "grandchild" });
      const presence = detectTpm2({ path: bin, device: DEVICE });
      const pidFile = join(records, "grandchild.pid");
      const started = performance.now();
      try {
        // The bound has headroom over the fake's cold start, which must reach
        // the grandchild before the kill; the grandchild sleeps 60 s, so a
        // runTool that waited for EOF would run far past the ceiling.
        const reason = await runTool(presence, "tpm2_unseal", [], {
          timeoutMs: 2_500,
        }).catch((e) => e.reason);
        const elapsed = performance.now() - started;
        expect(existsSync(pidFile)).toBe(true);
        expect(reason).toBe("tool_timeout");
        expect(elapsed).toBeLessThan(15_000);
      } finally {
        if (existsSync(pidFile))
          process.kill(Number(readFileSync(pidFile, "utf8")), 9);
      }
    },
    { timeout: 30_000 },
  );

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
  test(
    "a FIFO at the path is refused at once and never blocks the open",
    async () => {
      const { base } = fresh();
      const fifo = join(base, "seal.priv");
      expect(Bun.spawnSync(["/usr/bin/mkfifo", fifo]).exitCode).toBe(0);
      // A blocking open cannot be timed out in-process, so the call runs in a
      // child with a deadline: a regression is a clean failure, not a hang.
      const adapter = join(
        import.meta.dir,
        "..",
        "src",
        "adapters",
        "tpm2-tools.ts",
      );
      const child = Bun.spawn(
        [
          process.execPath,
          "-e",
          `const m = await import(process.argv[1]);
try { m.adoptToolFile(process.argv[2]); console.log("accepted"); }
catch (e) { console.log(e.reason); }`,
          adapter,
          fifo,
        ],
        { stdout: "pipe", stderr: "pipe" },
      );
      const deadline = setTimeout(() => child.kill(9), 8_000);
      try {
        const out = await new Response(child.stdout).text();
        expect(out.trim()).toBe("blob_not_user_private");
      } finally {
        clearTimeout(deadline);
        child.kill(9);
      }
    },
    { timeout: 20_000 },
  );

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

  test("a directory that cannot be created is its own reason, not a tool failure", () => {
    const { base } = fresh();
    expect(
      reasonOf(() => preparePrivateDirectory(join(base, "no", "such", "dir"))),
    ).toBe("directory_unusable");
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
    const error = refusal(() => requirePrivateFile(blob));
    expect(error.reason).toBe("blob_not_user_private");
    expect(error.message).toBe("blob not user-private");
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
//
// The mechanism, measured below: Bun.spawn passes only the descriptors it is
// handed in stdio, and does not pass even one whose close-on-exec flag is
// clear. So what keeps the lock out of a tool is Bun.spawn, not openSync's
// O_CLOEXEC. The first control proves the acquirer sees a lock a child really
// holds as fd 3; the second proves a bare descriptor is not passed. A Bun
// upgrade that changes this turns one of them or the real test red.
describe("the setup lock is not inherited by a spawned tool", () => {
  const libc = dlopen(
    process.platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : "libc.so.6",
    {
      flock: { args: ["int", "int"], returns: "int" },
      dup: { args: ["int"], returns: "int" },
    },
  ).symbols;
  const flock = libc.flock as (fd: number, operation: number) => number;
  const dup = libc.dup as (fd: number) => number;
  const LOCK_EX_NB = 2 | 4;

  function heldLock(directory: string): number {
    mkdirSync(directory, { mode: 0o700 });
    const fd = openSync(join(directory, "setup.lock"), "w+", 0o600);
    expect(flock(fd, LOCK_EX_NB)).toBe(0);
    return fd;
  }

  async function refusedWhileChildLives(
    directory: string,
    spawnChild: () => { kill(signal: number): void; exited: Promise<number> },
    releaseParentCopies: () => void,
  ): Promise<void> {
    const child = spawnChild();
    releaseParentCopies();
    try {
      expect(() => acquireSetupSession(directory)).toThrow(
        expect.objectContaining({ code: "setup_in_progress" }),
      );
    } finally {
      child.kill(9);
      await child.exited;
    }
    acquireSetupSession(directory).release();
  }

  test("control: a lock a child holds as fd 3 is seen by the acquirer", async () => {
    const { base } = fresh();
    const directory = join(base, "ward");
    const fd = heldLock(directory);
    // An extra stdio slot, so the child holds the description as fd 3, the
    // slot an inherited lock fd would occupy.
    await refusedWhileChildLives(
      directory,
      () =>
        Bun.spawn(["/bin/sleep", "30"], {
          stdio: ["ignore", "ignore", "ignore", fd],
        }),
      () => closeSync(fd),
    );
  });

  test("measured: Bun.spawn does not pass a descriptor that lacks close-on-exec", async () => {
    const { base } = fresh();
    const directory = join(base, "ward");
    const fd = heldLock(directory);
    // dup(2) returns a descriptor with close-on-exec clear, sharing the lock.
    const bare = dup(fd);
    const child = Bun.spawn(["/bin/sleep", "30"], {
      stdin: "ignore",
      stdout: "ignore",
      stderr: "ignore",
    });
    closeSync(fd);
    closeSync(bare);
    try {
      // The child lives and holds nothing: Bun closes every descriptor it was
      // not asked to pass, whatever its close-on-exec flag.
      acquireSetupSession(directory).release();
      expect(child.exitCode).toBeNull();
    } finally {
      child.kill(9);
      await child.exited;
    }
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
      // The tool is alive, and the lock is free for the next setup.
      acquireSetupSession(directory).release();
      // Still alive after the re-acquire: had it died first, an inherited
      // descriptor would have closed and this would pass for no reason.
      expect(child.exitCode).toBeNull();
    } finally {
      child.kill(9);
      await child.exited;
    }
  });
});
