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
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, delimiter, dirname, join, relative } from "node:path";
import { acquireSetupSession } from "../src/adapters/setup-session.ts";
import {
  accessRemedy,
  adoptToolFile,
  assertToolTrusted,
  walkToolTrustForTest,
  defaultOpenCheck,
  defaultToolTimeoutMs,
  detectTpm2,
  detectTpm2ForTest,
  diagnoseTpm2ForTest,
  maxToolOutputBytes,
  preparePrivateDirectory,
  diagnosticTool,
  requiredTools,
  requirePrivateFile,
  runTool,
  safeOpenFlags,
  sealedPrivateName,
  sealedPublicName,
  sealKey,
  classifySessionPrintoutForTest,
  tpm2ErrorCodes,
  wardErrorFor,
  unsealKey,
  withLoadedKey,
  spawnTool,
  Tpm2Error,
  type Tpm2Host,
  type Tpm2Presence,
  type Tpm2Tool,
  type Tpm2Reason,
  tpm2StateFor,
  keyUnloadableHint,
  keyUnloadableSummary,
  tpmDevicePath,
} from "../src/adapters/tpm2-tools.ts";
import { errorCatalog } from "../src/contract/errors.ts";
import { installFakeTools } from "./fixtures/fake-tpm2/install.ts";
import { createImmediateTimers } from "./support/immediate-timers.ts";
import { createTempRoot } from "./support/temp-root.ts";

const root = createTempRoot("ward-tpm2-");
// The test files live under a temp directory the test does not own (a
// sticky, world-writable /tmp on Linux), so the trust walk starts at the
// test's private root. Production leaves trustRoot unset and walks to /.
function detect(host: Tpm2Host = {}, trustedUids?: readonly number[]) {
  return detectTpm2ForTest(host, { trustRoot: root, trustedUids });
}
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

// Kills the grandchild a fake left running, from the pid file the fake wrote.
// The file can be absent, empty (the fake killed between creating it and
// writing it) or garbled, and process.kill(0, 9) would signal the runner's own
// process group, so only a positive integer is ever signalled.
function killGrandchild(pidFile: string): void {
  try {
    const text = readFileSync(pidFile, "utf8").trim();
    const pid = Number(text);
    // Digits only and within a signed 32-bit pid: a larger value could wrap to
    // 0 or a negative number in a coercion and signal a process group.
    if (/^\d+$/.test(text) && pid > 0 && pid <= 0x7fffffff)
      process.kill(pid, 9);
  } catch {
    // No pid file, or the grandchild is already gone.
  }
}

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
    tool: string;
    args: string[];
    env: Record<string, string>;
    stdinHex: string;
  };
}

describe("presence is detected, not versioned, and refuses by name", () => {
  test("every required tool resolves to an absolute path", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const presence = detect({ path: bin, device: DEVICE });
    expect(Object.keys(presence.tools).sort()).toEqual(
      [...requiredTools].sort(),
    );
    for (const tool of requiredTools)
      expect(presence.tools[tool]).toBe(join(bin, tool));
  });

  test("symlinked tools, as tpm2-tools 5.x installs them, resolve and run", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, {}, { multicall: true });
    const presence = detect({ path: bin, device: DEVICE });
    expect(presence.tools.tpm2_unseal).toBe(join(bin, "tpm2_unseal"));
    await runTool(presence, "tpm2_unseal", ["-p", "x"]);
    // The multicall binary dispatched on the name it was spawned as.
    expect(record(records, "tpm2_unseal").args).toEqual(["-p", "x"]);
  });

  test("the device is /dev/tpmrm0 unless a host says otherwise", () => {
    expect(tpmDevicePath).toBe("/dev/tpmrm0");
  });

  test("a missing device is TPM absent, even with every tool missing too", () => {
    const { base } = fresh();
    expect(
      reasonOf(() =>
        detect({ path: base, device: join(base, "no-such-device") }),
      ),
    ).toBe("tpm_absent");
  });

  test("a regular file planted at the device path is not a TPM", () => {
    const { bin, records, base } = fresh();
    installFakeTools(bin, records);
    const planted = join(base, "tpmrm0");
    writeFileSync(planted, "");
    expect(reasonOf(() => detect({ path: bin, device: planted }))).toBe(
      "tpm_absent",
    );
  });

  test("a missing tool is refused by name, naming the package", () => {
    const { base } = fresh();
    const error = refusal(() => detect({ path: base, device: DEVICE }));
    expect(error.reason).toBe("tools_absent");
    expect(error.message).toContain("tpm2-tools");
    for (const tool of requiredTools) expect(error.detail).toContain(tool);
  });

  test("only the absent tool is named, and a non-executable one is absent", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    chmodSync(join(bin, "tpm2_unseal"), 0o644);
    expect(refusal(() => detect({ path: bin, device: DEVICE })).detail).toBe(
      "tpm2_unseal",
    );
  });

  test("a relative PATH entry is never searched", () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const previous = process.cwd();
    process.chdir(bin);
    try {
      expect(reasonOf(() => detect({ path: ".", device: DEVICE }))).toBe(
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
      detect({ path: bin, device: DEVICE, openCheck: denied }),
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
      detect({ path: bin, device: DEVICE, openCheck: readOnly }),
    );
    expect(error.reason).toBe("tpm_unusable");
    expect(error.detail).toBe("EROFS");
  });

  test("the order is TPM absent, then tools absent, then not accessible", () => {
    const { base, bin, records } = fresh();
    // Tools missing and the device unopenable: the tools are named first.
    expect(
      reasonOf(() => detect({ path: base, device: DEVICE, openCheck: denied })),
    ).toBe("tools_absent");
    installFakeTools(bin, records);
    expect(
      reasonOf(() => detect({ path: bin, device: DEVICE, openCheck: denied })),
    ).toBe("tpm_not_accessible");
  });
});

// DEC-262 (a10): a tool receives the vault key on stdin, so it is trusted only
// after an ownership and mode walk of the chain that decides which file runs.
// Trees are built under the test's private root (trustRoot), each directory
// chmod'ed explicitly so the umask cannot decide the outcome. Another uid's
// file cannot be created without root, so that case narrows the trusted uids
// instead: a file owned by this user is then another uid's file.
describe("a tool is trusted only after an ownership and mode walk", () => {
  const root0 = process.getuid?.() === 0;
  function dir(path: string, mode: number): string {
    mkdirSync(path, { recursive: true });
    chmodSync(path, mode);
    return path;
  }
  function trustedTree(name: string) {
    const base = dir(join(fresh().base, name), 0o755);
    const bin = dir(join(base, "bin"), 0o755);
    const records = join(base, "records");
    installFakeTools(bin, records);
    return { base, bin, records };
  }
  const walk = (path: string) =>
    walkToolTrustForTest(path, { trustRoot: root });
  function untrusted(action: () => unknown): Tpm2Error {
    const error = refusal(action);
    expect(error.reason).toBe("tool_untrusted");
    return error;
  }

  test("accept: a symlinked multicall tool in a 0755 tree, relative and absolute links", async () => {
    const { bin, records } = fresh();
    dir(bin, 0o755);
    installFakeTools(bin, records, {}, { multicall: true });
    chmodSync(records, 0o755);
    expect(() => walk(join(bin, "tpm2_create"))).not.toThrow();
    // An absolute link to the same target is followed the same way.
    const other = dir(join(fresh().base, "bin"), 0o755);
    symlinkSync(join(bin, "tpm2"), join(other, "tpm2_create"));
    expect(() => walk(join(other, "tpm2_create"))).not.toThrow();
    const presence = detect({ path: bin, device: DEVICE });
    await runTool(presence, "tpm2_create", []);
    expect(record(records, "tpm2_create").tool).toBe("tpm2_create");
  });

  test("accept: a real system binary under the default policy, from / (positive control)", () => {
    // Walks /bin/sh to its final file with no trustRoot: the real chain of a
    // host, symlinks included (/bin and sh are links on many Linux hosts).
    expect(() => assertToolTrusted("/bin/sh")).not.toThrow();
  });

  test("reject: a group-writable PATH directory ahead of the good one, never falling through", () => {
    const good = trustedTree("good");
    const bad = trustedTree("bad");
    chmodSync(bad.bin, 0o775);
    const error = untrusted(() =>
      detect({ path: `${bad.bin}:${good.bin}`, device: DEVICE }),
    );
    expect(error.detail).toContain(bad.bin);
    expect(error.detail).toContain("0775");
    expect(error.detail).toContain("group- or world-writable");
    // The good tool later on PATH was not used in its place and nothing ran.
    expect(() => detect({ path: good.bin, device: DEVICE })).not.toThrow();
    expect(existsSync(join(bad.records, "tpm2_create.json"))).toBe(false);
  });

  test("reject: a world-writable sticky directory is not excused by the sticky bit", () => {
    const tree = trustedTree("sticky");
    // chmodSync drops the sticky bit under Bun, so the shell sets it, and the
    // precondition is asserted: a test that never made the directory sticky
    // would pass without testing the sticky rule.
    expect(Bun.spawnSync(["/bin/chmod", "1777", tree.bin]).exitCode).toBe(0);
    expect(statSync(tree.bin).mode & 0o1000).toBe(0o1000);
    const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
    expect(error.detail).toContain(tree.bin);
    expect(error.detail).toContain("1777");
  });

  test("reject: a good link whose target sits in a writable directory", () => {
    const good = trustedTree("linkgood");
    const evil = dir(join(fresh().base, "evil"), 0o775);
    writeFileSync(join(evil, "tpm2"), "#!/bin/sh\n");
    chmodSync(join(evil, "tpm2"), 0o755);
    const link = join(good.bin, "tpm2_unseal");
    rmSync(link);
    symlinkSync(join(evil, "tpm2"), link);
    const error = untrusted(() => walk(link));
    expect(error.detail).toContain(evil);
    expect(error.detail).toContain("0775");
  });

  test("reject: a tool file that is itself group-writable", () => {
    const tree = trustedTree("filewide");
    chmodSync(join(tree.bin, "tpm2_create"), 0o775);
    const error = untrusted(() => walk(join(tree.bin, "tpm2_create")));
    expect(error.detail).toContain(join(tree.bin, "tpm2_create"));
  });

  test.skipIf(root0)(
    "reject: another uid's file (this user is not trusted)",
    () => {
      const tree = trustedTree("otheruid");
      const error = untrusted(() =>
        detect({ path: tree.bin, device: DEVICE }, [0]),
      );
      expect(error.detail).toContain(`uid ${process.getuid?.()}`);
      expect(error.detail).toContain("untrusted owner");
    },
  );

  test("reject: a symlink loop, and a path through a file", () => {
    const { bin } = trustedTree("loop");
    symlinkSync(join(bin, "b"), join(bin, "a"));
    symlinkSync(join(bin, "a"), join(bin, "b"));
    expect(untrusted(() => walk(join(bin, "a"))).detail).toContain(
      "too many symlinks",
    );
    expect(
      untrusted(() => walk(join(bin, "tpm2_create", "x"))).detail,
    ).toContain("not a directory");
  });

  test("the refusal names the tool, the first offender with owner and mode, and the remedy", () => {
    const tree = trustedTree("message");
    chmodSync(tree.bin, 0o775);
    const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
    expect(error.message).toContain("not trusted to receive the vault key");
    expect(error.detail).toContain(join(tree.bin, "tpm2_createprimary"));
    expect(error.detail).toContain(`uid ${process.getuid?.()}`);
    expect(error.detail).toContain("put a trusted tpm2-tools first on PATH");
  });

  test("the walk refuses before the device check, and after presence", () => {
    const tree = trustedTree("order");
    chmodSync(tree.bin, 0o775);
    expect(
      reasonOf(() =>
        detect({ path: tree.bin, device: DEVICE, openCheck: denied }),
      ),
    ).toBe("tool_untrusted");
    expect(
      reasonOf(() =>
        detect({
          path: tree.bin,
          device: join(tree.base, "no-such-device"),
        }),
      ),
    ).toBe("tpm_absent");
  });

  test("a directory above the trust root is not examined, one below is", () => {
    const outer = dir(join(fresh().base, "outer"), 0o777);
    const inner = dir(join(outer, "inner"), 0o755);
    const bin = dir(join(inner, "bin"), 0o755);
    writeFileSync(join(bin, "t"), "x");
    chmodSync(join(bin, "t"), 0o755);
    expect(() =>
      walkToolTrustForTest(join(bin, "t"), { trustRoot: inner }),
    ).not.toThrow();
    const error = untrusted(() =>
      walkToolTrustForTest(join(bin, "t"), { trustRoot: outer }),
    );
    expect(error.detail).toContain(`${outer} is owned by`);
    expect(error.detail).toContain("0777");
  });

  // DEC-262 (a12): a script tool's shebang interpreter is walked too.
  const script = (path: string, text: string | Buffer) => {
    writeFileSync(path, text);
    chmodSync(path, 0o755);
  };

  test("accept: a script tool whose interpreter is a regular binary at a walked absolute path, and env", () => {
    const tree = trustedTree("shebang-ok");
    script(join(tree.bin, "tpm2_create"), "#!/bin/sh\nexit 0\n");
    expect(() => detect({ path: tree.bin, device: DEVICE })).not.toThrow();
    script(join(tree.bin, "tpm2_create"), "#!/usr/bin/env sh\nexit 0\n");
    expect(() => detect({ path: tree.bin, device: DEVICE })).not.toThrow();
  });

  test("reject: an interpreter in a writable directory", () => {
    const tree = trustedTree("shebang-writable");
    const loose = dir(join(tree.base, "loose"), 0o777);
    script(join(loose, "sh"), "#!/bin/sh\nexit 0\n");
    script(join(tree.bin, "tpm2_create"), `#!${join(loose, "sh")}\n`);
    const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
    expect(error.detail).toContain(`${loose} is owned by`);
  });

  test("reject: a relative interpreter, and an empty one", () => {
    const tree = trustedTree("shebang-relative");
    for (const line of ["#!sh", "#!./sh", "#! ", "#!"]) {
      script(join(tree.bin, "tpm2_create"), `${line}\n`);
      const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
      expect(error.detail).toContain("not an absolute path");
    }
  });

  test("reject: an interpreter that is itself a script, even in a walked directory", () => {
    const tree = trustedTree("shebang-script-interpreter");
    script(join(tree.bin, "inner"), "#!/bin/sh\nexit 0\n");
    script(join(tree.bin, "tpm2_create"), `#!${join(tree.bin, "inner")}\n`);
    const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
    expect(error.detail).toContain(join(tree.bin, "inner"));
    expect(error.detail).toContain('is itself a "#!" script');
    // Host-independent control: a real interpreter is a binary, not a script.
    expect(readFileSync("/bin/sh").subarray(0, 2).toString()).not.toBe("#!");
  });

  // DEC-262 (a14): after env, the rest of the line is ONE bare command name.
  const envRefused = [
    "env /bin/sh",
    "env -S PATH=/x sh",
    "env A=B sh",
    "env -i sh",
    "env",
    "env ",
    "env sh\r",
    "env sh x/y",
  ];
  test("reject: env given anything but one bare command name", () => {
    const tree = trustedTree("env-args");
    for (const line of envRefused) {
      script(join(tree.bin, "tpm2_create"), `#!/usr/bin/env${line.slice(3)}\n`);
      const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
      expect([line, error.detail]).toEqual([
        line,
        expect.stringContaining("one bare command name"),
      ]);
    }
  });

  test("accept: env with one bare command name, spaces and tabs around it", () => {
    const tree = trustedTree("env-ok");
    for (const line of ["env sh", "env \t sh \t"]) {
      script(join(tree.bin, "tpm2_create"), `#!/usr/bin/${line}\n`);
      expect(() => detect({ path: tree.bin, device: DEVICE })).not.toThrow();
    }
  });

  test("reject: env by a multicall shape or an alias gets the same argument check", () => {
    const tree = trustedTree("env-shapes");
    // Written name env, final file not named env (busybox, uutils).
    symlinkSync("/bin/sh", join(tree.bin, "env"));
    script(
      join(tree.bin, "tpm2_create"),
      `#!${join(tree.bin, "env")} -S PATH=/x sh\n`,
    );
    expect(
      untrusted(() => detect({ path: tree.bin, device: DEVICE })).detail,
    ).toContain("one bare command name");
    // Written name not env, final file env (an alias). The host's env must be
    // named env for this to be the alias shape.
    expect(basename(realpathSync("/usr/bin/env"))).toBe("env");
    symlinkSync("/usr/bin/env", join(tree.bin, "myenv"));
    script(
      join(tree.bin, "tpm2_create"),
      `#!${join(tree.bin, "myenv")} -S PATH=/x sh\n`,
    );
    expect(
      untrusted(() => detect({ path: tree.bin, device: DEVICE })).detail,
    ).toContain("one bare command name");
    script(join(tree.bin, "tpm2_create"), `#!${join(tree.bin, "myenv")} sh\n`);
    expect(() => detect({ path: tree.bin, device: DEVICE })).not.toThrow();
  });

  test("a helper findable only on the parent's PATH is not found by a tool", async () => {
    const tree = trustedTree("helper");
    const elsewhere = dir(join(tree.base, "elsewhere"), 0o755);
    script(join(elsewhere, "ward-helper-probe"), "#!/bin/sh\nexit 0\n");
    script(
      join(tree.bin, "tpm2_create"),
      "#!/bin/sh\nexec ward-helper-probe\n",
    );
    // The detection path carries the helper's directory too, so a child that
    // were given presence.path (or the parent's PATH) would find the helper.
    const presence = detect({
      path: `${tree.bin}${delimiter}${elsewhere}`,
      device: DEVICE,
    });
    const before = process.env.PATH;
    process.env.PATH = `${elsewhere}${delimiter}${before ?? ""}`;
    try {
      // Positive control: the helper really is on the parent's PATH.
      expect(Bun.which("ward-helper-probe", { PATH: process.env.PATH })).toBe(
        join(elsewhere, "ward-helper-probe"),
      );
      await expect(runTool(presence, "tpm2_create", [])).rejects.toMatchObject({
        reason: "tool_failed",
      });
      // The same helper beside the tool is found: the tool's own directory
      // is on the built PATH.
      script(join(tree.bin, "ward-helper-probe"), "#!/bin/sh\nexit 0\n");
      await runTool(presence, "tpm2_create", []);
    } finally {
      if (before === undefined) delete process.env.PATH;
      else process.env.PATH = before;
    }
  });

  test("reject: /usr/bin and /bin stand-ins are walked too, and a clean one passes", () => {
    const tree = trustedTree("system-dirs");
    const loose = dir(join(tree.base, "loose-system"), 0o777);
    const clean = dir(join(tree.base, "clean-system"), 0o755);
    const host = { path: tree.bin, device: DEVICE };
    const policy = { trustRoot: root };
    const error = untrusted(() =>
      detectTpm2ForTest(host, { ...policy, systemDirectories: [clean, loose] }),
    );
    expect(error.detail).toContain(`${loose} is owned by`);
    expect(() =>
      detectTpm2ForTest(host, { ...policy, systemDirectories: [clean] }),
    ).not.toThrow();
  });

  test("reject: a system directory that is a file, not a directory", () => {
    const tree = trustedTree("system-notdir");
    script(join(tree.base, "afile"), "x");
    const error = untrusted(() =>
      detectTpm2ForTest(
        { path: tree.bin, device: DEVICE },
        { trustRoot: root, systemDirectories: [join(tree.base, "afile")] },
      ),
    );
    expect(error.detail).toContain("is not a directory");
  });

  test.skipIf(root0)(
    "reject: a tool this user cannot read is refused, not skipped",
    () => {
      const tree = trustedTree("execute-only");
      chmodSync(join(tree.bin, "tpm2_create"), 0o111);
      const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
      expect(error.detail).toContain("cannot be read (EACCES)");
    },
  );

  test("reject: a shebang the kernel would read differently", () => {
    const tree = trustedTree("shebang-bytes");
    const cases: [string, Buffer, string][] = [
      ["CRLF", Buffer.from("#!/bin/sh\r\nexit 0\n"), "printable ASCII"],
      [
        "leading 0xA0",
        Buffer.from([0x23, 0x21, 0xa0, 0x2f, 0x73, 0x0a]),
        "printable ASCII",
      ],
      [
        "a high byte inside",
        Buffer.from([0x23, 0x21, 0x2f, 0x62, 0xe9, 0x6e, 0x0a]),
        "printable ASCII",
      ],
      [
        "a line with no end",
        Buffer.from(`#!/${"a".repeat(300)}`),
        "longer than the kernel",
      ],
    ];
    for (const [name, bytes, expected] of cases) {
      script(join(tree.bin, "tpm2_create"), bytes);
      const error = untrusted(() => detect({ path: tree.bin, device: DEVICE }));
      expect([name, error.detail]).toEqual([
        name,
        expect.stringContaining(expected),
      ]);
    }
    // Spaces and tabs before and after the interpreter are the kernel's own.
    script(join(tree.bin, "tpm2_create"), "#! \t/bin/sh -e\nexit 0\n");
    expect(() => detect({ path: tree.bin, device: DEVICE })).not.toThrow();
  });

  test("a missing element is refused by name with its errno", () => {
    const { bin } = trustedTree("missing");
    const error = untrusted(() => walk(join(bin, "nope")));
    expect(error.detail).toContain(join(bin, "nope"));
    expect(error.detail).toContain("ENOENT");
  });

  // Relative link targets resolve against the link's own directory (DEC-262).
  test("accept: a relative link to a tool beside it", () => {
    const { bin } = trustedTree("rel-ok");
    symlinkSync("tpm2_create", join(bin, "alias"));
    expect(() => walk(join(bin, "alias"))).not.toThrow();
  });

  test("reject: a relative link whose ../ target sits in a writable directory", () => {
    const tree = trustedTree("rel-bad");
    const loose = dir(join(tree.base, "loose"), 0o777);
    writeFileSync(join(loose, "t"), "x");
    chmodSync(join(loose, "t"), 0o755);
    symlinkSync("../loose/t", join(tree.bin, "viaparent"));
    const error = untrusted(() => walk(join(tree.bin, "viaparent")));
    expect(error.detail).toContain(`${loose} is owned by`);
    expect(error.detail).toContain("0777");
  });

  // The production default, with no test policy: the whole chain to / counts.
  // Both production cases build under the checkout, whose ancestors the tests
  // assert are clean, so neither depends on how the host's temp directory is set.
  const topmostOffender = (path: string): string | undefined => {
    const trusted = [0, process.getuid?.() ?? 0];
    let offender: string | undefined;
    for (let at = realpathSync(path); ; at = dirname(at)) {
      const stats = lstatSync(at);
      if ((stats.mode & 0o022) !== 0 || !trusted.includes(stats.uid))
        offender = at;
      if (at === "/") return offender;
    }
  };

  test("reject: the production detectTpm2 refuses a tree under a world-writable ancestor", () => {
    // A 0777 directory inside the checkout stands in for a sticky /tmp, so the
    // reject runs on every host; the checkout's own ancestors are asserted clean.
    const loose = mkdtempSync(join(process.cwd(), ".ward-trust-test-"));
    try {
      expect(topmostOffender(dirname(loose))).toBeUndefined();
      chmodSync(loose, 0o777);
      const bin = dir(join(loose, "bin"), 0o755);
      installFakeTools(bin, join(loose, "records"));
      const error = untrusted(() => detectTpm2({ path: bin, device: DEVICE }));
      expect(error.detail).toContain(`${realpathSync(loose)} is owned by`);
      expect(error.detail).toContain("0777");
    } finally {
      rmSync(loose, { recursive: true, force: true });
    }
  });

  test("accept: the production detectTpm2 passes a clean owned tree inside the checkout", () => {
    const base = mkdtempSync(join(process.cwd(), ".ward-trust-test-"));
    try {
      chmodSync(base, 0o755);
      const bin = dir(join(base, "bin"), 0o755);
      installFakeTools(bin, join(base, "records"));
      expect(topmostOffender(base)).toBeUndefined();
      expect(detectTpm2({ path: bin, device: DEVICE }).tools.tpm2_create).toBe(
        join(bin, "tpm2_create"),
      );
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
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
      // Linux CI must have one (/dev/mem is root-only; /dev/kmsg is mode 0644, so only
      // the O_RDWR open is denied):
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
          expect(reasonOf(() => detect({ path: bin, device }))).toBe(
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
    "fsyncSync",
    "linkSync",
    "mkdtempSync",
    "lstatSync",
    "mkdirSync",
    "openSync",
    "readFileSync",
    "readlinkSync",
    "readSync",
    "realpathSync",
    "rmSync",
    "statSync",
    "type Stats",
    "unlinkSync",
  ]);
  const allowedModules = new Set([
    "../contract/errors.ts",
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
    const presence = detect({ path: bin, device: DEVICE });
    const key = "WARD_PROBE_ENV_SECRET";
    process.env[key] = "synthetic-env-value";
    process.env.TPM2TOOLS_TCTI = "swtpm:host=attacker";
    process.env.TSS2_LOG = "all+TRACE";
    process.env.LD_PRELOAD = "/nonexistent/ward-probe.so";
    process.env.DYLD_INSERT_LIBRARIES = "/nonexistent/ward-probe.dylib";
    try {
      await runTool(presence, "tpm2_create", ["-i", "-"]);
    } finally {
      delete process.env[key];
      delete process.env.TPM2TOOLS_TCTI;
      delete process.env.TSS2_LOG;
      delete process.env.LD_PRELOAD;
      delete process.env.DYLD_INSERT_LIBRARIES;
    }
    const { env } = record(records, "tpm2_create");
    // A TSS2 log level would make the libraries print handles and buffers.
    expect(env).not.toHaveProperty("TSS2_LOG");
    expect(env.PATH).toBe(`${bin}:/usr/bin:/bin`);
    expect(env.TPM2TOOLS_TCTI).toBe(`device:${DEVICE}`);
    expect(env.LANG).toBe("C");
    expect(env.LC_ALL).toBe("C");
    // The fake tool's shell adds PWD, SHLVL, _ and possibly OLDPWD of its own, so
    // the exact key set is pinned in the next test, from a tool that is env
    // itself; here the names are pinned modulo those four.
    expect(
      Object.keys(env)
        .filter((name) => !["_", "SHLVL", "PWD", "OLDPWD"].includes(name))
        .sort(),
    ).toEqual(["LANG", "LC_ALL", "PATH", "TPM2TOOLS_TCTI"]);
    expect(env).not.toHaveProperty(key);
    expect(env).not.toHaveProperty("HOME");
    expect(
      Object.keys(env).filter((name) => /^(LD_|DYLD_)/.test(name)),
    ).toEqual([]);
  });

  test("the adapter's tool environment is exactly LANG, LC_ALL, PATH and TPM2TOOLS_TCTI, read from a tool that is env itself, no shell in between", async () => {
    // DEC-262 (a31): the exact key-set pin, red on any other name including _,
    // SHLVL, PWD and OLDPWD. /usr/bin/env is run directly by runTool, so what it
    // prints is the environment the adapter built and nothing a shell added.
    const saved = { SHLVL: process.env.SHLVL, PWD: process.env.PWD };
    process.env.SHLVL = "3";
    process.env.PWD = "/somewhere";
    try {
      // Every tool Ward runs, so a name added for one tool only is still seen.
      const all: Tpm2Tool[] = [...requiredTools, diagnosticTool];
      const presence = {
        device: DEVICE,
        tools: Object.fromEntries(all.map((tool) => [tool, "/usr/bin/env"])),
      } as unknown as Tpm2Presence;
      for (const tool of all) {
        const run = await runTool(presence, tool, []);
        const names = Buffer.from(run.stdout)
          .toString("latin1")
          .split("\n")
          .filter((line) => line !== "")
          .map((line) => line.split("=")[0]);
        expect(names.sort()).toEqual([
          "LANG",
          "LC_ALL",
          "PATH",
          "TPM2TOOLS_TCTI",
        ]);
      }
    } finally {
      for (const [name, value] of Object.entries(saved))
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
    }
  });

  test("stdin carries bytes to the tool and argv carries none of them", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records);
    const presence = detect({ path: bin, device: DEVICE });
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
    await runTool(presence, "tpm2_create", ["-i", "-"], { stdin: bytes });
    const seen = record(records, "tpm2_create");
    expect(seen.stdinHex).toBe(Buffer.from(bytes).toString("hex"));
    expect(seen.args).toEqual(["-i", "-"]);
  });

  test("a failing tool is tool_failed", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_load: "fail" });
    const presence = detect({ path: bin, device: DEVICE });
    expect(
      await runTool(presence, "tpm2_load", []).catch((e) => e.reason),
    ).toBe("tool_failed");
  });

  test("output past the cap is refused, not buffered", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_unseal: "flood" });
    const presence = detect({ path: bin, device: DEVICE });
    expect(maxToolOutputBytes).toBeLessThan(64 * 1024);
    expect(
      await runTool(presence, "tpm2_unseal", []).catch((e) => e.reason),
    ).toBe("tool_output_too_large");
  });

  test("a tool that exits without reading a large stdin raises nothing unhandled", async () => {
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_create: "no-read" });
    const presence = detect({ path: bin, device: DEVICE });
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
    const presence = detect({ path: bin, device: DEVICE });
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
      const presence = detect({ path: bin, device: DEVICE });
      const pidFile = join(records, "grandchild.pid");
      const started = performance.now();
      try {
        // The 2.5 s bound is a budget, not a measurement: the fake's cold
        // start, its stdin read, the grandchild spawn and the pid write must
        // all finish inside it, about 5x the 474 ms WCLI-53 saw under load, and
        // the test fails loudly (no pid file) if they do not. The grandchild
        // sleeps 60 s, so a runTool that waited for EOF would run far past
        // the ceiling.
        const reason = await runTool(presence, "tpm2_unseal", [], {
          timeoutMs: 2_500,
        }).catch((e) => e.reason);
        const elapsed = performance.now() - started;
        // The file exists and holds a positive integer: in the window where
        // the fake was killed between creating it and writing it, the file is
        // present but empty and the grandchild was never started.
        expect(existsSync(pidFile)).toBe(true);
        expect(readFileSync(pidFile, "utf8")).toMatch(/^[1-9]\d*$/);
        expect(reason).toBe("tool_timeout");
        expect(elapsed).toBeLessThan(15_000);
      } finally {
        killGrandchild(pidFile);
      }
    },
    { timeout: 30_000 },
  );

  test("the grandchild cleanup never signals pid 0 or a garbled pid", () => {
    const { base } = fresh();
    const real = process.kill;
    const signalled: Array<[number, unknown]> = [];
    process.kill = ((pid: number, signal?: string | number) => {
      signalled.push([pid, signal]);
      return true;
    }) as typeof process.kill;
    try {
      // A pid file the fake had created but not yet written, a zero (which
      // process.kill would send to the runner's whole process group), a
      // negative one, and text: none may signal anything, or throw.
      for (const [index, content] of [
        "",
        "0",
        "-1",
        "abc",
        "1.5",
        "4294967296",
        "2147483648",
      ].entries()) {
        const file = join(base, `pid-${index}`);
        writeFileSync(file, content);
        killGrandchild(file);
      }
      killGrandchild(join(base, "absent"));
      expect(signalled).toEqual([]);
      // The control: a real pid is signalled with SIGKILL.
      const file = join(base, "pid-real");
      writeFileSync(file, "4242\n");
      killGrandchild(file);
      expect(signalled).toEqual([[4242, 9]]);
    } finally {
      process.kill = real;
    }
  });

  test("the default bound is 10 s and is the one applied", async () => {
    expect(defaultToolTimeoutMs).toBe(10_000);
    const { bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_unseal: "hang" });
    const presence = detect({ path: bin, device: DEVICE });
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
  test("a runtime lacking an open flag refuses instead of dropping it", () => {
    const real = { ...constants } as Record<string, number>;
    for (const flag of ["O_NOFOLLOW", "O_NONBLOCK", "O_NOCTTY", "O_RDONLY"]) {
      const lacking = { ...real };
      delete lacking[flag];
      expect(reasonOf(() => safeOpenFlags(lacking))).toBe(
        "platform_unsupported",
      );
    }
    // The control, and the CI witness for the platform actually running: every
    // flag is defined here and the combined mask carries each of them.
    const mask = safeOpenFlags();
    for (const flag of [
      constants.O_NOFOLLOW,
      constants.O_NONBLOCK,
      constants.O_NOCTTY,
    ])
      expect(mask & flag).toBe(flag);
  });

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
          `import { statSync } from "node:fs";
const m = await import(process.argv[1]);
try { m.adoptToolFile(process.argv[2]); console.log("accepted"); }
catch (e) { console.log(e.reason); }
console.log(statSync(process.argv[2]).isFIFO());`,
          adapter,
          fifo,
        ],
        { stdout: "pipe", stderr: "pipe" },
      );
      const deadline = setTimeout(() => child.kill(9), 8_000);
      try {
        const out = await new Response(child.stdout).text();
        // Refused as not user-private, and the path was really a FIFO.
        expect(out.trim().split("\n")).toEqual([
          "blob_not_user_private",
          "true",
        ]);
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
    const presence = detect({ path: bin, device: DEVICE });
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
    const presence = detect({ path: bin, device: DEVICE });
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

describe("the trust-policy seam is test-only", () => {
  test("no production source outside the adapter names the seam, and Tpm2Host cannot carry a policy", () => {
    const own = "tpm2-tools.ts";
    const files = (readdirSync("src", { recursive: true }) as string[]).filter(
      (file) => file.endsWith(".ts"),
    );
    // Positive control: the scan really read the adapter and the CLI.
    expect(files).toContain(join("adapters", own));
    expect(files.length).toBeGreaterThan(5);
    const leaks = files.filter(
      (file) =>
        !file.endsWith(own) &&
        /ForTest|walkToolTrust|trustedUids|trustRoot/.test(
          readFileSync(join("src", file), "utf8"),
        ),
    );
    expect(leaks).toEqual([]);
    const host = readFileSync(join("src", "adapters", own), "utf8");
    const start = host.indexOf("export interface Tpm2Host");
    const end = host.indexOf("export interface Tpm2Presence");
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(host.slice(start, end)).not.toMatch(
      /trustedUids|trustRoot|ToolTrustPolicy/,
    );
  });
});

// DEC-262 (a9): sealing. Synthetic key and fake tools only; nothing reaches a
// TPM. The key must reach exactly one place, tpm2_create's stdin.
describe("sealing the vault key", () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + i);
  const keyHex = Buffer.from(key).toString("hex");
  function sealable(modes: Record<string, string> = {}) {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, modes);
    const directory = join(base, "ward-tpm");
    return {
      base,
      directory,
      records,
      presence: detect({ path: bin, device: DEVICE }),
    };
  }

  test("createprimary then create, the key on create's stdin and nowhere else", async () => {
    const { directory, records, presence } = sealable();
    const sealed = await sealKey(presence, key, directory);
    expect(sealed.publicBlob).toBe(join(directory, sealedPublicName));
    expect(sealed.privateBlob).toBe(join(directory, sealedPrivateName));
    const primary = record(records, "tpm2_createprimary");
    const create = record(records, "tpm2_create");
    // The whole argv is the on-disk contract: a dropped attribute, an added
    // -L or -p, or a changed template must go red here.
    expect(primary.args).toEqual([
      "-C",
      "o",
      "-g",
      "sha256",
      "-G",
      "ecc256:aes128cfb",
      "-a",
      "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda",
      "-c",
      join(directory, "primary.ctx"),
      "-Q",
    ]);
    expect(create.args).toEqual([
      "-C",
      join(directory, "primary.ctx"),
      "-g",
      "sha256",
      "-a",
      "fixedtpm|fixedparent|noda|userwithauth",
      "-i",
      "-",
      "-u",
      join(directory, `${sealedPublicName}.partial`),
      "-r",
      join(directory, `${sealedPrivateName}.partial`),
      "-Q",
    ]);
    expect(create.stdinHex).toBe(keyHex);
    expect(primary.stdinHex).toBe("");
    // The key is in no argv, no environment, no other tool's stdin, and no
    // file Ward or the tools left behind.
    const everything = JSON.stringify([primary, { ...create, stdinHex: "" }]);
    expect(everything).not.toContain(keyHex);
    expect(everything).not.toContain(Buffer.from(key).toString("latin1"));
    for (const name of readdirSync(directory))
      expect(
        readFileSync(join(directory, name)).includes(Buffer.from(key)),
      ).toBe(false);
  });

  test("the sealed blobs and the context are user-private, whatever the tools wrote", async () => {
    const { directory, presence } = sealable();
    await sealKey(presence, key, directory);
    expect(statSync(directory).mode & 0o777).toBe(0o700);
    for (const name of [sealedPublicName, sealedPrivateName, "primary.ctx"])
      expect(statSync(join(directory, name)).mode & 0o777).toBe(0o600);
    // No partial file is left once both blobs are in place.
    expect(readdirSync(directory).sort()).toEqual(
      ["primary.ctx", sealedPrivateName, sealedPublicName].sort(),
    );
  });

  test("refuses a key that is not 32 bytes before running any tool", async () => {
    const { directory, records, presence } = sealable();
    await expect(
      sealKey(presence, new Uint8Array(31), directory),
    ).rejects.toBeInstanceOf(RangeError);
    expect(existsSync(join(records, "tpm2_createprimary.json"))).toBe(false);
  });

  test("refuses a directory that is not user-private", async () => {
    const { directory, records, presence } = sealable();
    mkdirSync(directory);
    chmodSync(directory, 0o755);
    await expect(sealKey(presence, key, directory)).rejects.toMatchObject({
      reason: "blob_not_user_private",
    });
    expect(existsSync(join(records, "tpm2_createprimary.json"))).toBe(false);
  });

  test("never replaces a sealed key that is already there, and a lone private blob counts", async () => {
    const { directory, records, presence } = sealable();
    await sealKey(presence, key, directory);
    const privatePath = join(directory, sealedPrivateName);
    const publicPath = join(directory, sealedPublicName);
    const before = [statSync(privatePath).ino, statSync(publicPath).ino];
    rmSync(join(records, "tpm2_create.json"));
    await expect(
      sealKey(presence, new Uint8Array(32).fill(7), directory),
    ).rejects.toMatchObject({ reason: "key_exists" });
    expect([statSync(privatePath).ino, statSync(publicPath).ino]).toEqual(
      before,
    );
    expect(existsSync(join(records, "tpm2_create.json"))).toBe(false);
    // The private blob alone is the commit marker: still a sealed key.
    rmSync(publicPath);
    // DEC-262 (a16): refused as key_incomplete, the recovery code.
    await expect(
      sealKey(presence, new Uint8Array(32).fill(7), directory),
    ).rejects.toMatchObject({ reason: "key_incomplete" });
    expect(statSync(privatePath).ino).toBe(before[0] as number);
    expect(existsSync(join(records, "tpm2_create.json"))).toBe(false);
  });

  test("a lone public blob is an interrupted seal: replaced, not reported as a sealed key", async () => {
    const { directory, presence } = sealable();
    preparePrivateDirectory(directory);
    writeFileSync(join(directory, sealedPublicName), "leftover");
    chmodSync(join(directory, sealedPublicName), 0o600);
    await sealKey(presence, key, directory);
    expect(readFileSync(join(directory, sealedPublicName), "utf8")).not.toBe(
      "leftover",
    );
    expect(existsSync(join(directory, sealedPrivateName))).toBe(true);
  });

  test("a second writer's private blob is never replaced or removed, and our public blob is withdrawn", async () => {
    const { directory, presence } = sealable({ tpm2_create: "race-final" });
    const error = await sealKey(presence, key, directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    // A second writer's key exists now: key_exists, not directory_unusable.
    expect(error).toMatchObject({ reason: "key_exists" });
    // The another-writer hint is given for EEXIST only.
    expect((error as Error).message).toContain("(EEXIST); another writer");
    expect(readFileSync(join(directory, sealedPrivateName), "utf8")).toBe(
      "planted",
    );
    expect(existsSync(join(directory, sealedPublicName))).toBe(false);
    expect(
      readdirSync(directory).filter((name) => name.endsWith(".partial")),
    ).toEqual([]);
  });

  test("a public blob that appears mid-seal is not a sealed key: directory_unusable, never key_exists (N1)", async () => {
    const { directory, presence } = sealable({ tpm2_create: "race-pub" });
    const error = await sealKey(presence, key, directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({ reason: "directory_unusable" });
    expect((error as Error).message).toContain("(EEXIST); another writer");
    // Nothing of ours is published, and the planted public blob is not removed.
    expect(readFileSync(join(directory, sealedPublicName), "utf8")).toBe(
      "planted",
    );
    expect(existsSync(join(directory, sealedPrivateName))).toBe(false);
  });

  test("a failing create leaves no blob and no partial file, and the same directory can be sealed after", async () => {
    const { base, directory, presence } = sealable({ tpm2_create: "fail" });
    await expect(sealKey(presence, key, directory)).rejects.toMatchObject({
      reason: "tool_failed",
    });
    expect(
      readdirSync(directory).filter((name) => name.startsWith("vault-key")),
    ).toEqual([]);
    // The same fakes, now succeeding, seal into the same directory.
    installFakeTools(join(base, "bin"), join(base, "records"));
    await sealKey(presence, key, directory);
    expect(existsSync(join(directory, sealedPrivateName))).toBe(true);
  });

  test("the contents are fsynced before publication, and the directory after each name", () => {
    // A power-cut ordering cannot be observed from a test; this pins that the
    // calls exist where the ordering needs them.
    const source = readFileSync(
      join(import.meta.dir, "..", "src", "adapters", "tpm2-tools.ts"),
      "utf8",
    );
    const adopt = source.slice(source.indexOf("export function adoptToolFile"));
    expect(adopt.slice(0, adopt.indexOf("\n}\n"))).toContain("fsyncSync(fd)");
    const seal = source.slice(source.indexOf("export async function sealKey"));
    expect(seal.indexOf("[publicPartial, publicBlob]")).toBeGreaterThan(0);
    // The private blob is published last: it is the commit marker.
    expect(seal.indexOf("[publicPartial, publicBlob]")).toBeLessThan(
      seal.indexOf("[privatePartial, privateBlob]"),
    );
    // fsyncDirectory sits INSIDE the publish loop: after a name is published
    // and immediately before the loop closes into the failure handler, so
    // hoisting it to one call after the loop must go red.
    const published = seal.indexOf("published.push(final);");
    expect(published).toBeGreaterThanOrEqual(0);
    const call = "fsyncDirectory(directory);";
    const fsync = seal.indexOf(call, published);
    expect(fsync).toBeGreaterThanOrEqual(0);
    expect(seal.slice(fsync + call.length)).toStartWith(
      "\n    }\n  } catch (error) {",
    );
  });

  // Root ignores a 0500 directory, so the case is skipped, not passed.
  test.skipIf(process.getuid?.() === 0)(
    "a link failure other than EEXIST carries no another-writer hint",
    async () => {
      const { directory, presence } = sealable({
        tpm2_create: "lock-directory",
      });
      const error = await sealKey(presence, key, directory).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      // Restore the mode so the temporary root can be removed.
      chmodSync(directory, 0o700);
      expect(error).toMatchObject({ reason: "directory_unusable" });
      expect((error as Error).message).toContain("(EACCES)");
      expect((error as Error).message).not.toContain("another writer");
    },
  );

  test("the failure cleanup removes the private blob (the commit marker) before the public one", () => {
    // An interrupted cleanup must never leave a lone .priv for a key that was
    // never committed (that reads as key_incomplete, a permanent recovery
    // condition). A forced mid-cleanup failure is not reachable from a test, so
    // this pins the reverse order in the source.
    const source = readFileSync(
      join(import.meta.dir, "..", "src", "adapters", "tpm2-tools.ts"),
      "utf8",
    );
    const seal = source.slice(source.indexOf("export async function sealKey"));
    expect(seal).toContain("...[...published].reverse()");
    expect(seal).not.toContain("[...partials, ...published]");
  });

  test("a noisy stderr is truncated, not refused (WCLI-157)", async () => {
    const { directory, presence } = sealable({
      tpm2_createprimary: "flood-stderr",
    });
    await sealKey(presence, key, directory);
    const run = await runTool(presence, "tpm2_createprimary", [], {});
    expect(run.stderr.length).toBe(maxToolOutputBytes);
  });

  test("a noisy stderr on a failing tool is tool_failed, not output-too-large (WCLI-157)", async () => {
    const { directory, presence } = sealable({
      tpm2_create: "flood-stderr-fail",
    });
    await expect(sealKey(presence, key, directory)).rejects.toMatchObject({
      reason: "tool_failed",
    });
  });

  test("a noisy stdout from a tool that stays alive is refused at once, not after the bound", async () => {
    const { directory, presence } = sealable({
      tpm2_createprimary: "flood-hang",
    });
    // With the child killed on the refusal this is tool_output_too_large at
    // once; waiting for its exit would make it tool_timeout after 3 s.
    await expect(
      sealKey(presence, key, directory, { timeoutMs: 3000 }),
    ).rejects.toMatchObject({ reason: "tool_output_too_large" });
  });

  test("a noisy stdout is still refused", async () => {
    const { directory, presence } = sealable({ tpm2_createprimary: "flood" });
    await expect(sealKey(presence, key, directory)).rejects.toMatchObject({
      reason: "tool_output_too_large",
    });
  });
});

// The fixture mirrors the real tools' file flags: -c is an OUTPUT of
// tpm2_createprimary and tpm2_load and an INPUT of tpm2_unseal and
// tpm2_startauthsession, so a wrong sequence fails the way it would for real.
describe("the fake tools' input and output flags", () => {
  test("an input that does not exist fails the tool; an output is created", async () => {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records);
    const presence = detect({ path: bin, device: DEVICE });
    const missing = join(base, "no-such.ctx");
    await expect(
      runTool(presence, "tpm2_unseal", ["-c", missing]),
    ).rejects.toMatchObject({ reason: "tool_failed" });
    // Each tpm2_load input is checked on its own: the other two are real.
    const real = join(base, "real.ctx");
    writeFileSync(real, "x");
    const flags = ["-C", "-u", "-r"] as const;
    for (const absent of flags) {
      const args = flags.flatMap((flag) => [
        flag,
        flag === absent ? missing : real,
      ]);
      await expect(
        runTool(presence, "tpm2_load", [...args, "-c", join(base, "out.ctx")]),
      ).rejects.toMatchObject({ reason: "tool_failed" });
    }
    expect(existsSync(join(base, "out.ctx"))).toBe(false);
    // -c is an output of load and createprimary, never of unseal.
    const out = join(base, "made.ctx");
    await runTool(presence, "tpm2_createprimary", ["-c", out]);
    expect(existsSync(out)).toBe(true);
    const inputOnly = join(base, "input-only.ctx");
    writeFileSync(inputOnly, "x");
    await runTool(presence, "tpm2_unseal", ["-c", inputOnly]);
    expect(readFileSync(inputOnly, "utf8")).toBe("x");
  });
});

// Loading the sealed key under the pinned primary (DEC-262). The session and
// the unseal wait on the salted-session measurement and are not here.
describe("loading the sealed key", () => {
  const key = new Uint8Array(32).fill(0x5a);
  async function sealed(modes: Record<string, string> = {}) {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, modes);
    const directory = join(base, "ward-tpm");
    const presence = detect({ path: bin, device: DEVICE });
    await sealKey(presence, key, directory);
    return { base, bin, records, directory, presence };
  }
  const scratches = (directory: string) =>
    readdirSync(directory).filter((name) => name.startsWith("unseal-"));
  // The pinned template, literally, with -c in the given scratch: a changed
  // template orphans every sealed blob.
  const primaryArgs = (scratch: string) => [
    "-C",
    "o",
    "-g",
    "sha256",
    "-G",
    "ecc256:aes128cfb",
    "-a",
    "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda",
    "-c",
    join(scratch, "primary.ctx"),
    "-Q",
  ];

  test("createprimary then load under that primary, in a private scratch that is removed", async () => {
    const { records, directory, presence } = await sealed();
    // The seal's record must not stand in for this load's.
    rmSync(join(records, "tpm2_createprimary.json"), { force: true });
    let seen:
      | { directory: string; primary: string; keyContext: string }
      | undefined;
    await withLoadedKey(presence, directory, async (loaded) => {
      seen = loaded;
      expect(statSync(loaded.directory).mode & 0o777).toBe(0o700);
      expect(statSync(loaded.keyContext).mode & 0o777).toBe(0o600);
      expect(statSync(loaded.primary).mode & 0o777).toBe(0o600);
    });
    if (seen === undefined) throw new Error("use() did not run");
    expect(dirname(seen.directory)).toBe(directory);
    // Both contexts are named in this call's own scratch, and the primary is
    // the one createprimary just made there, never sealKey's leftover.
    expect(seen.primary).toBe(join(seen.directory, "primary.ctx"));
    expect(seen.keyContext).toBe(join(seen.directory, "key.ctx"));
    expect(seen.primary).not.toBe(join(directory, "primary.ctx"));
    expect(record(records, "tpm2_createprimary").args).toEqual(
      primaryArgs(seen.directory),
    );
    expect(existsSync(seen.directory)).toBe(false);
    expect(scratches(directory)).toEqual([]);
    expect(record(records, "tpm2_load").args).toEqual([
      "-C",
      seen.primary,
      "-u",
      join(directory, sealedPublicName),
      "-r",
      join(directory, sealedPrivateName),
      "-c",
      seen.keyContext,
      "-Q",
    ]);
    // The sealed blobs are untouched.
    expect(existsSync(join(directory, sealedPrivateName))).toBe(true);
  });

  test("a throw from use() still removes the scratch", async () => {
    const { directory, presence } = await sealed();
    await expect(
      withLoadedKey(presence, directory, async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(scratches(directory)).toEqual([]);
  });

  test("two loads at once use different scratch directories, each with its own primary", async () => {
    const { directory, presence } = await sealed();
    const seen: { directory: string; primary: string; keyContext: string }[] =
      [];
    const hold = (loaded: {
      directory: string;
      primary: string;
      keyContext: string;
    }) => {
      seen.push(loaded);
      return new Promise<void>((resolve) => setTimeout(resolve, 50));
    };
    await Promise.all([
      withLoadedKey(presence, directory, hold),
      withLoadedKey(presence, directory, hold),
    ]);
    expect(new Set(seen.map((loaded) => loaded.directory)).size).toBe(2);
    expect(new Set(seen.map((loaded) => loaded.primary)).size).toBe(2);
    for (const loaded of seen) {
      expect(loaded.primary).toBe(join(loaded.directory, "primary.ctx"));
      expect(loaded.keyContext).toBe(join(loaded.directory, "key.ctx"));
    }
    expect(scratches(directory)).toEqual([]);
  });

  test("no sealed key, a missing directory, and a lone public blob run no tool", async () => {
    const { base, records, directory, presence } = await sealed();
    const empty = join(base, "empty");
    preparePrivateDirectory(empty);
    rmSync(join(records, "tpm2_load.json"), { force: true });
    rmSync(join(records, "tpm2_createprimary.json"), { force: true });
    await expect(
      withLoadedKey(presence, empty, async () => 1),
    ).rejects.toMatchObject({ reason: "key_not_sealed" });
    writeFileSync(join(empty, sealedPublicName), "x");
    chmodSync(join(empty, sealedPublicName), 0o600);
    await expect(
      withLoadedKey(presence, empty, async () => 1),
    ).rejects.toMatchObject({ reason: "key_not_sealed" });
    const absent = join(base, "absent");
    await expect(
      withLoadedKey(presence, absent, async () => 1),
    ).rejects.toMatchObject({ reason: "key_not_sealed" });
    expect(existsSync(absent)).toBe(false);
    // A relative path to a real, sealed, private directory is refused by the
    // absolute-path guard itself (its own detail), not by a later step:
    // without the guard the lstat succeeds against the cwd.
    const relativeError = await withLoadedKey(
      presence,
      relative(process.cwd(), directory),
      async () => 1,
    ).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(relativeError).toMatchObject({ reason: "blob_not_user_private" });
    expect((relativeError as Error).message).toContain("not an absolute path");
    expect(existsSync(join(records, "tpm2_load.json"))).toBe(false);
    expect(existsSync(join(records, "tpm2_createprimary.json"))).toBe(false);
  });

  test("only a missing directory is not sealed: a wider one is not user-private and an unreadable path is directory_unusable", async () => {
    const { base, records, directory, presence } = await sealed();
    rmSync(join(records, "tpm2_createprimary.json"), { force: true });
    chmodSync(directory, 0o755);
    await expect(
      withLoadedKey(presence, directory, async () => 1),
    ).rejects.toMatchObject({ reason: "blob_not_user_private" });
    chmodSync(directory, 0o700);
    // A path under a regular file is ENOTDIR, which is not ENOENT.
    const file = join(base, "a-file");
    writeFileSync(file, "x");
    await expect(
      withLoadedKey(presence, join(file, "ward-tpm"), async () => 1),
    ).rejects.toMatchObject({ reason: "directory_unusable" });
    expect(existsSync(join(records, "tpm2_createprimary.json"))).toBe(false);
  });

  // DEC-262 (a16): the private blob is the commit marker. A lone .priv is a
  // sealed key whose pair is gone (recovery: never a re-init, setup refuses); a
  // lone .pub, or neither, is not sealed.
  test("a lone private blob is key_incomplete, runs no tool, and setup refuses over it", async () => {
    const { records, directory, presence } = await sealed();
    rmSync(join(directory, sealedPublicName));
    rmSync(join(records, "tpm2_createprimary.json"), { force: true });
    rmSync(join(records, "tpm2_create.json"), { force: true });
    const before = readFileSync(join(directory, sealedPrivateName));
    await expect(
      withLoadedKey(presence, directory, async () => 1),
    ).rejects.toMatchObject({ reason: "key_incomplete" });
    expect(existsSync(join(records, "tpm2_createprimary.json"))).toBe(false);
    // Setup (a seal) refuses, names the recovery code, and changes nothing.
    await expect(sealKey(presence, key, directory)).rejects.toMatchObject({
      reason: "key_incomplete",
    });
    expect(existsSync(join(records, "tpm2_create.json"))).toBe(false);
    expect(existsSync(join(directory, sealedPublicName))).toBe(false);
    expect(
      readFileSync(join(directory, sealedPrivateName)).equals(before),
    ).toBe(true);
  });

  test.skipIf(process.getuid?.() === 0)(
    "a path that cannot be looked at is directory_unusable, never not sealed",
    async () => {
      const { base, records, directory, presence } = await sealed();
      rmSync(join(records, "tpm2_createprimary.json"), { force: true });
      const parent = join(base, "closed");
      mkdirSync(parent);
      chmodSync(parent, 0o000);
      try {
        await expect(
          withLoadedKey(presence, join(parent, "ward-tpm"), async () => 1),
        ).rejects.toMatchObject({ reason: "directory_unusable" });
      } finally {
        chmodSync(parent, 0o700);
      }
      expect(existsSync(join(records, "tpm2_createprimary.json"))).toBe(false);
      expect(existsSync(directory)).toBe(true);
    },
  );

  test("a lone public blob is key_not_sealed", async () => {
    const { directory, presence } = await sealed();
    rmSync(join(directory, sealedPrivateName));
    await expect(
      withLoadedKey(presence, directory, async () => 1),
    ).rejects.toMatchObject({ reason: "key_not_sealed" });
  });

  test("a blob wider than 0600 is refused before any tool reads it, never repaired", async () => {
    for (const name of [sealedPrivateName, sealedPublicName]) {
      const { records, directory, presence } = await sealed();
      rmSync(join(records, "tpm2_load.json"), { force: true });
      rmSync(join(records, "tpm2_createprimary.json"), { force: true });
      chmodSync(join(directory, name), 0o640);
      await expect(
        withLoadedKey(presence, directory, async () => 1),
      ).rejects.toMatchObject({ reason: "blob_not_user_private" });
      expect(statSync(join(directory, name)).mode & 0o777).toBe(0o640);
      expect(existsSync(join(records, "tpm2_load.json"))).toBe(false);
      expect(existsSync(join(records, "tpm2_createprimary.json"))).toBe(false);
      expect(scratches(directory)).toEqual([]);
    }
  });

  test("a failing load is tool_failed, leaves no scratch, and its stderr is never surfaced", async () => {
    const { bin, records, directory, presence } = await sealed();
    installFakeTools(bin, records, { tpm2_load: "flood-stderr-fail" });
    const error = await withLoadedKey(presence, directory, async () => 1).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({ reason: "tool_failed" });
    expect(String((error as Error).message)).not.toContain("e".repeat(16));
    expect(scratches(directory)).toEqual([]);
  });
});

// Unsealing (DEC-262 a9; opum-doc's slice-2 rules). Fake tools only: these
// prove the call order, the argv, the 0600 check and the stop on an
// unencrypted session. They do NOT prove that a real TPM encrypts the unsealed
// bytes or that the real tpm2_sessionconfig prints what the parser reads:
// that is the T26 jetson run.
describe("unsealing the sealed key", () => {
  const synthetic = new Uint8Array(32).fill(0x5a);
  async function sealed(modes: Record<string, string> = {}) {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, modes);
    const directory = join(base, "ward-tpm");
    const presence = detect({ path: bin, device: DEVICE });
    await sealKey(presence, synthetic, directory);
    // The seal's calls are not the unseal's.
    rmSync(join(records, "calls.jsonl"), { force: true });
    return { base, bin, records, directory, presence };
  }
  const calls = (records: string) =>
    readFileSync(join(records, "calls.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map(
        (line) =>
          JSON.parse(line) as {
            tool: string;
            args: string[];
            stdinHex: string;
            sessionMode: number | null;
          },
      );
  const scratches = (directory: string) =>
    readdirSync(directory).filter((name) => name.startsWith("unseal-"));

  test("loads, starts a salted session, requires encrypt and decrypt, unseals under it, flushes it", async () => {
    const { records, directory, presence } = await sealed();
    const key = await unsealKey(presence, directory);
    expect(Buffer.from(key).equals(Buffer.from(synthetic))).toBe(true);
    const made = calls(records);
    expect(made.map((call) => call.tool)).toEqual([
      "tpm2_createprimary",
      "tpm2_load",
      "tpm2_startauthsession",
      "tpm2_sessionconfig",
      "tpm2_sessionconfig",
      "tpm2_unseal",
      "tpm2_flushcontext",
    ]);
    const load = made[1]?.args ?? [];
    const scratch = dirname(load[load.indexOf("-c") + 1] ?? "");
    const session = join(scratch, "session.ctx");
    expect(dirname(scratch)).toBe(directory);
    expect(made[2]?.args).toEqual([
      "--hmac-session",
      "-c",
      join(scratch, "primary.ctx"),
      "-S",
      session,
      "-Q",
    ]);
    expect(made[3]?.args).toEqual([
      "--enable-decrypt",
      "--enable-encrypt",
      session,
    ]);
    expect(made[4]?.args).toEqual([session]);
    expect(made[5]?.args).toEqual([
      "-c",
      join(scratch, "key.ctx"),
      "-p",
      `session:${session}`,
    ]);
    expect(made[6]?.args).toEqual([session]);
    // The scratch, with the session in it, is gone.
    expect(scratches(directory)).toEqual([]);
  });

  test("the key is in no argv, no stdin and no file left behind", async () => {
    const { records, directory, presence } = await sealed();
    await unsealKey(presence, directory);
    const hex = Buffer.from(synthetic).toString("hex");
    const b64 = Buffer.from(synthetic).toString("base64");
    const log = readFileSync(join(records, "calls.jsonl"), "utf8");
    expect(log).not.toContain(hex);
    expect(log).not.toContain(b64);
    for (const call of calls(records)) expect(call.stdinHex).toBe("");
    for (const name of readdirSync(directory))
      if (statSync(join(directory, name)).isFile())
        expect(readFileSync(join(directory, name)).includes(0x5a)).toBe(false);
  });

  test("every unseal starts its own session, never a reused one", async () => {
    const { records, directory, presence } = await sealed();
    await unsealKey(presence, directory);
    await unsealKey(presence, directory);
    const starts = calls(records).filter(
      (call) => call.tool === "tpm2_startauthsession",
    );
    expect(starts.length).toBe(2);
    const paths = starts.map((call) => call.args[call.args.indexOf("-S") + 1]);
    expect(new Set(paths).size).toBe(2);
    expect(scratches(directory)).toEqual([]);
  });

  test("the session file is exactly 0600 when the unseal reads it", async () => {
    const { records, directory, presence } = await sealed();
    await unsealKey(presence, directory);
    // The fake writes its output files 0660, as the real tools do.
    const unseal = calls(records).find((call) => call.tool === "tpm2_unseal");
    expect(unseal?.sessionMode).toBe(0o600);
  });

  test("a session that does not encrypt stops before any unseal, flushed and cleaned up", async () => {
    for (const mode of ["session-off", "session-zero"]) {
      const { records, directory, presence } = await sealed({
        tpm2_sessionconfig: mode,
      });
      await expect(unsealKey(presence, directory)).rejects.toBeInstanceOf(
        Tpm2Error,
      );
      const tools = calls(records).map((call) => call.tool);
      expect(tools).not.toContain("tpm2_unseal");
      // The session started is still flushed, and the scratch removed.
      expect(tools.at(-1)).toBe("tpm2_flushcontext");
      expect(scratches(directory)).toEqual([]);
    }
  });

  test("a version that does not match the measured line is shown as unknown, never echoed", async () => {
    for (const versionMode of [
      "version-fail",
      "version-long",
      "version-quote",
      "version-ansi",
      "version-newline",
    ]) {
      const { directory, presence } = await sealed({
        tpm2_sessionconfig: `session-zero+${versionMode}`,
      });
      const error = await unsealKey(presence, directory).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect([versionMode, error]).toMatchObject([
        versionMode,
        { reason: "tool_incompatible", detail: "tpm2-tools unknown" },
      ]);
    }
  });

  test("a wrong-length output is tool_failed and no bytes are returned", async () => {
    const { directory, presence } = await sealed({
      tpm2_unseal: "short-unseal",
    });
    await expect(unsealKey(presence, directory)).rejects.toMatchObject({
      reason: "tool_failed",
    });
    expect(scratches(directory)).toEqual([]);
  });

  test("a failing unseal is tool_failed, its stderr unsurfaced, and the session is flushed", async () => {
    const { records, directory, presence } = await sealed({
      tpm2_unseal: "flood-stderr-fail",
    });
    const error = await unsealKey(presence, directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({ reason: "tool_failed" });
    expect(String((error as Error).message)).not.toContain("e".repeat(16));
    expect(calls(records).at(-1)?.tool).toBe("tpm2_flushcontext");
    expect(scratches(directory)).toEqual([]);
  });

  test("a failing flush does not take the key away", async () => {
    const { directory, presence } = await sealed({ tpm2_flushcontext: "fail" });
    const key = await unsealKey(presence, directory);
    expect(Buffer.from(key).equals(Buffer.from(synthetic))).toBe(true);
    expect(scratches(directory)).toEqual([]);
  });

  // DEC-262 (a15) NB6. on = the measured shape with decrypt and encrypt listed;
  // off = the measured shape (every token in the tpm2-tools vocabulary) without
  // one of them: the AC2 stop; unparsed = anything else: tool compatibility.
  // Both refuse; only "on" unseals.
  test("the printout is classified on, off or unparsed, and only on unseals", () => {
    const real =
      "Session-Handle: 0x02000000\nSession-Attributes: continuesession|decrypt|encrypt\n";
    const handle = "Session-Handle: 0x02000000\n";
    const on = [
      real,
      real.replaceAll("\n", "\r\n"),
      `${handle}Session-Attributes: encrypt|decrypt|continuesession`,
      `${handle}Session-Attributes: continuesession|decrypt|encrypt|audit\n`,
    ];
    // The measured off shapes (probe 4): --disable-encrypt, --disable-decrypt.
    const off = [
      `${handle}Session-Attributes: continuesession|decrypt\n`,
      `${handle}Session-Attributes: continuesession|encrypt\n`,
      `${handle}Session-Attributes: continuesession\n`,
      `${handle}Session-Attributes: audit\n`,
    ];
    const unparsed = [
      "",
      handle,
      // The handle line is required, once, and first.
      "Session-Attributes: continuesession|decrypt|encrypt\n",
      "Session-Attributes: encrypt|decrypt|continuesession\n",
      "Session-Attributes: continuesession\n",
      "Session-Attributes: continuesession|decrypt\n",
      `${handle}${handle}Session-Attributes: continuesession|decrypt|encrypt\n`,
      `Session-Attributes: continuesession|decrypt|encrypt\n${handle}`,
      // A repeated token.
      `${handle}Session-Attributes: continuesession|decrypt|decrypt|encrypt\n`,
      `${handle}Session-Attributes: continuesession|encrypt|encrypt\n`,
      // Lookalike names: a token outside the vocabulary means it changed.
      `${handle}Session-Attributes: continuesession|decrypt|encrypt_x\n`,
      `${handle}Session-Attributes: continuesession|decrypt|encrypt-off\n`,
      `${handle}Session-Attributes: continuesession|decrypt|no-encrypt\n`,
      `${handle}Session-Attributes: continuesession|decrypt|!encrypt\n`,
      `${handle}Session-Attributes: continuesession|decrypt|encrypt2\n`,
      `${handle}Session-Attributes: continuesession|decrypt|Encrypt\n`,
      // Values after a name, spaces, other separators.
      `${handle}Session-Attributes: continuesession|decrypt|encrypt 0\n`,
      `${handle}Session-Attributes: decrypt encrypt\n`,
      `${handle}Session-Attributes: decrypt,encrypt\n`,
      `${handle}Session-Attributes: continuesession|decrypt|encrypt=0\n`,
      "encrypt: 0\ndecrypt: 1\n",
      "encrypt: disabled\ndecrypt: 1\n",
      "encrypt: n\ndecrypt: 1\n",
      "encrypt: 0x0\ndecrypt: 1\n",
      // A line that merely mentions the words.
      `${handle}Session-Attributes: continuesession\nWARNING: decrypt/encrypt not supported\n`,
      // Duplicates: first match must not win.
      `${real}Session-Attributes: continuesession\n`,
      `${handle}Session-Attributes: continuesession\nSession-Attributes: continuesession|decrypt|encrypt\n`,
      `${real}encrypt: 0\n`,
      // Anything else around the measured shape.
      `${real}extra line\n`,
      "Session-Handle: nope\nSession-Attributes: continuesession|decrypt|encrypt\n",
      " Session-Handle: 0x02000000\nSession-Attributes: continuesession|decrypt|encrypt\n",
      "session-handle: 0x02000000\nsession-attributes: continuesession|decrypt|encrypt\n",
      `${handle}Session-Attributes: \n`,
    ];
    const verdicts = (inputs: string[]) =>
      inputs.map((input) => [input, classifySessionPrintoutForTest(input)]);
    expect(verdicts(on)).toEqual(on.map((input) => [input, "on"]));
    expect(verdicts(off)).toEqual(off.map((input) => [input, "off"]));
    expect(verdicts(unparsed)).toEqual(
      unparsed.map((input) => [input, "unparsed"]),
    );
    expect([on.length, off.length, unparsed.length]).toEqual([4, 4, 33]);
  });

  // The a16 condition, both ways, through the whole call: a measured-shape
  // printout with "decrypt" missing is (a), session_not_encrypted; an unknown
  // token or an unparseable shape is (b), tool_incompatible naming the
  // tpm2-tools version. Both refuse, and no unseal runs.
  test("a printout that says encryption is off is session_not_encrypted; one that does not parse is tool_incompatible naming the tpm2-tools version", async () => {
    const cases = [
      ["session-off", "session_not_encrypted"],
      ["session-no-decrypt", "session_not_encrypted"],
      ["session-unknown-token", "tool_incompatible"],
      ["session-zero", "tool_incompatible"],
    ] as const;
    for (const [mode, reason] of cases) {
      const { records, directory, presence } = await sealed({
        tpm2_sessionconfig: mode,
      });
      const error = await unsealKey(presence, directory).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect([mode, error]).toMatchObject([mode, { reason }]);
      if (reason === "tool_incompatible")
        expect((error as Tpm2Error).detail).toBe("tpm2-tools 5.6");
      expect(calls(records).map((call) => call.tool)).not.toContain(
        "tpm2_unseal",
      );
    }
  });

  test("a tool that rewrites the session file wide is re-adopted to 0600 before the unseal", async () => {
    const { records, directory, presence } = await sealed({
      tpm2_sessionconfig: "wide-on-enable",
    });
    const key = await unsealKey(presence, directory);
    expect(key.length).toBe(32);
    const unseal = calls(records).find((call) => call.tool === "tpm2_unseal");
    expect(unseal?.sessionMode).toBe(0o600);
  });

  test("a session file widened after the check is refused, never repaired, and no unseal runs", async () => {
    const { records, directory, presence } = await sealed({
      tpm2_sessionconfig: "wide-on-read",
    });
    await expect(unsealKey(presence, directory)).rejects.toMatchObject({
      reason: "blob_not_user_private",
    });
    const tools = calls(records).map((call) => call.tool);
    expect(tools).not.toContain("tpm2_unseal");
    expect(tools.at(-1)).toBe("tpm2_flushcontext");
    expect(scratches(directory)).toEqual([]);
  });

  test("a startauthsession that fails after saving a session still gets it flushed", async () => {
    const { records, directory, presence } = await sealed({
      tpm2_startauthsession: "fail",
    });
    await expect(unsealKey(presence, directory)).rejects.toMatchObject({
      reason: "tool_failed",
    });
    expect(calls(records).at(-1)?.tool).toBe("tpm2_flushcontext");
    expect(scratches(directory)).toEqual([]);
  });

  test("a startauthsession that fails without saving a session gets no flush", async () => {
    const { records, directory, presence } = await sealed({
      tpm2_startauthsession: "fail-no-output",
    });
    await expect(unsealKey(presence, directory)).rejects.toMatchObject({
      reason: "tool_failed",
    });
    // No -S file exists, so there is nothing of ours to flush.
    expect(calls(records).map((call) => call.tool)).not.toContain(
      "tpm2_flushcontext",
    );
    expect(scratches(directory)).toEqual([]);
  });

  test("no sealed key runs no tool at all", async () => {
    const { base, records, presence } = await sealed();
    const empty = join(base, "empty");
    preparePrivateDirectory(empty);
    await expect(unsealKey(presence, empty)).rejects.toMatchObject({
      reason: "key_not_sealed",
    });
    expect(existsSync(join(records, "calls.jsonl"))).toBe(false);
  });
});

// MUTANT REGISTER for slice 3b (WCLI-21), written BEFORE the runs. Each line is
// a one-site mutation of src/adapters/tpm2-tools.ts and the tests predicted to
// go red, by the first words of their titles; every other test in the file must
// stay green. Run against a saved copy of the source, restored after each.
//   M1  never call onWarning                       -> "a failed flush after a good unseal returns the key and warns"
//   M2  also warn on a failed unseal               -> "a failed flush after a FAILED unseal", "a session never saved"
//   M3  retry the flush once on failure            -> "a failed flush after a good unseal returns the key and warns"
//   M4  drop flushFailure from the rethrown error  -> "a failed flush after a FAILED unseal"
//   M10 flush without the exists(session) guard    -> "a startauthsession that fails without saving", "a session never saved"
//   M11 do not swallow a returned promise          -> "a warning listener whose promise rejects"
//   M5  tpm2StateFor drops the path                -> "an untrusted tool is its own state"
//   M6  key_unloadable not derived in tpm2StateFor -> "blobs that no longer load", "with tpm2_load failing, a refused open"
//                                                     (positive control), "the unseal path and diagnoseTpm2 agree"
//   M7  loose saved-session count parse            -> "a count that cannot be read"
//   M8  report a count of zero as attention        -> "a sealed key on a healthy host is ready"
//   M9  drop the tpm2-tools version                -> "a tool whose printout changed"
//   G1  no trust walk of tpm2_getcap               -> "tpm2_getcap is trust-walked before it runs"
//   G2  absent getcap reads as a count of 0        -> "a host without tpm2_getcap is still supported"
//   G3  failed getcap reads as a count of 0        -> "a count that cannot be read"
//   G4  untrusted getcap reads as a count of 0     -> "tpm2_getcap is trust-walked before it runs"
//   G5  unrecognised output reads as a count of 0  -> "a count that cannot be read"
//   G6  untrusted getcap drops the path            -> "tpm2_getcap is trust-walked before it runs"
//   W1  summary states the cause as fact           -> "key_unloadable hedges"
//   W2  hint tells the user to re-seal             -> "key_unloadable carries the do-not-run-setup caution"
//   W3  unloadable ignores the failing reason      -> "a load failure that is really another refusal"
//       observed after the run (not predicted): also reddened "a load that times out".
//       Likewise M6 was predicted to redden 3 tests and reddened 4: the extra one was
//       "a load failure that is really another refusal". W5 is unused (numbering gap).
//       The register lists 23 mutants: M1-M11, G1-G6, W1-W4, W6, W7.
//   W4  unloadable ignores the failing tool        -> "blobs that no longer load", "a load failure that is really another refusal"
//   W6  getcap is called with another capability   -> "a sealed key on a healthy host is ready", "visible saved sessions",
//                                                     "a count that cannot be read", "a leaked slot shows even when no key"
//   W7  untrustedAt does not stamp the path        -> "a trust refusal carries the tool as a structured path", "an untrusted tool is its own state"
// DEC-262 (a15) 2 and (a17): a flush that fails leaks a saved-session slot.
describe("a leaked session slot is warned about once and never retried", () => {
  const synthetic = new Uint8Array(32).fill(0x5a);
  async function sealed(modes: Record<string, string> = {}) {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, modes);
    const directory = join(base, "ward-tpm");
    const presence = detect({ path: bin, device: DEVICE });
    await sealKey(presence, synthetic, directory);
    rmSync(join(records, "calls.jsonl"), { force: true });
    return { directory, presence, records };
  }
  const flushCalls = (records: string) =>
    readFileSync(join(records, "calls.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { tool: string; args: string[] })
      .filter((call) => call.tool === "tpm2_flushcontext");

  test("a failed flush after a good unseal returns the key and warns exactly once, flushing only its own session once", async () => {
    const { directory, presence, records } = await sealed({
      tpm2_flushcontext: "fail",
    });
    const warnings: unknown[] = [];
    const key = await unsealKey(presence, directory, {
      onWarning: (warning) => warnings.push(warning),
    });
    expect(Buffer.from(key).equals(Buffer.from(synthetic))).toBe(true);
    expect(warnings).toEqual([{ code: "tpm_session_leaked" }]);
    // No path and no handle value in the warning.
    expect(JSON.stringify(warnings)).not.toMatch(/\/|0x/);
    // One flush attempt, no retry, and only the session Ward created.
    const flushes = flushCalls(records);
    expect(flushes).toHaveLength(1);
    expect(flushes[0]?.args).toHaveLength(1);
    expect(flushes[0]?.args[0]).toMatch(/unseal-[^/]+\/session\.ctx$/);
    expect(flushes[0]?.args[0]?.startsWith(directory)).toBe(true);
  });

  test("a warning listener whose promise rejects is not an unhandled rejection", async () => {
    const { directory, presence } = await sealed({ tpm2_flushcontext: "fail" });
    const unhandled: unknown[] = [];
    const listener = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", listener);
    try {
      const key = await unsealKey(presence, directory, {
        onWarning: async () => {
          throw new Error("async listener");
        },
      });
      expect(Buffer.from(key).equals(Buffer.from(synthetic))).toBe(true);
      // Let a stray rejection surface before judging.
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      process.off("unhandledRejection", listener);
    }
    expect(unhandled).toEqual([]);
  });

  test("a flush that works warns of nothing", async () => {
    const { directory, presence } = await sealed();
    const warnings: unknown[] = [];
    await unsealKey(presence, directory, {
      onWarning: (warning) => warnings.push(warning),
    });
    expect(warnings).toEqual([]);
  });

  test("a warning listener that throws does not take the key away", async () => {
    const { directory, presence } = await sealed({ tpm2_flushcontext: "fail" });
    const key = await unsealKey(presence, directory, {
      onWarning: () => {
        throw new Error("listener");
      },
    });
    expect(Buffer.from(key).equals(Buffer.from(synthetic))).toBe(true);
  });

  test("a failed flush after a FAILED unseal reports the unseal's error with the flush failure beside it, and no warning", async () => {
    const { directory, presence } = await sealed({
      tpm2_unseal: "fail",
      tpm2_flushcontext: "fail",
    });
    const warnings: unknown[] = [];
    const error = await unsealKey(presence, directory, {
      onWarning: (warning) => warnings.push(warning),
    }).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(Tpm2Error);
    expect(error).toMatchObject({
      reason: "tool_failed",
      detail: "tpm2_unseal",
      flushFailure: "tool_failed",
    });
    expect(warnings).toEqual([]);
  });

  test("a failed unseal whose flush works carries no flushFailure", async () => {
    const { directory, presence } = await sealed({ tpm2_unseal: "fail" });
    const error = await unsealKey(presence, directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({
      reason: "tool_failed",
      detail: "tpm2_unseal",
    });
    expect((error as Tpm2Error).flushFailure).toBeUndefined();
  });

  test("a session never saved is never flushed, so a failed flush cannot be claimed", async () => {
    const { directory, presence, records } = await sealed({
      tpm2_startauthsession: "fail-no-output",
      tpm2_flushcontext: "fail",
    });
    const warnings: unknown[] = [];
    const error = await unsealKey(presence, directory, {
      onWarning: (warning) => warnings.push(warning),
    }).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect((error as Tpm2Error).flushFailure).toBeUndefined();
    expect(flushCalls(records)).toHaveLength(0);
    expect(warnings).toEqual([]);
  });
});

// DEC-262 (a15) 1, (a16) Q1, (a17) Q1: the doctor states, read from the
// Tpm2Error (reason and detail), through a pure adapter-level diagnosis.
describe("the TPM2 doctor states", () => {
  const synthetic = new Uint8Array(32).fill(0x5a);
  async function sealed(modes: Record<string, string> = {}) {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, modes);
    const directory = join(base, "ward-tpm");
    const presence = detect({ path: bin, device: DEVICE });
    await sealKey(presence, synthetic, directory);
    rmSync(join(records, "calls.jsonl"), { force: true });
    return { bin, directory, presence, records };
  }
  const diagnose = (
    bin: string,
    directory: string,
    host: Partial<Tpm2Host> = {},
    trustedUids?: readonly number[],
  ) =>
    diagnoseTpm2ForTest(
      { path: bin, device: DEVICE, ...host },
      { trustRoot: root, trustedUids },
      directory,
    );

  test("a sealed key on a healthy host is ready, with no attention state", async () => {
    const { bin, directory } = await sealed();
    expect(await diagnose(bin, directory)).toEqual({
      state: { state: "ready" },
    });
  });

  test("diagnosing runs no session and no unseal", async () => {
    const { bin, directory, records } = await sealed();
    await diagnose(bin, directory);
    const tools = readFileSync(join(records, "calls.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => (JSON.parse(line) as { tool: string }).tool);
    expect(tools).toContain("tpm2_load");
    for (const refused of [
      "tpm2_unseal",
      "tpm2_startauthsession",
      "tpm2_flushcontext",
    ])
      expect(tools).not.toContain(refused);
  });

  test("no TPM device is unsupported (s1), and a refused open is access_refused (s2)", async () => {
    const { bin, directory } = await sealed();
    expect(
      (await diagnose(bin, directory, { device: join(bin, "nope") })).state,
    ).toEqual({ state: "unsupported", code: "tpm_absent" });
    expect(
      (await diagnose(bin, directory, { openCheck: denied })).state,
    ).toEqual({ state: "access_refused", code: "tpm_access_refused" });
  });

  test("the unsupported state groups two reasons that keep two codes", () => {
    expect(tpm2StateFor(new Tpm2Error("tpm_absent"))).toEqual({
      state: "unsupported",
      code: "tpm_absent",
    });
    expect(tpm2StateFor(new Tpm2Error("platform_unsupported"))).toEqual({
      state: "unsupported",
      code: "tpm_platform_unsupported",
    });
  });

  test("a trust refusal carries the tool as a structured path, not parsed out of the detail", async () => {
    const { bin } = await sealed();
    const error = refusal(() =>
      detect({ path: bin, device: DEVICE }, [999_999]),
    );
    expect(error.reason).toBe("tool_untrusted");
    expect(error.path).toBe(join(bin, "tpm2_createprimary"));
    // Not derived from the detail text.
    expect(error.detail?.startsWith(`${error.path}: `)).toBe(true);
    const bare = new Tpm2Error("tool_untrusted", "x: y");
    expect(tpm2StateFor(bare).path).toBeUndefined();
  });

  test("an untrusted tool is its own state and names the path", async () => {
    const { bin, directory } = await sealed();
    const { state } = await diagnose(bin, directory, {}, [999_999]);
    expect(state).toEqual({
      state: "tool_untrusted",
      code: "tpm_tool_untrusted",
      path: join(bin, "tpm2_createprimary"),
    });
  });

  test("a tool whose printout changed is tool_incompatible naming the version, never not-encrypted; an off printout is the other state", async () => {
    const changed = await sealed({
      tpm2_sessionconfig: "session-unknown-token",
    });
    const incompatible = await unsealKey(
      changed.presence,
      changed.directory,
    ).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(tpm2StateFor(incompatible as Tpm2Error)).toEqual({
      state: "tool_incompatible",
      code: "tpm_tool_incompatible",
      version: "5.6",
    });
    const off = await sealed({ tpm2_sessionconfig: "session-off" });
    const refused = await unsealKey(off.presence, off.directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(tpm2StateFor(refused as Tpm2Error)).toEqual({
      state: "session_not_encrypted",
      code: "tpm_session_not_encrypted",
    });
  });

  test("a wide blob is blob_not_user_private", async () => {
    const { bin, directory } = await sealed();
    chmodSync(join(directory, sealedPrivateName), 0o644);
    expect((await diagnose(bin, directory)).state).toEqual({
      state: "blob_not_user_private",
      code: "tpm_blob_not_user_private",
    });
  });

  test("a lone .priv is key_incomplete with the do-not-run-setup hint; a lone .pub is key_not_sealed", async () => {
    const { bin, directory } = await sealed();
    rmSync(join(directory, sealedPublicName));
    const incomplete = await diagnose(bin, directory);
    expect(incomplete.state).toEqual({
      state: "key_incomplete",
      code: "tpm_key_incomplete",
    });
    expect(errorCatalog.tpm_key_incomplete.hint).toContain(
      "Do not run `ward setup`",
    );
    const lone = await sealed();
    rmSync(join(lone.directory, sealedPrivateName));
    expect((await diagnose(lone.bin, lone.directory)).state).toEqual({
      state: "key_not_sealed",
      code: "tpm_key_not_sealed",
    });
  });

  test("blobs that no longer load are key_unloadable; a failed primary is not", async () => {
    const cleared = await sealed({ tpm2_load: "fail" });
    expect((await diagnose(cleared.bin, cleared.directory)).state).toEqual({
      state: "key_unloadable",
      code: "tpm_tool_failed",
      summary: keyUnloadableSummary,
      hint: keyUnloadableHint,
    });
    const broken = await sealed();
    // The seal ran with working fakes; only the probe's primary breaks now.
    installFakeTools(broken.bin, join(broken.bin, "..", "records"), {
      tpm2_createprimary: "fail",
    });
    expect((await diagnose(broken.bin, broken.directory)).state.state).toBe(
      "tool_failed",
    );
  });

  // DEC-262 (a18) 1: hedged wording, never "the TPM was cleared".
  test("key_unloadable hedges: could not be loaded, a TPM clear is a likely cause, never that it was cleared", () => {
    expect(keyUnloadableSummary).toContain("could not be loaded");
    expect(keyUnloadableSummary).toContain("tpm2_clear");
    expect(keyUnloadableSummary).toContain("is a likely cause, among others");
    expect(keyUnloadableSummary).not.toMatch(
      /was cleared|has been cleared|were cleared|is cleared/i,
    );
  });

  // DEC-262 (a18) 2: no destructive advice, the do-NOT-run-setup caution.
  test("key_unloadable carries the do-not-run-setup caution and no instruction at all", () => {
    const caution = "Do not run `ward setup`";
    expect(keyUnloadableHint.startsWith(caution)).toBe(true);
    expect(keyUnloadableHint).toContain("only copy");
    expect(errorCatalog.tpm_key_incomplete.hint).toContain(caution);
    // Beyond the caution itself, nothing tells the user to run, re-seal,
    // delete or remove anything; and the summary is no instruction either.
    const rest = keyUnloadableHint.slice(caution.length);
    expect(rest).not.toMatch(/run|re-?seal|delete|remove/i);
    expect(keyUnloadableSummary).not.toMatch(
      /run .*setup|re-?seal|delete|remove/i,
    );
  });

  // DEC-262 (a18) 3: key_unloadable is the remainder; each specific state wins.
  test("a load failure that is really another refusal reports as that state, and only a plain tpm2_load tool failure is unloadable", async () => {
    for (const reason of [
      "tpm_not_accessible",
      "tool_untrusted",
      "tool_incompatible",
      "tool_timeout",
      "tool_output_too_large",
    ] as const) {
      // The same detail a load failure carries: the reason alone decides.
      const state = tpm2StateFor(new Tpm2Error(reason, "tpm2_load"));
      expect(state.state).not.toBe("key_unloadable");
    }
    expect(tpm2StateFor(new Tpm2Error("tool_failed", "tpm2_load")).state).toBe(
      "key_unloadable",
    );
    // Other tool failures are not unloadable.
    expect(
      tpm2StateFor(new Tpm2Error("tool_failed", "tpm2_unseal")).state,
    ).toBe("tool_failed");
  });

  const loadCalls = (records: string) =>
    existsSync(join(records, "tpm2_load.json")) ||
    (existsSync(join(records, "calls.jsonl")) &&
      readFileSync(join(records, "calls.jsonl"), "utf8").includes(
        '"tpm2_load"',
      ));

  test("with tpm2_load failing, a refused open is access_refused and an untrusted tool is tool_untrusted, and the load is never reached", async () => {
    const refused = await sealed({ tpm2_load: "fail" });
    expect(
      (await diagnose(refused.bin, refused.directory, { openCheck: denied }))
        .state.state,
    ).toBe("access_refused");
    expect(loadCalls(refused.records)).toBe(false);
    const untrusted = await sealed({ tpm2_load: "fail" });
    expect(
      (await diagnose(untrusted.bin, untrusted.directory, {}, [999_999])).state
        .state,
    ).toBe("tool_untrusted");
    expect(loadCalls(untrusted.records)).toBe(false);
    // Positive control: with neither refusal, the same fake IS reached.
    const reached = await sealed({ tpm2_load: "fail" });
    expect((await diagnose(reached.bin, reached.directory)).state.state).toBe(
      "key_unloadable",
    );
    expect(loadCalls(reached.records)).toBe(true);
  });

  test("a load that times out is a timeout, not an unloadable key", async () => {
    const slow = await sealed({ tpm2_load: "hang" });
    const timed = await diagnoseTpm2ForTest(
      { path: slow.bin, device: DEVICE },
      { trustRoot: root },
      slow.directory,
      { timeoutMs: 300 },
    );
    expect(timed.state.state).toBe("tool_timeout");
  });

  // MUTANT REGISTER, 3d-2b(i), written BEFORE any run. Bun 1.3.14 on each observation.
  //   I1 countSavedSessions never calls the sink              -> "a tpm2_getcap that times out tells the abandon sink..."
  //   I2 diagnoseWith never calls the sink                    -> "a load that times out tells the abandon sink..."
  //   I3 the sink is called unguarded                         -> "an abandon sink that throws does not change what doctor reports"
  //   I4 every tool failure calls the sink                    -> "an ordinary tool failure does not tell the abandon sink"
  //   I5 (test/reporting.test.ts) catalogEntry loses its `?? {}`  -> "a code the catalog does not know fails closed to the state name, never a throw"
  // OBSERVED (bun 1.3.14, 2026-11-17; predictions unchanged). I1, I2, I4, I5 went red on exactly their predicted tests. I3 went red on exactly its predicted test when run alone; in the first combined run it stalled the suite (an unguarded listener throw), so that run was killed and I3 re-run alone.
  // MUTANT REGISTER, #351 round-1 fixes, written BEFORE any run. Bun 1.3.14 on each observation.
  //   J1 diagnoseWith's createprimary timeout does not tell the sink      -> "a createprimary that times out tells the abandon sink once..."
  //   J2 diagnoseWith's sink call is unguarded                            -> "an abandon sink that throws does not change what doctor reports" (its load variant)
  //   J3 (test/reporting.test.ts) the catalog fail-closed value is the state name again -> "a code the catalog does not know fails closed to fixed prose, never a throw"
  // OBSERVED (#351 round-1 fixes, bun 1.3.14, 2026-11-17; predictions unchanged). J2 and J3 went red on exactly their predicted tests (J2 run alone, as I3 stalls a combined run). J1 also reddened the load-timeout test, since the mutant skips the sink for every tool_timeout at that site, not only createprimary's.
  // WCLI-21 3d-2b(i): doctor's own tool runs tell the abandon sink, so the
  // command exits explicitly, and the doctor state stays what it was.
  const diagnoseSunk = async (
    modes: Record<string, string>,
    onAbandon: () => void,
  ) => {
    const host = await sealed(modes);
    return await diagnoseTpm2ForTest(
      { path: host.bin, device: DEVICE },
      { trustRoot: root },
      host.directory,
      { timeoutMs: 400, onAbandon },
    );
  };

  test("a tpm2_getcap that times out tells the abandon sink and the count is still unavailable", async () => {
    let told = 0;
    const out = await diagnoseSunk({ tpm2_getcap: "hang" }, () => {
      told += 1;
    });
    expect(told).toBe(1);
    expect(out).toEqual({
      state: { state: "ready" },
      savedSessions: { unavailable: "tool_failed" },
    });
  });

  test("a load that times out tells the abandon sink once and the state is tool_timeout", async () => {
    let told = 0;
    const out = await diagnoseSunk({ tpm2_load: "hang" }, () => {
      told += 1;
    });
    expect(out.state.state).toBe("tool_timeout");
    // The default getcap fake prints nothing, so exactly one abandon is the
    // load's.
    expect(told).toBe(1);
  });

  // The fixture is sealed with working tools, then tpm2_createprimary is made
  // to hang for the diagnosis alone (sealing uses it too).
  test("a createprimary that times out tells the abandon sink once, the state is tool_timeout, and no load runs", async () => {
    const host = await sealed();
    installFakeTools(host.bin, host.records, { tpm2_createprimary: "hang" });
    let told = 0;
    const out = await diagnoseTpm2ForTest(
      { path: host.bin, device: DEVICE },
      { trustRoot: root },
      host.directory,
      {
        timeoutMs: 400,
        onAbandon: () => {
          told += 1;
        },
      },
    );
    expect(out.state.state).toBe("tool_timeout");
    expect(told).toBe(1);
    expect(loadCalls(host.records)).toBe(false);
  });

  test("an ordinary tool failure does not tell the abandon sink", async () => {
    let told = 0;
    const sink = () => {
      told += 1;
    };
    expect(
      (await diagnoseSunk({ tpm2_getcap: "fail" }, sink)).savedSessions,
    ).toEqual({ unavailable: "tool_failed" });
    expect((await diagnoseSunk({ tpm2_load: "fail" }, sink)).state.state).toBe(
      "key_unloadable",
    );
    expect(told).toBe(0);
  });

  test("an abandon sink that throws does not change what doctor reports", async () => {
    const throwing = () => {
      throw new Error("synthetic listener fault");
    };
    // getcap's site: the state is still ready and the count unavailable.
    expect(await diagnoseSunk({ tpm2_getcap: "hang" }, throwing)).toEqual({
      state: { state: "ready" },
      savedSessions: { unavailable: "tool_failed" },
    });
    // diagnoseWith's site: the state is still tool_timeout.
    expect(
      (await diagnoseSunk({ tpm2_load: "hang" }, throwing)).state.state,
    ).toBe("tool_timeout");
  });

  test("the unseal path and diagnoseTpm2 agree: a failing load is key_unloadable by either, an incompatible printout is tool_incompatible and never key_unloadable", async () => {
    const failing = await sealed({ tpm2_load: "fail" });
    const viaUnseal = await unsealKey(failing.presence, failing.directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(tpm2StateFor(viaUnseal as Tpm2Error).state).toBe("key_unloadable");
    expect(tpm2StateFor(viaUnseal as Tpm2Error)).toEqual(
      (await diagnose(failing.bin, failing.directory)).state,
    );
    const changed = await sealed({
      tpm2_sessionconfig: "session-unknown-token",
    });
    const error = await unsealKey(changed.presence, changed.directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(tpm2StateFor(error as Tpm2Error).state).toBe("tool_incompatible");
    expect(tpm2StateFor(error as Tpm2Error).state).not.toBe("key_unloadable");
  });

  test("visible saved sessions are an attention state beside the state, not a failure, and name what clears them", async () => {
    const two = await sealed({ tpm2_getcap: "saved-2" });
    expect(await diagnose(two.bin, two.directory)).toEqual({
      state: { state: "ready" },
      savedSessions: { count: 2, clearedBy: "reset or reboot" },
    });
    const one = await sealed({ tpm2_getcap: "saved-1" });
    expect((await diagnose(one.bin, one.directory)).savedSessions).toEqual({
      count: 1,
      clearedBy: "reset or reboot",
    });
  });

  // DEC-262 (a15) 2: the count is an attention state that never fails doctor,
  // so an unreadable count is "unavailable": not a failure, and not zero.
  test("a count that cannot be read is unavailable, never zero and never a failure", async () => {
    const weird = await sealed({ tpm2_getcap: "saved-weird" });
    expect(await diagnose(weird.bin, weird.directory)).toEqual({
      state: { state: "ready" },
      savedSessions: { unavailable: "output_unrecognised" },
    });
    const failing = await sealed({ tpm2_getcap: "fail" });
    expect(await diagnose(failing.bin, failing.directory)).toEqual({
      state: { state: "ready" },
      savedSessions: { unavailable: "tool_failed" },
    });
  });

  test("a host without tpm2_getcap is still supported: sealing, unsealing and the state are unaffected, and the count is unavailable", async () => {
    const { bin, directory, presence } = await sealed({
      tpm2_getcap: "absent",
    });
    expect(existsSync(join(bin, "tpm2_getcap"))).toBe(false);
    expect(Object.keys(presence.tools)).not.toContain("tpm2_getcap");
    const key = await unsealKey(presence, directory);
    expect(Buffer.from(key).equals(Buffer.from(synthetic))).toBe(true);
    expect(await diagnose(bin, directory)).toEqual({
      state: { state: "ready" },
      savedSessions: { unavailable: "tool_absent" },
    });
  });

  test("tpm2_getcap is trust-walked before it runs: an untrusted one is never executed", async () => {
    const { bin, directory, records } = await sealed({
      tpm2_getcap: "saved-2",
    });
    chmodSync(join(bin, "tpm2_getcap"), 0o777);
    // The required tools still pass detection; only the diagnostic tool fails.
    // (a19): the reason AND the path are structured fields, exact.
    expect(await diagnose(bin, directory)).toEqual({
      state: { state: "ready" },
      savedSessions: {
        unavailable: "tool_untrusted",
        path: join(bin, "tpm2_getcap"),
      },
    });
    expect(existsSync(join(records, "tpm2_getcap.json"))).toBe(false);
    // Positive control: the diagnosis did run other tools (the load), and not
    // one getcap row is in the call log.
    const log = readFileSync(join(records, "calls.jsonl"), "utf8");
    expect(log).toContain('"tpm2_load"');
    expect(log).not.toContain("tpm2_getcap");
  });

  test("a leaked slot shows even when no key is sealed", async () => {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_getcap: "saved-1" });
    const diagnosis = await diagnose(bin, join(base, "ward-tpm"));
    expect(diagnosis.state.state).toBe("key_not_sealed");
    expect(diagnosis.savedSessions).toEqual({
      count: 1,
      clearedBy: "reset or reboot",
    });
  });

  test("every reason has a doctor state carrying its own contract code", () => {
    const reasons = Object.keys(tpm2ErrorCodes) as Tpm2Reason[];
    expect(reasons.length).toBeGreaterThan(10);
    for (const reason of reasons)
      expect(tpm2StateFor(new Tpm2Error(reason)).code).toBe(
        tpm2ErrorCodes[reason],
      );
  });
});

// DEC-262 (a15): each Tpm2Reason maps to exactly ONE contract code, never
// merged. The Record type makes a new reason fail to compile; these hold the
// values distinct and real, and the text fixed.
describe("every Tpm2Reason has its own contract code", () => {
  test("the codes are pairwise distinct and each is in the error catalog", () => {
    const codes = Object.values(tpm2ErrorCodes);
    expect(codes.length).toBeGreaterThanOrEqual(16);
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) expect(code in errorCatalog).toBe(true);
  });

  test("the ruled mappings", () => {
    expect(tpm2ErrorCodes.platform_unsupported).toBe(
      "tpm_platform_unsupported",
    );
    expect(tpm2ErrorCodes.tpm_absent).toBe("tpm_absent");
    expect(tpm2ErrorCodes.tpm_not_accessible).toBe("tpm_access_refused");
    expect(tpm2ErrorCodes.blob_not_user_private).toBe(
      "tpm_blob_not_user_private",
    );
    expect(tpm2ErrorCodes.key_not_sealed).toBe("tpm_key_not_sealed");
    expect(tpm2ErrorCodes.key_incomplete).toBe("tpm_key_incomplete");
    expect(tpm2ErrorCodes.key_exists).toBe("tpm_key_exists");
    expect(tpm2ErrorCodes.tool_untrusted).toBe("tpm_tool_untrusted");
    // NB6: not-encrypted and not-recognised are two codes.
    expect(tpm2ErrorCodes.session_not_encrypted).not.toBe(
      tpm2ErrorCodes.tool_incompatible,
    );
  });

  test("the contract error carries the catalog's fixed text, never a path or a tool version", () => {
    const secret = "/home/someone/ward-tpm tpm2-tools 5.6";
    for (const reason of Object.keys(tpm2ErrorCodes) as Array<
      keyof typeof tpm2ErrorCodes
    >) {
      const error = wardErrorFor(new Tpm2Error(reason, secret));
      expect(error.code).toBe(tpm2ErrorCodes[reason]);
      expect(error.message).toBe(errorCatalog[error.code].message);
      expect(error.message).not.toContain("/home/someone");
      expect(error.message).not.toContain("5.6");
    }
  });
});

// WCLI-21 slice 3d-1a: WCLI-158 and N4.
describe("a timed-out tool and a spawn that threw", () => {
  const alive = (pid: number) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  };

  test(
    "a timed-out tool's grandchild is killed with it",
    async () => {
      const { bin, records } = fresh();
      installFakeTools(bin, records, { tpm2_unseal: "grandchild-hang" });
      const presence = detect({ path: bin, device: DEVICE });
      const pidFile = join(records, "grandchild.pid");
      try {
        const reason = await runTool(presence, "tpm2_unseal", [], {
          timeoutMs: 2_500,
        }).catch((e) => e.reason);
        expect(reason).toBe("tool_timeout");
        expect(readFileSync(pidFile, "utf8")).toMatch(/^[1-9]\d*$/);
        const pid = Number(readFileSync(pidFile, "utf8"));
        // The group kill is a signal: give the kernel a moment to reap.
        for (let wait = 0; wait < 50 && alive(pid); wait++)
          await new Promise((resolve) => setTimeout(resolve, 20));
        expect(alive(pid)).toBe(false);
      } finally {
        killGrandchild(pidFile);
      }
    },
    { timeout: 30_000 },
  );

  test(
    "a timed-out tool lets the process exit",
    async () => {
      const { bin, records } = fresh();
      const probe = join(
        import.meta.dir,
        "fixtures",
        "tpm2-timeout-exit-probe.ts",
      );
      const child = Bun.spawn([process.execPath, probe, bin, records, root], {
        stdout: "pipe",
        stderr: "pipe",
      });
      const pidFile = join(records, "grandchild.pid");
      try {
        const outcome = await Promise.race([
          child.exited.then(() => "exited"),
          new Promise<string>((resolve) =>
            setTimeout(() => resolve("still running"), 20_000),
          ),
        ]);
        expect(outcome).toBe("exited");
        expect(await new Response(child.stdout).text()).toContain(
          "done tool_timeout",
        );
      } finally {
        child.kill(9);
        killGrandchild(pidFile);
      }
    },
    { timeout: 40_000 },
  );

  test(
    "a flush timeout after a good unseal calls onAbandon and still returns the key",
    async () => {
      const { base, bin, records } = fresh();
      installFakeTools(bin, records, { tpm2_flushcontext: "hang" });
      const directory = join(base, "ward-tpm");
      const presence = detect({ path: bin, device: DEVICE });
      const key = new Uint8Array(32).fill(0x5a);
      await sealKey(presence, key, directory);
      let abandoned = 0;
      const warnings: unknown[] = [];
      try {
        const got = await unsealKey(presence, directory, {
          timeoutMs: 2_500,
          onAbandon: () => {
            abandoned += 1;
          },
          onWarning: (warning) => warnings.push(warning),
        });
        expect(Buffer.from(got).equals(Buffer.from(key))).toBe(true);
      } finally {
        killGrandchild(join(records, "grandchild.pid"));
      }
      expect(abandoned).toBe(1);
      expect(warnings).toEqual([{ code: "tpm_session_leaked" }]);
    },
    { timeout: 30_000 },
  );

  test(
    "a tpm2-tools version probe that times out still calls onAbandon",
    async () => {
      const { base, bin, records } = fresh();
      installFakeTools(bin, records, {
        tpm2_sessionconfig: "session-zero+version-hang",
      });
      const directory = join(base, "ward-tpm");
      const presence = detect({ path: bin, device: DEVICE });
      await sealKey(presence, new Uint8Array(32).fill(0x5a), directory);
      let abandoned = 0;
      try {
        const error = await unsealKey(presence, directory, {
          timeoutMs: 2_500,
          onAbandon: () => {
            abandoned += 1;
          },
        }).then(
          () => undefined,
          (caught: unknown) => caught,
        );
        // The refusal is unchanged: the version only labels it.
        expect(error).toMatchObject({
          reason: "tool_incompatible",
          detail: "tpm2-tools unknown",
        });
      } finally {
        killGrandchild(join(records, "grandchild.pid"));
      }
      expect(abandoned).toBe(1);
    },
    { timeout: 30_000 },
  );

  test("a non-Tpm2Error unseal failure keeps flushFailure", async () => {
    const { base, bin, records } = fresh();
    installFakeTools(bin, records, { tpm2_flushcontext: "fail" });
    const directory = join(base, "ward-tpm");
    const presence = detect({ path: bin, device: DEVICE });
    await sealKey(presence, new Uint8Array(32).fill(0x5a), directory);
    // The unseal tool vanishes after detection: Bun.spawn throws, which is
    // not a Tpm2Error, and the session the start step saved is still flushed.
    rmSync(join(bin, "tpm2_unseal"));
    const error = await unsealKey(presence, directory).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(Tpm2Error);
    expect(error).toMatchObject({
      reason: "tool_failed",
      flushFailure: "tool_failed",
    });
    // The spawn error's text (it names the tool's path) is not passed on.
    expect((error as Tpm2Error).detail).toBeUndefined();
    expect((error as Tpm2Error).message).not.toContain(bin);
  });
});
