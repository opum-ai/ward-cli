// WCLI-21 slice 4a-2b-2, part A: the rows and support the harness script wires
// (the shim rows in requiredChecks, the expected-call-set row, the control call,
// the latin1 log, the diagnostic tool through the interposers, the path-name scan)
// and one end-to-end test that drives the real adapter through real interposers
// over fake tools. No TPM is reached and nothing here runs the script.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  detectTpm2ForTest,
  diagnosticTool,
  requiredTools,
  runTool,
  sealKey,
  tpmDevicePath,
  unsealKey,
} from "../src/adapters/tpm2-tools.ts";
import {
  envControlRow,
  expectedCallsRow,
  expectedTools,
  parseToolLog,
  tctiRow,
  type ToolCall,
} from "../scripts/qualify-linux-rows.ts";
import {
  argvRow,
  changedFiles,
  envRow,
  installInterposers,
  interposerScript,
  listWindowRoots,
  readToolLog,
  scanWindow,
  windowRow,
  withDiagnosticTool,
  withheldPath,
  expectedEnvironment,
} from "../scripts/qualify-linux-shim.ts";
import {
  type Check,
  deriveKey,
  needleForms,
  requiredChecks,
  secretNeedles,
  verdict,
} from "../scripts/qualify-linux-support.ts";
import { installFakeTools } from "./fixtures/fake-tpm2/install.ts";

const root = realpathSync(mkdtempSync(join(tmpdir(), "ward-qualify-wiring-")));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let counter = 0;
const fresh = (name: string): string => {
  const dir = join(root, `${name}-${counter++}`);
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  return dir;
};
const uid = process.getuid?.() ?? 0;
const nonce =
  "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";

const shimRows = [
  "key-not-in-tool-environment",
  "key-not-in-tool-argv",
  "report-states-the-logging-shim",
  "expected-tool-calls-made",
  "interposer-env-matches-tool-env",
];
const windowName = "key-not-in-files-present-at-the-after-listing";

describe("the shim rows are required, so a run that never produced one cannot pass", () => {
  const allOk = (phase: keyof typeof requiredChecks): Check[] =>
    requiredChecks[phase].map((name) => ({ name, ok: true }));

  test("seal, unseal and clean require the shim rows, seal and unseal the window row; facts and deliver owe none (DEC-262 a32)", () => {
    for (const phase of ["seal", "unseal", "clean"] as const) {
      for (const name of shimRows)
        expect(requiredChecks[phase]).toContain(name);
      expect(requiredChecks[phase].includes(windowName)).toBe(
        phase !== "clean",
      );
    }
    // P0 is read-only with no interposer and handles no key; the delivery phase
    // runs no tool. Neither owes a shim row or the window row.
    for (const phase of ["facts", "deliver"] as const)
      for (const name of [...shimRows, windowName])
        expect(requiredChecks[phase]).not.toContain(name);
  });

  test("with every required row present and ok a phase passes, and dropping any one shim row fails it", () => {
    for (const phase of ["facts", "seal", "unseal", "clean"] as const) {
      expect(verdict(phase, allOk(phase))).toBe("PASSED");
      for (const name of [...shimRows, windowName]) {
        if (!requiredChecks[phase].includes(name)) continue;
        expect(
          verdict(
            phase,
            allOk(phase).filter((check) => check.name !== name),
          ),
        ).toBe("FAILED");
        expect(
          verdict(
            phase,
            allOk(phase).map((check) =>
              check.name === name ? { ...check, ok: false } : check,
            ),
          ),
        ).toBe("FAILED");
      }
    }
  });
});

describe("the run-wide rows sit on the phases DEC-262 (a33) assigns", () => {
  test("facts owes none of them, deliver owes the ward-metadata row only, and seal, unseal and clean owe all three", () => {
    const tcti = "tcti-is-device-tpmrm0";
    const handles = "handle-lists-unchanged";
    const metadata = "real-ward-metadata-unchanged";
    for (const name of [tcti, handles, metadata])
      expect(requiredChecks.facts).not.toContain(name);
    expect(requiredChecks.deliver).toContain(metadata);
    expect(requiredChecks.deliver).not.toContain(tcti);
    expect(requiredChecks.deliver).not.toContain(handles);
    for (const phase of ["seal", "unseal", "clean"] as const)
      for (const name of [tcti, handles, metadata])
        expect(requiredChecks[phase]).toContain(name);
  });

  test("facts passes on exactly the rows its four commands can produce", () => {
    expect([...requiredChecks.facts].sort()).toEqual([
      "effective-groups-recorded",
      "python3-recorded",
      "tpm-device-present",
      "tpm2-tools-present",
    ]);
  });
});

describe("the expected call set", () => {
  const call = (tool: string): ToolCall => ({
    tool,
    tcti: "device:/dev/tpmrm0",
    args: [],
  });

  test("every tool a phase must run, and none outside its set, passes", () => {
    for (const phase of ["seal", "unseal", "clean"] as const) {
      const set = expectedTools[phase];
      const calls = set.required.map(call);
      expect(expectedCallsRow(phase, calls).ok).toBe(true);
      expect(expectedCallsRow(phase, calls).name).toBe(
        "expected-tool-calls-made",
      );
      // A repeated call is fine.
      expect(expectedCallsRow(phase, [...calls, ...calls]).ok).toBe(true);
      // A required tool that was never logged fails, each in turn.
      for (const tool of set.required)
        expect(
          expectedCallsRow(
            phase,
            calls.filter((c) => c.tool !== tool),
          ).ok,
        ).toBe(false);
      // A tool outside the phase's set fails.
      expect(
        expectedCallsRow(phase, [...calls, call("tpm2_evictcontrol")]).ok,
      ).toBe(false);
    }
  });

  test("no calls, and an unknown phase, fail; the unseal phase creates nothing", () => {
    expect(expectedCallsRow("seal", []).ok).toBe(false);
    // facts runs no interposer (a32), so it has no call set to satisfy.
    expect(expectedCallsRow("facts", [call(diagnosticTool)]).ok).toBe(false);
    expect(expectedCallsRow("not-a-phase", [call(diagnosticTool)]).ok).toBe(
      false,
    );
    expect(expectedCallsRow("toString", [call(diagnosticTool)]).ok).toBe(false);
    expect(expectedTools.unseal.required).not.toContain("tpm2_create");
    expect(
      expectedCallsRow("unseal", [
        ...expectedTools.unseal.required.map(call),
        call("tpm2_create"),
      ]).ok,
    ).toBe(false);
    expect(expectedTools.seal.required).toEqual([
      ...requiredTools,
      diagnosticTool,
    ]);
  });
});

describe("the control call: what the interposer logged is what a tool received", () => {
  const digest = (value: string) =>
    new Bun.CryptoHasher("sha256").update(value).digest("hex");
  const env = { PATH: "/a:/bin", LANG: "C" };
  const logged = Object.entries(env).map(([name, value]) => ({
    name,
    digest: digest(value),
  }));
  const printed = Object.entries(env)
    .map(([name, value]) => `${name}=${value}`)
    .join("\n");

  test("the same names with the same value digests pass; a missing, extra, changed or repeated name fails", () => {
    expect(envControlRow(logged, `${printed}\n`).ok).toBe(true);
    expect(envControlRow(logged, `${printed}\n`).name).toBe(
      "interposer-env-matches-tool-env",
    );
    expect(envControlRow(logged, "PATH=/a:/bin\n").ok).toBe(false);
    expect(envControlRow(logged, `${printed}\nSHLVL=1\n`).ok).toBe(false);
    expect(envControlRow(logged, `PATH=/a:/bin\nLANG=POSIX\n`).ok).toBe(false);
    expect(envControlRow(logged, `${printed}\nLANG=C\n`).ok).toBe(false);
    expect(envControlRow(logged, "garbage line\n").ok).toBe(false);
    expect(envControlRow(undefined, `${printed}\n`).ok).toBe(false);
    expect(envControlRow([], "").ok).toBe(false);
    // A logged name repeated passes a one-directional comparison when the count
    // matches (round 1, N2): the names must be the same set.
    const dup = [logged[0], logged[0]] as typeof logged;
    expect(envControlRow(dup, `${printed}\n`).ok).toBe(false);
    // A printed byte above 0x7f is hashed as the single byte the log's latin1
    // read holds, not as its two-byte utf8 form.
    const high = [
      {
        name: "X",
        digest: createHash("sha256")
          .update(Buffer.from([0xe9]))
          .digest("hex"),
      },
    ];
    expect(envControlRow(high, "X=\u00e9\n").ok).toBe(true);
  });

  test("a value is never kept in the row", () => {
    const row = envControlRow(logged, `${printed}\n`);
    expect(JSON.stringify(row)).not.toContain("/a:/bin");
  });

  test("a real interposer in front of /usr/bin/env passes it on this host's shell", () => {
    const dir = fresh("control");
    const log = join(dir, "tools.log");
    writeFileSync(log, "", { mode: 0o600 });
    const script = join(dir, "tpm2_load");
    writeFileSync(
      script,
      interposerScript("tpm2_load", "/usr/bin/env", log, false),
      { mode: 0o700 },
    );
    const result = Bun.spawnSync(["/bin/sh", script], {
      env: expectedEnvironment(dir),
    });
    const [call] = readToolLog(log);
    expect(
      envControlRow(call?.env, Buffer.from(result.stdout).toString("latin1"))
        .ok,
    ).toBe(true);
  });
});

describe("the tool log is read as bytes", () => {
  test("an argument of raw key bytes that are not valid UTF-8 is found, and a utf8 read would lose it", () => {
    // 0xff and 0xfe never occur in UTF-8; no newline or NUL, which the shell and
    // the log format could not carry.
    const key = Buffer.from([
      0xff, 0xfe, 0xc3, 0x28, 0xa0, 0xa1, 0xe2, 0x28, 0xa1, 0xf0, 0x90, 0x28,
      0xbc, 0xf8, 0xa1, 0xa1, 0xa1, 0xa1,
    ]);
    const forms = needleForms([key]);
    const dir = fresh("latin1");
    const log = join(dir, "tools.log");
    writeFileSync(log, "", { mode: 0o600 });
    const tool = join(dir, "fake-tool");
    writeFileSync(tool, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    const script = join(dir, "tpm2_load");
    writeFileSync(script, interposerScript("tpm2_load", tool, log, false), {
      mode: 0o700,
    });
    // A JS string argument is sent as UTF-8, so the raw bytes are produced by a
    // driver script's printf, which passes them to the interposer as one argument.
    const octal = [...key].map((b) => `\\${b.toString(8).padStart(3, "0")}`);
    const driver = join(dir, "driver");
    writeFileSync(
      driver,
      `#!/bin/sh\nexec /bin/sh '${script}' -i "$(printf '${octal.join("")}')"\n`,
      { mode: 0o700 },
    );
    const result = Bun.spawnSync(["/bin/sh", driver], {
      env: expectedEnvironment(dir),
    });
    expect(result.exitCode).toBe(0);
    // The log holds the raw bytes, and decoded as latin1 they are found ...
    expect(readFileSync(log).includes(key)).toBe(true);
    expect(argvRow(readToolLog(log), forms).ok).toBe(false);
    // ... where a utf8 decode replaces them with U+FFFD and finds nothing.
    expect(argvRow(parseToolLog(readFileSync(log, "utf8")), forms).ok).toBe(
      true,
    );
  });
});

describe("tpm2_getcap goes through the interposers", () => {
  const presenceIn = (bin: string) => {
    const records = join(bin, "..", "records");
    installFakeTools(bin, records);
    return detectTpm2ForTest(
      { path: bin, device: "/dev/null" },
      { trustRoot: root },
    );
  };
  const noTrust = () => undefined;

  test("it is resolved on the search path, trusted by the walk it is given, and added beside the required tools", () => {
    const base = fresh("getcap");
    const bin = join(base, "bin");
    const presence = presenceIn(bin);
    const trusted: string[] = [];
    const withCap = withDiagnosticTool(presence, bin, (path) =>
      trusted.push(path),
    );
    expect(withCap.tools[diagnosticTool]).toBe(join(bin, diagnosticTool));
    expect(trusted).toEqual([join(bin, diagnosticTool)]);
    expect(withCap.device).toBe(presence.device);
    for (const tool of requiredTools)
      expect(withCap.tools[tool]).toBe(presence.tools[tool]);
    // The input presence is not changed.
    expect(presence.tools[diagnosticTool]).toBeUndefined();
  });

  test("a refusal by the trust walk propagates, and a getcap that is absent, relative, or not beside a trusted tool is refused", () => {
    const base = fresh("getcap");
    const bin = join(base, "bin");
    const presence = presenceIn(bin);
    expect(() =>
      withDiagnosticTool(presence, bin, () => {
        throw new Error("untrusted");
      }),
    ).toThrow(/untrusted/);
    // Absent: a path with no getcap.
    expect(() => withDiagnosticTool(presence, fresh("empty"), noTrust)).toThrow(
      /not found/,
    );
    // A relative entry is skipped, so relative-only is absent.
    expect(() => withDiagnosticTool(presence, "bin", noTrust)).toThrow(
      /not found/,
    );
    // Found, but in a directory no required tool's trust walk covered.
    const elsewhere = fresh("elsewhere");
    const lone = join(elsewhere, diagnosticTool);
    writeFileSync(lone, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    expect(() => withDiagnosticTool(presence, elsewhere, noTrust)).toThrow(
      /not beside a trust-walked tool/,
    );
    // The first match wins and a later one is never tried in its place.
    const seen: string[] = [];
    withDiagnosticTool(presence, `${bin}:${elsewhere}`, (p) => seen.push(p));
    expect(seen).toEqual([join(bin, diagnosticTool)]);
    expect(() =>
      withDiagnosticTool(presence, `${elsewhere}:${bin}`, noTrust),
    ).toThrow(/not beside/);
  });
});

describe("a file named after the key", () => {
  const key = Buffer.from(deriveKey(nonce));
  const forms = needleForms(secretNeedles(nonce));
  const keyHex = key.toString("hex");

  test("fails the row, and its name is never printed", () => {
    const dir = fresh("window");
    const before = listWindowRoots([dir], uid);
    writeFileSync(join(dir, `leak-${keyHex}`), "innocent contents");
    writeFileSync(join(dir, "ordinary"), "x");
    const after = listWindowRoots([dir], uid);
    const scan = scanWindow(changedFiles(before, after), () => forms, uid);
    expect(scan.nameMatches).toBe(1);
    expect(scan.matches).toEqual([]);
    const row = windowRow(before, after, scan, [dir]);
    expect(row.ok).toBe(false);
    expect(JSON.stringify(row)).not.toContain(keyHex);
  });

  test("a leaking name on a file that also holds the key is withheld in `matches`, and an unreadable one in `unreadable`", () => {
    const dir = fresh("window");
    const before = listWindowRoots([dir], uid);
    writeFileSync(join(dir, `${keyHex}.txt`), keyHex);
    writeFileSync(join(dir, "plain-leak"), keyHex);
    const after = listWindowRoots([dir], uid);
    const scan = scanWindow(changedFiles(before, after), () => forms, uid);
    expect([...scan.matches].sort()).toEqual(
      [join(dir, "plain-leak"), withheldPath].sort(),
    );
    expect(JSON.stringify(windowRow(before, after, scan, [dir]))).not.toContain(
      keyHex,
    );
    // The same name on a file nobody can read this user's way.
    const other = fresh("window");
    const b2 = listWindowRoots([other], uid);
    // A symlink is never listed, so it reaches the scan only when named to it;
    // a link to itself opens with ELOOP and is set aside as unreadable.
    const link = join(other, `${keyHex}.bin`);
    symlinkSync(link, link);
    const a2 = listWindowRoots([other], uid);
    const s2 = scanWindow([link], () => forms, uid);
    expect(s2.unreadable).toEqual([withheldPath]);
    expect(s2.nameMatches).toBe(1);
    expect(JSON.stringify(windowRow(b2, a2, s2, [other]))).not.toContain(
      keyHex,
    );
  });

  test("a key-named path that vanished, and one that is foreign, is counted and never printed", () => {
    const dir = fresh("window");
    const gone = join(dir, `${keyHex}.gone`);
    const vanished = scanWindow([gone], () => forms, uid);
    expect(vanished.vanished).toBe(1);
    expect(vanished.nameMatches).toBe(1);
    // Foreign: a file this user cannot read, judged against another uid.
    if (uid !== 0) {
      const mine = join(dir, `${keyHex}.locked`);
      writeFileSync(mine, "x", { mode: 0o000 });
      const foreign = scanWindow([mine], () => forms, uid + 1);
      expect(foreign.foreign).toBe(1);
      expect(foreign.nameMatches).toBe(1);
      chmodSync(mine, 0o600);
    }
  });

  test("an error on a key-named path is rethrown without that path, from the scan and from each step of the listing", () => {
    const dir = fresh("window");
    const file = join(dir, `${keyHex}.file`);
    writeFileSync(file, "x");
    // A path through a regular file is ENOTDIR, which neither function absorbs.
    const through = join(file, "child");
    const message = (run: () => unknown): string => {
      try {
        run();
      } catch (error) {
        return String((error as Error).message);
      }
      return "";
    };
    const scanned = message(() => scanWindow([through], () => forms, uid));
    expect(scanned).toContain("ENOTDIR");
    expect(scanned).not.toContain(keyHex);
    // realpath: the same path as a root.
    const realpathed = message(() => listWindowRoots([through], uid));
    expect(realpathed).toContain("realpath: ENOTDIR");
    expect(realpathed).not.toContain(keyHex);
  });

  test("the listing's lstat and readdir failures are rethrown as the step and the code only", () => {
    const message = (run: () => unknown): string => {
      try {
        run();
      } catch (error) {
        return String((error as Error).message);
      }
      return "";
    };
    // lstat: an owned directory with no search permission lists, and the child
    // cannot be examined (EACCES). Root ignores modes, so it cannot make this.
    if (uid !== 0) {
      const locked = fresh("window");
      const inner = join(locked, `${keyHex}.dir`);
      mkdirSync(inner);
      chmodSync(locked, 0o400);
      try {
        const lstatted = message(() => listWindowRoots([locked], uid));
        expect(lstatted).toContain("lstat: EACCES");
        expect(lstatted).not.toContain(keyHex);
      } finally {
        chmodSync(locked, 0o700);
      }
    }
    // readdir: no file forces a failure that is not a permission one, so the
    // seam throws one whose message names a key-named path.
    const dir = fresh("window");
    const readdirFailure = message(() =>
      listWindowRoots([dir], uid, (() => {
        throw Object.assign(new Error(`ENOTDIR: ${join(dir, keyHex)}`), {
          code: "ENOTDIR",
          path: join(dir, keyHex),
        });
      }) as never),
    );
    expect(readdirFailure).toContain("readdir: ENOTDIR");
    expect(readdirFailure).not.toContain(keyHex);
  });

  // Names that are not valid UTF-8 can be made on Linux only (a Mac's APFS
  // refuses them with EILSEQ); a Linux run may not take the early return.
  const badName = (dir: string): Buffer =>
    Buffer.concat([Buffer.from(`${dir}/`), Buffer.from([0xff, 0xfe])]);
  const makeBad = (dir: string): boolean => {
    try {
      writeFileSync(badName(dir), "x");
      return true;
    } catch (error) {
      expect((error as NodeJS.ErrnoException).code).toBe("EILSEQ");
      expect(process.platform).not.toBe("linux");
      return false;
    }
  };

  test("a valid non-ASCII name lists", () => {
    const dir = fresh("window");
    const good = join(dir, "caf\u00e9");
    writeFileSync(good, "x");
    expect(Object.keys(listWindowRoots([dir], uid).files)).toEqual([good]);
  });

  test("a name that is not valid UTF-8 fails the row whoever owns the directory, with the window otherwise sound", () => {
    // The directory is judged as its owner and as another user: /tmp and
    // /dev/shm are directories of other users that this run writes into.
    for (const judge of [uid, uid + 1]) {
      const dir = fresh("window");
      // A directory holding such a name is unlisted as a whole, so a sound file
      // is put in a second root: the scan reads it, and the row's verdict then
      // rests on the name alone.
      const sound = fresh("window");
      const roots = [dir, sound];
      const before = listWindowRoots(roots, judge);
      writeFileSync(join(sound, "ordinary"), "x");
      if (!makeBad(dir)) return;
      const after = listWindowRoots(roots, judge);
      expect(after.ownUnreadable).toEqual([dir]);
      const scan = scanWindow(changedFiles(before, after), () => forms, uid);
      expect(scan.filesRead).toBe(1);
      expect(scan.nameMatches).toBe(0);
      expect(windowRow(before, after, scan, roots).ok).toBe(false);
      // The same window without the bad name passes, so it is the name that fails.
      rmSync(badName(dir));
      const clean = listWindowRoots(roots, judge);
      expect(
        windowRow(
          before,
          clean,
          scanWindow(changedFiles(before, clean), () => forms, uid),
          roots,
        ).ok,
      ).toBe(true);
    }
  });

  test("a root that resolves to a path the listing cannot find is an error, not a silent absence", () => {
    const base = fresh("window");
    const target = badName(base);
    try {
      mkdirSync(target);
    } catch (error) {
      expect((error as NodeJS.ErrnoException).code).toBe("EILSEQ");
      expect(process.platform).not.toBe("linux");
      return;
    }
    const link = join(base, "root");
    symlinkSync(target, link);
    expect(() => listWindowRoots([link], uid)).toThrow(/lstat: ENOENT/);
  });

  test("an ordinary name passes and is judged once", () => {
    const dir = fresh("window");
    const before = listWindowRoots([dir], uid);
    writeFileSync(join(dir, "ordinary"), "x");
    const after = listWindowRoots([dir], uid);
    const scan = scanWindow(changedFiles(before, after), () => forms, uid);
    expect(scan.nameMatches).toBe(0);
    expect(windowRow(before, after, scan, [dir]).ok).toBe(true);
  });
});

describe("the adapter, through real interposers, over fake tools", () => {
  test("a seal and an unseal produce a log that every shim row accepts, with the ruled device and the adapter's own environment", async () => {
    const base = fresh("e2e");
    const bin = join(base, "bin");
    installFakeTools(bin, join(base, "records"));
    const detected = detectTpm2ForTest(
      { path: bin, device: "/dev/null" },
      { trustRoot: root },
    );
    // The fake host has no /dev/tpmrm0, so the presence names the ruled device
    // directly, as the jetson's real detection does.
    const real = withDiagnosticTool(
      { ...detected, device: tpmDevicePath },
      bin,
      () => undefined,
    );
    const run = join(base, "run");
    mkdirSync(run, { mode: 0o700 });
    const interposers = join(run, "interposers");
    const log = join(run, "tools.log");
    const presence = installInterposers(interposers, real, log);
    const key = deriveKey(nonce);
    const sealedAt = join(run, "tpm");
    await sealKey(presence, key, sealedAt);
    const sealed = readToolLog(log).length;
    await runTool(presence, diagnosticTool, ["handles-saved-session"]);
    const unsealed = await unsealKey(presence, sealedAt);
    expect(unsealed.length).toBe(32);
    const calls = readToolLog(log);
    const forms = needleForms(secretNeedles(nonce));
    expect(tctiRow(calls).ok).toBe(true);
    expect(envRow(calls, interposers, forms).ok).toBe(true);
    expect(argvRow(calls, forms).ok).toBe(true);
    expect(expectedCallsRow("seal", calls).ok).toBe(true);
    // The seal-only tool is not part of the unseal phase's set.
    expect(expectedCallsRow("unseal", calls).ok).toBe(false);
    // The log of the unseal alone (cut after the seal) is what that phase
    // accepts, from real calls rather than hand-built ones, and not the seal's.
    const unsealOnly = calls.slice(sealed);
    expect(expectedCallsRow("unseal", unsealOnly).ok).toBe(true);
    expect(expectedCallsRow("seal", unsealOnly).ok).toBe(false);
    expect(JSON.stringify(calls)).not.toContain(
      Buffer.from(key).toString("hex"),
    );
  });
});

// MUTANT REGISTER, WCLI-21 slice 4a-2b-2 part A (the rows and support the harness script wires), written and committed BEFORE any run of it. Bun 1.3.14, a Mac with bash as sh. Each mutant is applied to the named file and goes red on the named test(s) of this file only, across test/qualify-linux-wiring.test.ts, test/qualify-linux-shim.test.ts, test/qualify-linux-rows.test.ts, test/qualify-linux.test.ts and test/tpm2-tools.test.ts.
//   W1  qualify-linux-support.ts: the seal phase drops the shim rows from requiredChecks            -> "every phase that runs a tool requires the shim rows, and all but clean the window row" and "with every required row present and ok a phase passes, and dropping any one shim row fails it"
//   W2  qualify-linux-support.ts: the clean phase also requires the window row                      -> "every phase that runs a tool requires the shim rows, and all but clean the window row" only
//   W3  qualify-linux-rows.ts: expectedCallsRow ignores a tool outside the phase's set               -> "every tool a phase must run, and none outside its set, passes" and "no calls, and an unknown phase, fail; the unseal phase creates nothing"
//   W4  qualify-linux-rows.ts: expectedCallsRow ignores a required tool that was never logged        -> "every tool a phase must run, and none outside its set, passes" only
//   W5  qualify-linux-rows.ts: envControlRow compares names and drops the digest comparison           -> "the same names with the same value digests pass; a missing, extra, changed or repeated name fails" only
//   W6  qualify-linux-shim.ts: readToolLog decodes as utf8                                           -> "an argument of raw key bytes that are not valid UTF-8 is found, and a utf8 read would lose it" only
//   W7  qualify-linux-shim.ts: withDiagnosticTool drops the beside-a-trust-walked-tool check         -> "a refusal by the trust walk propagates, and a getcap that is absent, relative, or not beside a trusted tool is refused" only
//   W8  qualify-linux-shim.ts: withDiagnosticTool never calls the trust walk                         -> "it is resolved on the search path, trusted by the walk it is given, and added beside the required tools" and the refusal test above
//   W9  qualify-linux-shim.ts: scanWindow never judges a path's name (no count, nothing withheld)    -> "fails the row, and its name is never printed" and "a leaking name on a file that also holds the key is withheld in `matches`, and an unreadable one in `unreadable`"
//   W10 qualify-linux-shim.ts: windowRow drops the name-match requirement (the count is still kept)  -> "fails the row, and its name is never printed" only
// ROUND 1 (opus review of c1f8dbe), predictions written and committed BEFORE any run of the new mutants, bun 1.3.14 on a Mac:
//   W11 qualify-linux-shim.ts: listWindowRoots rethrows the raw error from realpath/lstat/readdir    -> "an error on a key-named path is rethrown without that path" only
//   W12 qualify-linux-shim.ts: scanWindow rethrows the raw error                                      -> "an error on a key-named path is rethrown without that path" only
//   W13 qualify-linux-shim.ts: listWindowRoots drops the non-round-tripping-name check                -> NO red on a Mac (APFS refuses the name, the test returns at EILSEQ); red on the Linux arm runner on "a directory holding a name that is not valid UTF-8 fails the row instead of dropping it..." only
//   W14 qualify-linux-rows.ts: envControlRow drops the unique-names requirement                       -> "the same names with the same value digests pass; a missing, extra, changed or repeated name fails" only
//   W15 qualify-linux-rows.ts: envControlRow hashes the printed value as utf8, not latin1             -> the same test only
//   W16 qualify-linux-shim.ts: readdirSync back to the default utf8 names (the block as it was)       -> as W13 (Linux only)
// ROUND 2 (DEC-262 a32, facts is read-only with no interposer), predictions written and committed BEFORE any run:
//   W17 qualify-linux-support.ts: facts requires the shim rows again                                  -> "seal, unseal and clean require the shim rows, seal and unseal the window row; facts and deliver owe none (DEC-262 a32)" only
//   W18 qualify-linux-support.ts: facts requires the window row again                                 -> the same test only
//   W19 qualify-linux-rows.ts: expectedTools regains a facts entry                                    -> "no calls, and an unknown phase, fail; the unseal phase creates nothing" only
// ROUND 3 (round 2 review F1, N-a, N-b, N-e, DEC-262 a33), predictions written and committed BEFORE any run; W13 and W16 are re-stated against the new test names. "Linux" means measured on the ubuntu-24.04-arm Check job through a throwaway draft PR; a Mac cannot make a non-UTF-8 name, so those tests return early there.
//   W11a qualify-linux-shim.ts: realpath failure rethrown raw                                        -> "an error on a key-named path is rethrown without that path, from the scan and from each step of the listing" only (Mac and Linux)
//   W11b qualify-linux-shim.ts: lstat failure rethrown raw                                           -> "the listing's lstat and readdir failures are rethrown as the step and the code only" only (Mac and Linux)
//   W11c qualify-linux-shim.ts: readdir failure rethrown raw                                         -> the same test as W11b only (Mac and Linux)
//   W13  qualify-linux-shim.ts: the round-trip check dropped                                         -> "a name that is not valid UTF-8 fails the row whoever owns the directory, with the window otherwise sound" only (Linux)
//   W16  qualify-linux-shim.ts: readdir back to utf8 names                                           -> the same test only (Linux)
//   W23  qualify-linux-shim.ts: the non-round-tripping name counted foreign when the directory is not the judge's own (the round 2 F1 form) -> the same test only, on its uid + 1 pass (Linux)
//   W24  qualify-linux-shim.ts: a top-level ENOENT swallowed again                                   -> "a root that resolves to a path the listing cannot find is an error, not a silent absence" only (Linux)
//   W20  qualify-linux-support.ts: facts requires runWide again                                      -> "facts owes none of them, deliver owes the ward-metadata row only, and seal, unseal and clean owe all three" and "facts passes on exactly the rows its four commands can produce" (Mac and Linux)
//   W21  qualify-linux-support.ts: deliver drops real-ward-metadata-unchanged                        -> the first of those two tests and "each phase's list holds the (a29) and T26 rows it owes, and the unseal phase holds all of the seal phase's"
//   W22  qualify-linux-support.ts: clean drops runWide                                                -> the first of those two tests only
// OBSERVED, ROUND 3, Mac (bun 1.3.14, predictions above unchanged, a driver restoring each file after each mutant, on 3732ac6): W11a, W11b, W11c and W20 went red on exactly the tests predicted (W11b and W11c on the same one). W21 went red on the two predicted. W22 DIVERGED: it also reddened "each phase's list holds the (a29) and T26 rows it owes, ..." because clean's owed list there names the three rows, so it went red on two tests, not the one predicted. W13, W16, W23 and W24 went red on nothing on the Mac, as predicted (Linux-only; their Linux results are recorded below once measured).
// OBSERVED, ROUND 3, Linux (ubuntu-24.04-arm Check jobs through throwaway draft PRs cut from 867a99a, one per mutant, 2026-11-19; predictions unchanged): W11a, W11c, W13, W16, W23 each went red on exactly the one test predicted (W11a opum-ai/ward-cli#382, W11c #384, W13 #385, W16 #386, W23 #387). W11b (#383) DIVERGED: red on the predicted test AND on "a root that resolves to a path the listing cannot find is an error, not a silent absence", whose /lstat: ENOENT/ pattern a raw rethrow no longer matches. W24 (#388) went red on its one predicted test. Two earlier attempts are void: the first set was cut from af1bf25, whose bad-name test wrongly expected a sound file in the unlistable directory to be read (found by #370's own Check, fixed in 867a99a), and the first W13 body failed the format gate before any test ran.
// OBSERVED, ROUND 2 (bun 1.3.14 on a Mac, predictions above unchanged, a driver restoring each file after each mutant): W17, W18 and W19 each went red on exactly the one test predicted.
// OBSERVED, ROUND 1 (bun 1.3.14 on a Mac, 2026-11-18, predictions above unchanged, a driver restoring each file after each mutant, on e24053f): W11, W12, W14 and W15 each went red on exactly the one test predicted. W13 and W16 were NOT run: the Mac cannot create a non-UTF-8 name, so they are unobservable here and the Linux arm runner is where they are measured. Bun returns plain Uint8Arrays from readdirSync with encoding buffer (not Buffers), which the first run of the fix exposed. STATED LIMIT: the name scan does not cover a key-named empty directory, symlink or FIFO, because the listing holds regular files only.
// OBSERVED (slice 4a-2b-2 part A, bun 1.3.14 on a Mac with bash as sh, 2026-11-18; the predictions above unchanged, a driver restoring each file after each mutant, run on the tree at 03cdd71). No survivor. W2, W4-W7 and W10 each went red on exactly the one test predicted; W8 on its two; W9 on its two. Divergences from the predictions: W1 reddened ONE test, not two ("every phase that runs a tool requires the shim rows, and all but clean the window row"): the second test builds its all-ok list from requiredChecks itself, so a phase that stops requiring the shim rows is invisible to it, and only the first test (which names the rows) closes the mutant; W3 reddened a third test, the end-to-end one, which asserts that a seal log is not an unseal log because of the seal-only tools (so an unseal that ignores unexpected tools reads it as passing). The Linux target's /bin/sh is dash; none of this was measured there.
