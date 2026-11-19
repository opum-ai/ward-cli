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
  writeFileSync,
} from "node:fs";
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

  test("every phase that runs a tool requires the shim rows, and all but clean the window row", () => {
    for (const phase of ["facts", "seal", "unseal", "clean"] as const) {
      for (const name of shimRows)
        expect(requiredChecks[phase]).toContain(name);
      expect(requiredChecks[phase].includes(windowName)).toBe(
        phase !== "clean",
      );
    }
    // The delivery phase runs no tool, so it owes none of them.
    for (const name of [...shimRows, windowName])
      expect(requiredChecks.deliver).not.toContain(name);
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

describe("the expected call set", () => {
  const call = (tool: string): ToolCall => ({
    tool,
    tcti: "device:/dev/tpmrm0",
    args: [],
  });

  test("every tool a phase must run, and none outside its set, passes", () => {
    for (const phase of ["facts", "seal", "unseal", "clean"] as const) {
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
    writeFileSync(join(other, `${keyHex}.bin`), "x");
    symlinkAs(join(other, `${keyHex}.bin`));
    const a2 = listWindowRoots([other], uid);
    const s2 = scanWindow(changedFiles(b2, a2), () => forms, uid);
    expect(JSON.stringify(windowRow(b2, a2, s2, [other]))).not.toContain(
      keyHex,
    );
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

// Replaces a file with a link to itself, which the scan sets aside as unreadable
// (ELOOP) while its name still goes through the name check.
function symlinkAs(path: string): void {
  rmSync(path);
  Bun.spawnSync(["ln", "-s", path, path]);
}

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
