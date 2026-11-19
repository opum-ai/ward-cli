// WCLI-21 slice 4a-2b: the logging shim (the interposers, the environment row and
// the window rows) measured against fake tools, so no TPM is reached. The
// interposers are real shell scripts run by /bin/sh; the tools they front are
// small scripts written here.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  readdirSync,
  truncateSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseToolLog,
  privateRow,
  reportStatementRow,
  ruledTcti,
  shimStatement,
  type ToolCall,
} from "../scripts/qualify-linux-rows.ts";
import {
  argvRow,
  changedFiles,
  envRow,
  expectedEnvironment,
  installInterposers,
  interposerScript,
  listWindowRoots,
  maxWindowFileBytes,
  scanWindow,
  windowRow,
} from "../scripts/qualify-linux-shim.ts";
import {
  deriveKey,
  holdsAny,
  needleForms,
  secretNeedles,
  sha256,
} from "../scripts/qualify-linux-support.ts";
import type { Tpm2Presence } from "../src/adapters/tpm2-tools.ts";

const root = realpathSync(mkdtempSync(join(tmpdir(), "ward-qualify-shim-")));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let counter = 0;
const fresh = (name: string): string => {
  const dir = join(root, `${name}-${counter++}`);
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  return dir;
};
const asRoot = process.getuid?.() === 0;
const uid = process.getuid?.() ?? 0;
const nonce =
  "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";

// A fake real tool: it prints the bytes the test gives it on stdout, copies
// whatever it receives on stdin to stderr, and exits with the given code.
const fakeTool = (dir: string, stdoutBytes: Uint8Array, code = 0): string => {
  const out = join(dir, "fake.out");
  writeFileSync(out, stdoutBytes);
  const tool = join(dir, "fake-tool");
  writeFileSync(tool, `#!/bin/sh\ncat '${out}'\ncat >&2\nexit ${code}\n`, {
    mode: 0o700,
  });
  chmodSync(tool, 0o700);
  return tool;
};

const adapterEnv = (interposerDir: string): Record<string, string> =>
  expectedEnvironment(interposerDir);

const run = (
  script: string,
  args: string[],
  env: Record<string, string>,
  stdin = "",
) => {
  const result = Bun.spawnSync(["/bin/sh", script, ...args], {
    env,
    stdin: Buffer.from(stdin),
  });
  return {
    code: result.exitCode,
    stdout: Buffer.from(result.stdout),
    stderr: Buffer.from(result.stderr).toString("latin1"),
  };
};

describe("the interposer script", () => {
  test("a path with anything but letters, digits and _ . / - is refused", () => {
    for (const bad of ["a b", "a'b", "a;b", "a$b", "a\nb", "a`b"]) {
      expect(() => interposerScript("t", bad, "/l", false)).toThrow(/letters/);
      expect(() => interposerScript(bad, "/r", "/l", false)).toThrow(/letters/);
      expect(() => interposerScript("t", "/r", bad, false)).toThrow(/letters/);
    }
  });

  test("a call is logged with its TCTI, environment names with digests, and arguments, and the tool's stdout and stdin pass through untouched", () => {
    const dir = fresh("shim");
    const log = join(dir, "tools.log");
    const tool = fakeTool(dir, Buffer.from("secret-looking-output\n"));
    writeFileSync(log, "", { mode: 0o600 });
    const script = join(dir, "tpm2_unseal");
    writeFileSync(script, interposerScript("tpm2_unseal", tool, log, false), {
      mode: 0o700,
    });
    const env = adapterEnv(dir);
    const result = run(
      script,
      ["-c", "ctx", "-p", "session:s"],
      env,
      "stdin-bytes",
    );
    expect(result.code).toBe(0);
    expect(result.stdout.toString()).toBe("secret-looking-output\n");
    expect(result.stderr).toBe("stdin-bytes");
    const text = readFileSync(log, "utf8");
    // Neither the tool's stdout nor its stdin is in the log.
    expect(text).not.toContain("secret-looking-output");
    expect(text).not.toContain("stdin-bytes");
    const [call] = parseToolLog(text);
    expect(call?.tool).toBe("tpm2_unseal");
    expect(call?.tcti).toBe(ruledTcti);
    expect(call?.args).toEqual(["-c", "ctx", "-p", "session:s"]);
    expect(call?.stdout).toBeUndefined();
    const names = (call?.env ?? []).map((e) => e.name);
    for (const name of ["PATH", "TPM2TOOLS_TCTI", "LANG", "LC_ALL"])
      expect(names).toContain(name);
    // A value never appears, only its digest.
    expect(
      text
        .split("\n")
        .filter((line) => line.startsWith("ENV "))
        .join("\n"),
    ).not.toContain(ruledTcti);
    expect(call?.env?.find((e) => e.name === "LANG")?.digest).toBe(
      sha256(Buffer.from("C")),
    );
  });

  test("an argument that holds a newline stops the call before anything runs or is logged", () => {
    const dir = fresh("shim");
    const log = join(dir, "tools.log");
    const marker = join(dir, "ran");
    const tool = join(dir, "fake-tool");
    writeFileSync(tool, `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o700 });
    writeFileSync(log, "", { mode: 0o600 });
    const script = join(dir, "tpm2_load");
    writeFileSync(script, interposerScript("tpm2_load", tool, log, false), {
      mode: 0o700,
    });
    const result = run(script, ["ok", "a\nCALL tpm2_unseal"], adapterEnv(dir));
    expect(result.code).toBe(97);
    expect(existsSync(marker)).toBe(false);
    expect(readFileSync(log, "utf8")).toBe("");
  });

  test("the recorded tool's stdout reaches the caller byte for byte and keeps its exit code, whatever its trailing newlines", () => {
    for (const bytes of [
      Buffer.from("Session-Attributes: continuesession|decrypt|encrypt"),
      Buffer.from("Session-Attributes: continuesession|decrypt|encrypt\n"),
      Buffer.from("a\n\n\n"),
      Buffer.from("tab\tand  spaces \n"),
      Buffer.alloc(0),
    ])
      for (const code of [0, 3]) {
        const dir = fresh("shim");
        const log = join(dir, "tools.log");
        const tool = fakeTool(dir, bytes, code);
        writeFileSync(log, "", { mode: 0o600 });
        const script = join(dir, "tpm2_sessionconfig");
        writeFileSync(
          script,
          interposerScript("tpm2_sessionconfig", tool, log, true),
          { mode: 0o700 },
        );
        const result = run(script, ["/s.ctx"], adapterEnv(dir));
        expect(result.code).toBe(code);
        expect(Buffer.compare(result.stdout, bytes)).toBe(0);
        const [call] = parseToolLog(readFileSync(log, "utf8"));
        expect(call?.rc).toBe(code);
        expect(call?.stdout).toBeDefined();
        expect((call?.stdout ?? "").replace(/\n+$/, "")).toBe(
          bytes.toString().replace(/\n+$/, ""),
        );
        // The capture file is removed: nothing but the interposer, the fake
        // tool's files and the log is left beside it.
        expect(
          readdirSync(dir).filter((f) => f.startsWith("tools.log.out")),
        ).toEqual([]);
      }
  });
});

describe("installing the interposers", () => {
  const presenceOf = (): Tpm2Presence => {
    const tool = fakeTool(fresh("fake"), Buffer.from("x"));
    return {
      device: "/dev/tpmrm0",
      tools: {
        tpm2_createprimary: tool,
        tpm2_create: tool,
        tpm2_load: tool,
        tpm2_startauthsession: tool,
        tpm2_sessionconfig: tool,
        tpm2_unseal: tool,
        tpm2_flushcontext: tool,
      },
    };
  };

  test("a private directory of 0700 scripts, a 0600 log, and a presence that points at the scripts", () => {
    const base = fresh("install");
    const directory = join(base, "interposers");
    const log = join(base, "tools.log");
    const installed = installInterposers(directory, presenceOf(), log);
    expect(statSync(directory).mode & 0o7777).toBe(0o700);
    expect(statSync(log).mode & 0o7777).toBe(0o600);
    for (const [tool, path] of Object.entries(installed.tools)) {
      expect(path).toBe(join(directory, tool));
      expect(statSync(path as string).mode & 0o7777).toBe(0o700);
    }
    expect(installed.device).toBe("/dev/tpmrm0");
    // The recorded tool is the only one whose script copies stdout.
    expect(readFileSync(installed.tools.tpm2_sessionconfig, "utf8")).toContain(
      "OUT-BEGIN",
    );
    expect(readFileSync(installed.tools.tpm2_unseal, "utf8")).not.toContain(
      "OUT-BEGIN",
    );
    // The scripts are the only 0700 files the private row allows.
    expect(privateRow(base).ok).toBe(false);
    expect(privateRow(base, "interposers").ok).toBe(true);
  });

  test("a directory that is there is never adopted, and a relative or odd real path is refused before anything is made", () => {
    const base = fresh("install");
    const directory = join(base, "interposers");
    mkdirSync(directory);
    expect(() =>
      installInterposers(directory, presenceOf(), join(base, "tools.log")),
    ).toThrow();
    expect(existsSync(join(base, "tools.log"))).toBe(false);
    const other = fresh("install");
    const relative = presenceOf();
    expect(() =>
      installInterposers(
        join(other, "i"),
        {
          ...relative,
          tools: { ...relative.tools, tpm2_load: "tpm2_load" },
        } as Tpm2Presence,
        join(other, "tools.log"),
      ),
    ).toThrow(/not absolute/);
    expect(existsSync(join(other, "i"))).toBe(false);
    const odd = presenceOf();
    expect(() =>
      installInterposers(
        join(other, "j"),
        {
          ...odd,
          tools: { ...odd.tools, tpm2_load: "/usr/bin/tpm2 load" },
        } as Tpm2Presence,
        join(other, "tools.log"),
      ),
    ).toThrow(/letters/);
    expect(existsSync(join(other, "j"))).toBe(false);
  });

  test("the private row lets only the interposer directory's own files be executable", () => {
    const base = fresh("private");
    mkdirSync(join(base, "interposers"), { mode: 0o700 });
    writeFileSync(join(base, "interposers", "t"), "x", { mode: 0o700 });
    chmodSync(join(base, "interposers", "t"), 0o700);
    expect(privateRow(base, "interposers").ok).toBe(true);
    writeFileSync(join(base, "elsewhere"), "x", { mode: 0o700 });
    chmodSync(join(base, "elsewhere"), 0o700);
    expect(privateRow(base, "interposers").ok).toBe(false);
    const wide = fresh("private");
    mkdirSync(join(wide, "interposers"), { mode: 0o700 });
    writeFileSync(join(wide, "interposers", "t"), "x");
    chmodSync(join(wide, "interposers", "t"), 0o770);
    expect(privateRow(wide, "interposers").ok).toBe(false);
  });
});

describe("the environment row", () => {
  const callWith = (env: Record<string, string>): ToolCall => ({
    tool: "tpm2_load",
    tcti: ruledTcti,
    args: [],
    env: Object.entries(env).map(([name, value]) => ({
      name,
      digest: sha256(Buffer.from(value)),
    })),
  });
  const good = expectedEnvironment("/run/interposers");
  const forms = needleForms([deriveKey(nonce)]);

  test("the adapter's own four variables, each with its exact value, pass, and no name outside them does, the shell's own included", () => {
    expect(envRow([callWith(good)], "/run/interposers", forms).ok).toBe(true);
    for (const extra of ["PWD", "SHLVL", "_", "OLDPWD"])
      expect(
        envRow([callWith({ ...good, [extra]: "1" })], "/run/interposers", forms)
          .ok,
      ).toBe(false);
    const row = envRow([callWith(good)], "/run/interposers", forms);
    expect(row.name).toBe("key-not-in-tool-environment");
    // The report states the assertion in (a30)(i)'s words, and how it is proved.
    expect(JSON.stringify(row.detail)).toContain(
      "no env value contains the synthetic key",
    );
    expect(JSON.stringify(row.detail)).toContain("sha256");
  });

  test("a name outside the four never reaches the row, and a call must carry exactly the four, once each, with their digests", () => {
    const hex = `abcdef${Buffer.from(deriveKey(nonce)).toString("hex").slice(6)}`;
    const row = envRow(
      [callWith({ ...good, [hex]: "1" })],
      "/run/interposers",
      forms,
    );
    expect(row.ok).toBe(false);
    expect(JSON.stringify(row)).not.toContain(hex);
    expect((row.detail as { unexpected: number }).unexpected).toBe(1);
    // A missing name, a repeated name, and a wrong digest each fail on their own.
    const call = callWith(good);
    const env = call.env as { name: string; digest: string }[];
    expect(
      envRow([{ ...call, env: env.slice(1) }], "/run/interposers", forms).ok,
    ).toBe(false);
    expect(
      envRow(
        [{ ...call, env: [...env, ...env.slice(0, 1)] }],
        "/run/interposers",
        forms,
      ).ok,
    ).toBe(false);
    expect(
      envRow(
        [
          {
            ...call,
            env: env.map((e) =>
              e.name === "LANG"
                ? { ...e, digest: sha256(Buffer.from("x")) }
                : e,
            ),
          },
        ],
        "/run/interposers",
        forms,
      ).ok,
    ).toBe(false);
    // A good call beside a bad one fails: every call is judged.
    expect(
      envRow([call, { ...call, env: env.slice(1) }], "/run/interposers", forms)
        .ok,
    ).toBe(false);
  });

  test("a variable whose value holds a newline puts nothing of its continuation in the log or the row, whatever the continuation looks like", () => {
    const key = Buffer.from(deriveKey(nonce));
    const continuations = [
      `abcdef${key.toString("hex").slice(6)}`,
      `abcdef${key.toString("hex").slice(6)}=tail`,
      key.toString("base64"),
      "just text with no equals",
    ];
    for (const continuation of continuations)
      for (const recordStdout of [false, true]) {
        const dir = fresh("env");
        const log = join(dir, "tools.log");
        writeFileSync(log, "", { mode: 0o600 });
        const script = join(dir, "tpm2_load");
        // The real tool prints nothing of the environment, so the log holds only
        // what the shim itself wrote.
        const tool = fakeTool(dir, Buffer.from("ok\n"));
        writeFileSync(
          script,
          interposerScript("tpm2_load", tool, log, recordStdout),
          {
            mode: 0o700,
          },
        );
        const result = run(script, [], {
          ...expectedEnvironment(dir),
          ZZ_SPLIT: `x\n${continuation}`,
        });
        expect(result.code).toBe(0);
        const text = readFileSync(log, "utf8");
        // Over the log's bytes, for the key in every form and the continuation in
        // every form, not one substring.
        expect(
          holdsAny(readFileSync(log), [
            ...forms,
            ...needleForms([Buffer.from(continuation)]),
          ]),
        ).toBe(false);
        expect(text).toContain("ENV-SPLIT");
        // The parser refuses the log, so no row is ever built from it ...
        expect(() => parseToolLog(text)).toThrow(/malformed/);
        // ... and a row built from a hand-made call would not carry it either.
        const forged: ToolCall = {
          tool: "tpm2_load",
          tcti: ruledTcti,
          args: [],
          env: [
            {
              name: continuation.split("=")[0] as string,
              digest: "0".repeat(64),
            },
          ],
        };
        const row = envRow([forged], dir, forms);
        expect(row.ok).toBe(false);
        expect(JSON.stringify(row)).not.toContain(
          continuation.split("=")[0] as string,
        );
      }
  });

  test.skipIf(asRoot)(
    "a printout call whose log cannot be written after the tool ran exits 98 and leaves no capture file",
    () => {
      const dir = fresh("env");
      const log = join(dir, "tools.log");
      writeFileSync(log, "", { mode: 0o600 });
      // The tool makes the log read-only as its last act, so the OUT-block append
      // is the write that fails.
      const tool = join(dir, "fake-tool");
      writeFileSync(tool, `#!/bin/sh\necho printed\nchmod 0400 '${log}'\n`, {
        mode: 0o700,
      });
      const script = join(dir, "tpm2_sessionconfig");
      writeFileSync(
        script,
        interposerScript("tpm2_sessionconfig", tool, log, true),
        {
          mode: 0o700,
        },
      );
      const result = run(script, ["/s.ctx"], expectedEnvironment(dir));
      expect(result.code).toBe(98);
      expect(
        readdirSync(dir).filter((f) => f.startsWith("tools.log.out")),
      ).toEqual([]);
    },
  );

  test("a clean environment writes no split marker, and a TCTI holding a newline stops the call", () => {
    const dir = fresh("env");
    const log = join(dir, "tools.log");
    writeFileSync(log, "", { mode: 0o600 });
    const script = join(dir, "tpm2_load");
    writeFileSync(
      script,
      interposerScript("tpm2_load", "/usr/bin/env", log, false),
      { mode: 0o700 },
    );
    expect(run(script, [], expectedEnvironment(dir)).code).toBe(0);
    expect(readFileSync(log, "utf8")).not.toContain("ENV-SPLIT");
    const stopped = run(script, [], {
      ...expectedEnvironment(dir),
      TPM2TOOLS_TCTI: "device:/dev/tpmrm0\nCALL tpm2_unseal",
    });
    expect(stopped.code).toBe(97);
  });

  test("a call that cannot be logged does not run: the interposer exits 98 and the tool never starts", () => {
    for (const recordStdout of [false, true]) {
      const dir = fresh("env");
      const marker = join(dir, "ran");
      const tool = join(dir, "fake-tool");
      writeFileSync(tool, `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o700 });
      const log = join(dir, "no-such-dir", "tools.log");
      const script = join(dir, "tpm2_load");
      writeFileSync(
        script,
        interposerScript("tpm2_load", tool, log, recordStdout),
        { mode: 0o700 },
      );
      const result = run(script, [], expectedEnvironment(dir));
      expect(result.code).toBe(98);
      expect(existsSync(marker)).toBe(false);
    }
  });

  test("an expected value that holds a raw, hex or base64 form of the key fails the row, whatever the digests say", () => {
    const key = Buffer.from(deriveKey(nonce));
    const seeded = [
      key.toString("hex"),
      key.toString("hex").toUpperCase(),
      key.toString("base64"),
      key.toString("base64url"),
      key.toString("latin1"),
    ];
    for (const form of seeded) {
      // The interposer directory is part of the expected PATH, so a directory
      // whose name holds the key puts it in an expected value; the logged call
      // carries the matching digests, so only the key check can fail the row.
      const dir = `/run/${form}`;
      const env = expectedEnvironment(dir);
      expect(env.PATH).toContain(form);
      expect(envRow([callWith(env)], dir, forms).ok).toBe(false);
    }
    // The real expected values hold none of them.
    for (const value of Object.values(good))
      for (const form of seeded) expect(value).not.toContain(form);
    expect(envRow([callWith(good)], "/run/interposers", forms).ok).toBe(true);
  });

  test("the argv row: an argument holding the key in any form fails, a clean log passes, and nothing logged is not a pass", () => {
    const key = Buffer.from(deriveKey(nonce));
    const call = (...args: string[]): ToolCall => ({
      tool: "tpm2_create",
      tcti: ruledTcti,
      args,
    });
    expect(argvRow([call("-c", "ctx")], forms).ok).toBe(true);
    for (const form of [
      key.toString("latin1"),
      key.toString("hex"),
      key.toString("base64"),
      key.toString("base64url"),
    ])
      expect(argvRow([call("-c", `x${form}y`)], forms).ok).toBe(false);
    expect(
      argvRow([call("a"), call("-i", key.toString("hex"))], forms).ok,
    ).toBe(false);
    expect(argvRow([], forms).ok).toBe(false);
    expect(argvRow([call("a")], forms).name).toBe("key-not-in-tool-argv");
    expect(JSON.stringify(argvRow([call("a")], forms).detail)).toContain(
      "no argv element contains the synthetic key",
    );
  });

  test("a tool behind an interposer sees exactly the adapter's four variables, whichever shell runs the script", () => {
    const dir = fresh("env");
    const log = join(dir, "tools.log");
    writeFileSync(log, "", { mode: 0o600 });
    const script = join(dir, "tpm2_load");
    // The real tool is env itself, so its stdout is the environment it received.
    writeFileSync(
      script,
      interposerScript("tpm2_load", "/usr/bin/env", log, false),
      {
        mode: 0o700,
      },
    );
    const result = run(script, [], expectedEnvironment(dir));
    expect(result.code).toBe(0);
    const received = result.stdout
      .toString()
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => line.split("=")[0] ?? "")
      .sort();
    expect(received).toEqual(["LANG", "LC_ALL", "PATH", "TPM2TOOLS_TCTI"]);
    // And the log says the same, with no name the shell added.
    const [call] = parseToolLog(readFileSync(log, "utf8"));
    expect((call?.env ?? []).map((e) => e.name).sort()).toEqual(received);
  });

  test("an extra variable, a changed or missing value, or a call with no environment fails", () => {
    const dir = "/run/interposers";
    for (const env of [
      { ...good, WARD_KEY: "anything" },
      { ...good, TPM2TOOLS_TCTI: "device:/dev/tpm0" },
      { ...good, PATH: `${good.PATH}:/tmp` },
      { ...good, LANG: "en_US.UTF-8" },
      { ...good, LC_ALL: `C${deriveKey(nonce)}` },
    ])
      expect(envRow([callWith(env)], dir, forms).ok).toBe(false);
    for (const missing of Object.keys(good)) {
      const env = { ...good };
      delete env[missing];
      expect(envRow([callWith(env)], dir, forms).ok).toBe(false);
    }
    expect(
      envRow([{ tool: "x", tcti: ruledTcti, args: [] }], dir, forms).ok,
    ).toBe(false);
    expect(envRow([], dir, forms).ok).toBe(false);
    // One bad call among good ones fails the row.
    expect(
      envRow([callWith(good), callWith({ ...good, EXTRA: "1" })], dir, forms)
        .ok,
    ).toBe(false);
    // A different interposer directory is a different PATH.
    expect(envRow([callWith(good)], "/other", forms).ok).toBe(false);
  });

  test("the row's detail carries the four names and counts, never a value or an unexpected name", () => {
    const row = envRow(
      [callWith({ ...good, SECRET_NAME_ONLY: "value-that-must-not-appear" })],
      "/run/interposers",
      forms,
    );
    expect(JSON.stringify(row)).not.toContain("value-that-must-not-appear");
    // An unexpected name is counted, never written (a split value can put part of
    // a key where a name goes).
    expect(JSON.stringify(row.detail)).not.toContain("SECRET_NAME_ONLY");
    expect((row.detail as { unexpected: number }).unexpected).toBe(1);
  });

  test("a real interposed call under the adapter's environment passes the row end to end", () => {
    const dir = fresh("env");
    const log = join(dir, "tools.log");
    const tool = fakeTool(dir, Buffer.from("x"));
    writeFileSync(log, "", { mode: 0o600 });
    const script = join(dir, "tpm2_load");
    writeFileSync(script, interposerScript("tpm2_load", tool, log, false), {
      mode: 0o700,
    });
    run(script, ["a"], expectedEnvironment(dir));
    expect(envRow(parseToolLog(readFileSync(log, "utf8")), dir, forms).ok).toBe(
      true,
    );
    // The same call with the key in an environment variable fails.
    const leaked = fresh("env");
    const llog = join(leaked, "tools.log");
    const ltool = fakeTool(leaked, Buffer.from("x"));
    writeFileSync(llog, "", { mode: 0o600 });
    const lscript = join(leaked, "tpm2_load");
    writeFileSync(lscript, interposerScript("tpm2_load", ltool, llog, false), {
      mode: 0o700,
    });
    run(lscript, ["a"], {
      ...expectedEnvironment(leaked),
      WARD_VAULT_KEY: Buffer.from(deriveKey(nonce)).toString("hex"),
    });
    expect(
      envRow(parseToolLog(readFileSync(llog, "utf8")), leaked, forms).ok,
    ).toBe(false);
  });
});

describe("the window rows", () => {
  const needles = needleForms(secretNeedles(nonce));
  const keyOnly = needleForms([deriveKey(nonce)]);
  const forAll = () => needles;
  const keyHex = Buffer.from(deriveKey(nonce)).toString("hex");

  const window = (
    rootsList: string[],
    step: () => void,
    needlesFor: (path: string) => readonly Buffer[] = forAll,
  ) => {
    const before = listWindowRoots(rootsList, uid);
    step();
    const after = listWindowRoots(rootsList, uid);
    const changed = changedFiles(before, after);
    const scan = scanWindow(changed, needlesFor, uid);
    return { before, after, changed, scan };
  };

  test("a file new in the window that holds the key, in any form, fails the row; a clean one passes", () => {
    for (const leak of [
      Buffer.from(deriveKey(nonce)),
      Buffer.from(keyHex),
      Buffer.from(Buffer.from(deriveKey(nonce)).toString("base64")),
      Buffer.from(nonce),
    ]) {
      const dir = fresh("window");
      const w = window([dir], () =>
        writeFileSync(
          join(dir, "leak"),
          Buffer.concat([Buffer.from("x "), leak]),
        ),
      );
      expect(w.scan.matches).toEqual([join(dir, "leak")]);
      expect(windowRow(w.before, w.after, w.scan, [dir]).ok).toBe(false);
    }
    const dir = fresh("window");
    const w = window([dir], () => writeFileSync(join(dir, "clean"), "nothing"));
    expect(windowRow(w.before, w.after, w.scan, [dir]).ok).toBe(true);
  });

  test("only files new or changed in the window are scanned, and a replacement that restores size and mtime is still changed", () => {
    const dir = fresh("window");
    writeFileSync(join(dir, "old-leak"), `old ${keyHex}`);
    const w = window([dir], () => writeFileSync(join(dir, "new"), "clean"));
    expect(w.changed).toEqual([join(dir, "new")]);
    expect(w.scan.matches).toEqual([]);
    // A file replaced by one of the same size with the mtime put back.
    const replaced = fresh("window");
    writeFileSync(join(replaced, "f"), "aaaa");
    utimesSync(join(replaced, "f"), 1_000_000_000, 1_000_000_000);
    const r = window([replaced], () => {
      rmSync(join(replaced, "f"));
      writeFileSync(join(replaced, "f"), `${keyHex.slice(0, 4)}`);
      utimesSync(join(replaced, "f"), 1_000_000_000, 1_000_000_000);
    });
    expect(r.changed).toEqual([join(replaced, "f")]);
  });

  test("state.json is searched for the key forms only, because it holds the nonce by design", () => {
    const dir = fresh("window");
    const state = join(dir, "state.json");
    const forState = (path: string) => (path === state ? keyOnly : needles);
    const w = window(
      [dir],
      () => writeFileSync(state, JSON.stringify({ nonce })),
      forState,
    );
    expect(w.scan.matches).toEqual([]);
    expect(windowRow(w.before, w.after, w.scan, [dir]).ok).toBe(true);
    // The key itself in state.json is still a hit.
    const dir2 = fresh("window");
    const state2 = join(dir2, "state.json");
    const w2 = window(
      [dir2],
      () => writeFileSync(state2, JSON.stringify({ key: keyHex })),
      (path) => (path === state2 ? keyOnly : needles),
    );
    expect(w2.scan.matches).toEqual([state2]);
    // And a nonce anywhere else is a hit.
    const dir3 = fresh("window");
    const w3 = window(
      [dir3],
      () => writeFileSync(join(dir3, "other"), nonce),
      forState,
    );
    expect(w3.scan.matches).toEqual([join(dir3, "other")]);
  });

  test("a window that read no file, a missing required root, and a file nobody accounted for all fail", () => {
    const dir = fresh("window");
    const none = window([dir], () => undefined);
    expect(windowRow(none.before, none.after, none.scan, [dir]).ok).toBe(false);
    const w = window([dir], () => writeFileSync(join(dir, "f"), "x"));
    expect(windowRow(w.before, w.after, w.scan, [dir]).ok).toBe(true);
    expect(
      windowRow(w.before, w.after, w.scan, [join(root, "no-root")]).ok,
    ).toBe(false);
    // A scan that skipped a changed file (read one fewer than changed).
    expect(
      windowRow(w.before, w.after, { ...w.scan, filesRead: 0 }, [dir]).ok,
    ).toBe(false);
    // A scan that read one file too many, or too few.
    expect(
      windowRow(w.before, w.after, { ...w.scan, filesRead: 2 }, [dir]).ok,
    ).toBe(false);
    // A path that is accounted for but never disposed of: two files changed, both
    // listed as accounted, one read and the other neither read, foreign, vanished
    // nor set aside.
    const two = window([dir], () => {
      writeFileSync(join(dir, "a"), "x");
      writeFileSync(join(dir, "b"), "y");
    });
    expect(windowRow(two.before, two.after, two.scan, [dir]).ok).toBe(true);
    expect(
      windowRow(two.before, two.after, { ...two.scan, filesRead: 1 }, [dir]).ok,
    ).toBe(false);
    // Counts that add up but name another path: accounted by path, not by number.
    expect(
      windowRow(
        w.before,
        w.after,
        { ...w.scan, accounted: [join(dir, "other")] },
        [dir],
      ).ok,
    ).toBe(false);
    expect(
      windowRow(
        w.before,
        w.after,
        { ...w.scan, accounted: [...w.scan.accounted, join(dir, "extra")] },
        [dir],
      ).ok,
    ).toBe(false);
    expect(
      windowRow(w.before, w.after, { ...w.scan, accounted: [] }, [dir]).ok,
    ).toBe(false);
  });

  test("a root that does not exist is recorded as absent, not an error, and may stay absent", () => {
    const dir = fresh("window");
    const absent = join(root, "dev-shm-that-is-not-here");
    const w = window([dir, absent], () => writeFileSync(join(dir, "f"), "x"));
    expect(w.after.present[absent]).toBe(false);
    expect(windowRow(w.before, w.after, w.scan, [dir]).ok).toBe(true);
    // A root that appears or vanishes between the listings is a different window.
    const other = listWindowRoots([dir], uid);
    expect(windowRow(w.before, other, w.scan, [dir]).ok).toBe(false);
  });

  test.skipIf(asRoot)(
    "a directory of this user's own that cannot be listed, and a file of this user's own that cannot be read, fail closed",
    () => {
      const dir = fresh("window");
      mkdirSync(join(dir, "locked"));
      writeFileSync(join(dir, "locked", "f"), "x");
      chmodSync(join(dir, "locked"), 0o000);
      try {
        const listing = listWindowRoots([dir], uid);
        expect(listing.ownUnreadable).toEqual([join(dir, "locked")]);
        const row = windowRow(
          listing,
          listing,
          {
            filesRead: 1,
            matches: [],
            foreign: 0,
            vanished: 0,
            unreadable: [],
            nameMatches: 0,
            accounted: [],
          },
          [dir],
        );
        expect(row.ok).toBe(false);
      } finally {
        chmodSync(join(dir, "locked"), 0o700);
      }
      const files = fresh("window");
      const before = listWindowRoots([files], uid);
      writeFileSync(join(files, "sealed"), keyHex, { mode: 0o000 });
      chmodSync(join(files, "sealed"), 0o000);
      try {
        const after = listWindowRoots([files], uid);
        const scan = scanWindow(changedFiles(before, after), forAll, uid);
        expect(scan.unreadable).toEqual([join(files, "sealed")]);
        expect(scan.filesRead).toBe(0);
        expect(windowRow(before, after, scan, [files]).ok).toBe(false);
      } finally {
        chmodSync(join(files, "sealed"), 0o600);
      }
    },
  );

  test("a file larger than the cap is not scanned and fails the row, and a vanished file is accounted for", () => {
    expect(maxWindowFileBytes).toBe(64 * 1024 * 1024);
    const dir = fresh("window");
    const before = listWindowRoots([dir], uid);
    writeFileSync(join(dir, "gone"), "x");
    writeFileSync(join(dir, "kept"), "y");
    const after = listWindowRoots([dir], uid);
    rmSync(join(dir, "gone"));
    const scan = scanWindow(changedFiles(before, after), forAll, uid);
    expect(scan.vanished).toBe(1);
    expect(scan.filesRead).toBe(1);
    expect(windowRow(before, after, scan, [dir]).ok).toBe(true);
    // A real file one byte over the cap (sparse, so it costs nothing): the scan
    // refuses it, and the row fails.
    const big = fresh("window");
    const bw = window([big], () => {
      writeFileSync(join(big, "big"), "");
      truncateSync(join(big, "big"), maxWindowFileBytes + 1);
      writeFileSync(join(big, "ok"), "y");
    });
    expect(bw.scan.unreadable).toEqual([join(big, "big")]);
    expect(bw.scan.filesRead).toBe(1);
    expect(windowRow(bw.before, bw.after, bw.scan, [big]).ok).toBe(false);
    // Exactly the cap is scanned.
    const edge = fresh("window");
    const ew = window([edge], () => {
      writeFileSync(join(edge, "edge"), "");
      truncateSync(join(edge, "edge"), maxWindowFileBytes);
    });
    expect(ew.scan.unreadable).toEqual([]);
    expect(windowRow(ew.before, ew.after, ew.scan, [edge]).ok).toBe(true);
  });

  test("scan.accounted holds exactly the input paths, whichever way each was disposed of: read, vanished, set aside", () => {
    const dir = fresh("window");
    const outside = fresh("outside");
    writeFileSync(join(outside, "target"), "t");
    writeFileSync(join(dir, "read"), "x");
    symlinkSync(join(outside, "target"), join(dir, "link"));
    // Another user's file this user cannot read: the first of the two that exists
    // here (master.passwd on a Mac, shadow on Linux), none when running as root.
    const foreignUnreadable = asRoot
      ? []
      : ["/etc/master.passwd", "/etc/shadow"]
          .filter((path) => {
            try {
              accessSync(path, constants.R_OK);
              return false;
            } catch {
              return existsSync(path);
            }
          })
          .slice(0, 1);
    const paths = [
      join(dir, "read"),
      join(dir, "link"),
      join(dir, "gone"),
      ...foreignUnreadable,
    ];
    const scan = scanWindow(paths, forAll, uid);
    expect([...scan.accounted].sort()).toEqual([...paths].sort());
    expect(scan.filesRead).toBe(1);
    expect(scan.vanished).toBe(1);
    // The link is set aside as unreadable (never followed), and another user's
    // unreadable file, where this host has one, is foreign.
    expect(scan.unreadable).toEqual([join(dir, "link")]);
    expect(scan.foreign).toBe(paths.length - 3);
    expect(
      scan.filesRead + scan.foreign + scan.vanished + scan.unreadable.length,
    ).toBe(paths.length);
  });

  test("a link or a FIFO swapped in after the listing is neither followed nor blocked on, and fails the row", () => {
    const outside = fresh("outside");
    writeFileSync(join(outside, "secret"), keyHex);
    const dir = fresh("window");
    const w = window([dir], () => writeFileSync(join(dir, "f"), "x"));
    // The listed file becomes a symlink to a secret before the scan reads it.
    rmSync(join(dir, "f"));
    symlinkSync(join(outside, "secret"), join(dir, "f"));
    const linked = scanWindow(w.changed, forAll, uid);
    expect(linked.matches).toEqual([]);
    expect(linked.unreadable).toEqual([join(dir, "f")]);
    expect(windowRow(w.before, w.after, linked, [dir]).ok).toBe(false);
    // ... or a FIFO, which would block a plain read forever.
    rmSync(join(dir, "f"));
    const fifo = Bun.spawnSync(["mkfifo", join(dir, "f")]);
    expect(fifo.exitCode).toBe(0);
    const piped = scanWindow(w.changed, forAll, uid);
    expect(piped.unreadable).toEqual([join(dir, "f")]);
    expect(piped.filesRead).toBe(0);
  });

  test("a symlink in a listed root is neither followed nor listed, so a link to a secret outside is not read", () => {
    const outside = fresh("outside");
    writeFileSync(join(outside, "secret"), keyHex);
    const dir = fresh("window");
    const w = window([dir], () => {
      symlinkSync(outside, join(dir, "link"));
      writeFileSync(join(dir, "real"), "x");
    });
    expect(w.changed).toEqual([join(dir, "real")]);
    expect(w.scan.matches).toEqual([]);
  });

  test("the row's detail carries counts and paths, never the key", () => {
    const dir = fresh("window");
    const w = window([dir], () => writeFileSync(join(dir, "leak"), keyHex));
    const row = windowRow(w.before, w.after, w.scan, [dir]);
    expect(row.ok).toBe(false);
    expect(JSON.stringify(row)).not.toContain(keyHex);
    expect(row.name).toBe("key-not-in-files-present-at-the-after-listing");
  });
});

describe("the report statement row", () => {
  test("only the exact shim statement passes", () => {
    expect(reportStatementRow(shimStatement).ok).toBe(true);
    expect(shimStatement).toBe(
      "Ward plus a logging shim in front of the trusted binaries",
    );
    for (const wrong of [
      "",
      "Ward",
      `${shimStatement}.`,
      shimStatement.toLowerCase(),
    ])
      expect(reportStatementRow(wrong).ok).toBe(false);
    expect(reportStatementRow(shimStatement).name).toBe(
      "report-states-the-logging-shim",
    );
  });
});

// MUTANT REGISTER, WCLI-21 slice 4a-2b-1 (the logging shim), written and committed BEFORE any run of it. Bun 1.3.14. Each mutant is applied to scripts/qualify-linux-shim.ts unless it names another file. "only" means no other test in test/qualify-linux-shim.test.ts, test/qualify-linux-rows.test.ts or test/qualify-linux.test.ts goes red.
//   S1  interposerScript drops the newline-in-argument stop                              -> "an argument that holds a newline stops the call before anything runs or is logged" only
//   S2  the recording path exits 0 whatever the tool returned                            -> "the recorded tool's stdout reaches the caller byte for byte and keeps its exit code, whatever its trailing newlines" only
//   S3  the recording path copies the capture through command substitution               -> "the recorded tool's stdout reaches the caller byte for byte and keeps its exit code, whatever its trailing newlines" only
//   S4  installInterposers records every tool's stdout, not the printout tool's only     -> "a private directory of 0700 scripts, a 0600 log, and a presence that points at the scripts" only
//   S5  interposerScript writes no ENV lines                                             -> "a call is logged with its TCTI, environment names with digests, and arguments, and the tool's stdout and stdin pass through untouched", "a real interposed call under the adapter's environment passes the row end to end"
//   S6  installInterposers makes the directory recursively (a stale one is adopted)      -> "a directory that is there is never adopted, and a relative or odd real path is refused before anything is made" only
//   S7  installInterposers writes the scripts at 0777                                    -> "a private directory of 0700 scripts, a 0600 log, and a presence that points at the scripts" only
//   S8  envRow accepts a variable by any name                                            -> "an extra variable, a changed or missing value, or a call with no environment fails", "a real interposed call under the adapter's environment passes the row end to end"
//   S9  envRow drops the digest comparison                                               -> "an extra variable, a changed or missing value, or a call with no environment fails" only
//   S10 envRow passes with no call at all                                                -> "an extra variable, a changed or missing value, or a call with no environment fails" only
//   S11 windowRow drops the files-read control                                           -> "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S12 windowRow drops the every-changed-file-is-accounted-for equality                 -> "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S13 scanWindow reads this user's own unreadable file as foreign and skips it         -> "a directory of this user's own that cannot be listed, and a file of this user's own that cannot be read, fail closed" only (a non-root user)
//   S14 listWindowRoots reads this user's own unreadable directory as foreign            -> "a directory of this user's own that cannot be listed, and a file of this user's own that cannot be read, fail closed" only (a non-root user)
//   S15 listWindowRoots follows a symlink                                                -> "a symlink in a listed root is neither followed nor listed, so a link to a secret outside is not read" only
//   S16 listWindowRoots drops the ctime from a file's key                                -> NOTHING goes red on a Mac (the inode differs after a replacement there); expected to SURVIVE locally, as M28 did
//   S17 listWindowRoots drops the ctime AND the inode from a file's key                  -> "only files new or changed in the window are scanned, and a replacement that restores size and mtime is still changed" only
//   S18 windowRow drops the no-match requirement                                         -> "a file new in the window that holds the key, in any form, fails the row; a clean one passes", "the row's detail carries counts and paths, never the key"
//   S19 windowRow drops the required-roots requirement                                   -> "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S20 windowRow drops the same-roots-in-both-listings requirement                      -> "a root that does not exist is recorded as absent, not an error, and may stay absent" only
//   S21 privateRow lets any file at 0700 pass, not only the interposer directory's (qualify-linux-rows.ts) -> "the private row lets only the interposer directory's own files be executable" only
//   S22 parseToolLog accepts a name given twice in one call (qualify-linux-rows.ts)      -> "an ENV line is a name and a sha256 digest: a malformed one, or a name given twice in a call, is refused" only
//   S23 parseToolLog accepts an ENV digest of any shape (qualify-linux-rows.ts)          -> "an ENV line is a name and a sha256 digest: a malformed one, or a name given twice in a call, is refused" only
// OBSERVED (slice 4a-2b-1, bun 1.3.14 on a Mac, 2026-11-18; the predictions above are unchanged). S1-S15 and S17-S23 went red on exactly their predicted test(s) and no other (S5, S8 and S18 on the two tests predicted). S16 SURVIVED, as predicted: on a Mac a replaced file gets a new inode, so the ctime is only measured on Linux, where the CI run of #362 showed the inode reused. A first pass of S21-S23 also showed a red in the window test: the driver left S20's mutant in place while S21-S23 ran (it restored only at the end); S21-S23 were re-run with the file restored after each mutant and went red on their predicted test only. M1-M41 of the module are not re-run here: this slice changed only the ENV parsing and the private row in qualify-linux-rows.ts and exported holdsAny and needleForms from qualify-linux-support.ts, and the full suite is green.

// MUTANT REGISTER, WCLI-21 slice 4a-2b-1, ADDENDUM for the leader's and opum-doc's added conditions (every logged name has an expected value; each expected value holds no form of the key; an explicit argv row), written and committed BEFORE the run of S24-S27. The interposer now strips the shell's own names (PWD, OLDPWD, SHLVL, _) with /usr/bin/env -u, so no name is allowed by name: S5 and S8 above are re-expressed against that text and S1-S23 are all re-run on this tree. Bun 1.3.14.
//   S24 envRow skips the expected-values-hold-no-form-of-the-key check                       -> "an expected value that holds a raw, hex or base64 form of the key fails the row, whatever the digests say" only
//   S25 the interposer stops stripping SHLVL (the -u SHLVL in each of its three uses)        -> on a Mac (bash as sh, which adds SHLVL): "a tool behind an interposer sees exactly the adapter's four variables, whichever shell runs the script", "a real interposed call under the adapter's environment passes the row end to end", and "a call is logged with ..." does not go red; on dash it would survive, so Linux-only survival is expected
//   S26 argvRow ignores what it found in the arguments                                       -> "the argv row: an argument holding the key in any form fails, a clean log passes, and nothing logged is not a pass" only
//   S27 the interposer stops stripping _ (the -u _ in each of its three uses)                -> the same two tests as S25 on a Mac
// OBSERVED (slice 4a-2b-1 addendum round, bun 1.3.14 on a Mac, 2026-11-18; predictions above unchanged). S1-S15 and S17-S27 were all re-run on this tree and went red; S16 SURVIVED, as before. Divergences from the predictions, none a survivor: S5 (no ENV lines) also reddened "a tool behind an interposer sees exactly the adapter's four variables" (the log's names no longer matched what the tool received), a third test beside the two predicted; S8 (accept any name) also reddened "the adapter's own four variables, each with its exact value, pass, and no name outside them does" (it now asserts the shell's names fail), a third test beside the two predicted. S25 (stop stripping SHLVL) reddened only "a tool behind an interposer sees exactly the adapter's four variables": bash adds SHLVL to the tool's environment but the interposer's own listing, which runs under the same unset, did not show it, so the row's end-to-end test stays green and my prediction line for S25 (which named two tests, in a muddled sentence) over-counted. S27 (stop stripping _) reddened that test and "a real interposed call under the adapter's environment passes the row end to end", as predicted. S25 and S27 are Mac-measured (bash as sh): dash adds none of these names, so on the jetson they would not distinguish. The shell-added values are not predicted, they are removed, so nothing is allowed by name.

// MUTANT REGISTER, WCLI-21 slice 4a-2b-1, ROUND 2 (the #367 review CHANGES at 42b3835: B1, N1, N2, N4-N8, N10), written and committed BEFORE the run of S28-S36. Bun 1.3.14. Each mutant is applied to the named file and goes red on the named test(s) only, among test/qualify-linux-shim.test.ts, test/qualify-linux-rows.test.ts, test/qualify-linux.test.ts and test/tpm2-tools.test.ts.
//   S28 interposerScript drops the split check (always writes the ENV lines)              -> "a variable whose value holds a newline puts nothing of its continuation in the log or the row, whatever the continuation looks like" only
//   S29 envRow writes every logged name into detail.names, unexpected ones too             -> "a name outside the four never reaches the row, ..." , "a variable whose value holds a newline ..." and "the row's detail carries the four names and counts, never a value or an unexpected name"
//   S30 envRow drops the exactly-four-once-each block (length and uniqueness)              -> "a name outside the four never reaches the row, and a call must carry exactly the four, once each, with their digests" only (the repeated-name case)
//   S31 interposerScript drops the `|| exit 98` after the log group                        -> "a call that cannot be logged does not run: the interposer exits 98 and the tool never starts" only
//   S32 scanWindow opens without O_NOFOLLOW                                                -> "a link or a FIFO swapped in after the listing is neither followed nor blocked on, and fails the row" only
//   S33 windowRow compares the accounted count, not the accounted paths                    -> "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S34 scanWindow drops the size cap (the fstat check and the capped read)                -> "a file larger than the cap is not scanned and fails the row, and a vanished file is accounted for" only
//   S35 interposerScript drops the TCTI newline stop                                       -> "a clean environment writes no split marker, and a TCTI holding a newline stops the call" only
//   S36 src/adapters/tpm2-tools.ts toolEnvironment gains a fifth variable (FOO)            -> "the adapter builds exactly four environment variables, by the names in its source" and "the child sees the search path and the device and nothing else" in test/tpm2-tools.test.ts; reverted after

// MUTANT REGISTER, ROUND 3 (the #367 round-2 REQUEST_CHANGES at f7075e6: X1 runtime key-set pin with no shell, X2 per-file disposition, X3 observations; n2, n3, n7), written and committed BEFORE any run of S37-S41, and BEFORE the re-run of S28-S36 whose round-2 observations were never recorded in this file. Bun 1.3.14. Each mutant goes red on the named test(s) only, across test/qualify-linux-shim.test.ts, test/qualify-linux-rows.test.ts, test/qualify-linux.test.ts and test/tpm2-tools.test.ts. S28-S36 keep their round-2 predictions above and are re-run on this tree (S28 and S35 now also run with the recording interposer, S28 on both paths).
//   S37 src/adapters/tpm2-tools.ts toolEnvironment gains SHLVL by spread (`...{ SHLVL: "1" }`)  -> "the adapter's tool environment is exactly LANG, LC_ALL, PATH and TPM2TOOLS_TCTI, read from a tool that is env itself, no shell in between" only (the shell-based child test filters SHLVL, so it stays green); reverted after
//   S38 windowRow drops the count identity (filesRead + foreign + vanished + unreadable === changed)  -> "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S39 scanWindow accounts a path at the top of the loop again, before it is disposed of, and the count identity is dropped (the round-2 shape)  -> "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S40 scanWindow does not push a read file into `accounted`                              -> every test whose row must pass: "a file new in the window that holds the key, in any form, fails the row; a clean one passes", "state.json is searched for the key forms only, because it holds the nonce by design", "a window that read no file, a missing required root, and a file nobody accounted for all fail", "a root that does not exist is recorded as absent, not an error, and may stay absent", "a file larger than the cap is not scanned and fails the row, and a vanished file is accounted for"
//   S41 interposerScript drops the OUT-block `|| { rm -f "$capture"; exit 98; }`            -> "a printout call whose log cannot be written after the tool ran exits 98 and leaves no capture file" only (a non-root user)
// OBSERVED (round 3, bun 1.3.14 on a Mac, 2026-11-18; the predictions above and the round-2 predictions are unchanged, a driver restoring each file after each mutant, run on the tree at a658b76). S28-S41 were all run and each went red on exactly the test(s) predicted and no other, across the four test files; no survivor. S28 is now measured on both the plain and the recording interposer (the test loops both), S36 reddened both of its predicted tests in test/tpm2-tools.test.ts, S37 only the env-direct runtime pin (the shell-based child test stayed green, as predicted), S40 reddened exactly the five predicted window tests. These are the round-2 observations that were not recorded in this file at 4c4e3f5.

// CORRECTION AND ROUND-4 PREDICTIONS (the #367 round-3 REQUEST_CHANGES at 39c42c1, B1: the round-3 OBSERVED line above is wrong for S36). The register is append-only, so the two lines above stay. S36's round-2 prediction named "the adapter builds exactly four environment variables, by the names in its source", a test deleted in a658b76 (the X1 fix); and with toolEnvironment gaining FOO the runtime pin "the adapter's tool environment is exactly LANG, LC_ALL, PATH and TPM2TOOLS_TCTI, read from a tool that is env itself, no shell in between" must go red too, because catching a fifth name is its whole purpose, and the prediction did not name it. So "exactly the predicted and no other" was false for S36. Corrected prediction for S36 on the current tree: in test/tpm2-tools.test.ts, the runtime pin above and "the child sees the search path and the device and nothing else", and no other. The pin now runs every tool Ward runs (requiredTools and the diagnostic tool), and scan.accounted has an isolating test. Written and committed BEFORE the run of S42-S43 and the full re-run of S28-S41 on this tree, which records each mutant by the test names that went red. Bun 1.3.14, a Mac (bash as sh); the Linux target's /bin/sh is dash, so none of this was measured there.
//   S42 scanWindow's dispose helper does not push into `accounted` (the read path still does)  -> "scan.accounted holds exactly the input paths, whichever way each was disposed of: read, vanished, set aside", and "a file larger than the cap is not scanned and fails the row, and a vanished file is accounted for" (a vanished file stops being accounted for, so its row fails)
//   S43 src/adapters/tpm2-tools.ts toolEnvironment adds FOO only for tpm2_unseal                -> the runtime pin only (it now loops every tool); the child test runs tpm2_create, so it stays green; reverted after
// OBSERVED (round 4, bun 1.3.14 on a Mac with bash as sh, 2026-11-18; run on the tree at faccefc; the predictions above and the S28-S41 predictions are unchanged, a driver restoring each file after each mutant). This supersedes the round-3 OBSERVED line, which was wrong for S36. Red tests per mutant, none a survivor (names shortened to their first words):
//   S28 "a variable whose value holds a newline puts nothing of its continuation ..." (now on the plain and the recording interposer)
//   S29 "a name outside the four never reaches the row ...", "a variable whose value holds a newline ...", "the row's detail carries the four names and counts ..."
//   S30 "a name outside the four never reaches the row ..." only
//   S31 "a call that cannot be logged does not run: the interposer exits 98 ..." only
//   S32 "a link or a FIFO swapped in after the listing ..." AND "scan.accounted holds exactly the input paths ..." (the second is a divergence: the new test sees the followed link in `unreadable`, which the S32 prediction did not name; not a survivor)
//   S33 "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S34 "a file larger than the cap is not scanned and fails the row, and a vanished file is accounted for" only
//   S35 "a clean environment writes no split marker, and a TCTI holding a newline stops the call" only
//   S36 (test/tpm2-tools.test.ts) "the adapter's tool environment is exactly LANG, LC_ALL, PATH and TPM2TOOLS_TCTI, read from a tool that is env itself, no shell in between" and "the child sees the search path and the device and nothing else": as the corrected prediction says
//   S37 the env-direct runtime pin only
//   S38 "a window that read no file, a missing required root, and a file nobody accounted for all fail" only
//   S39 the same single test
//   S40 six tests, one beyond the five predicted: "a file larger than the cap ...", "a file new in the window that holds the key ...", "a root that does not exist is recorded as absent ...", "a window that read no file ...", "state.json is searched for the key forms only ...", and the new "scan.accounted holds exactly the input paths ..." (a divergence, not a survivor)
//   S41 "a printout call whose log cannot be written after the tool ran exits 98 and leaves no capture file" only
//   S42 "a file larger than the cap ..." and "scan.accounted holds exactly the input paths ...", as predicted
//   S43 the env-direct runtime pin only (it now loops every tool), as predicted
// The Linux target's /bin/sh is dash, not bash: S25 and S27 style shell-name effects, and everything above, are Mac measurements; the jetson run measures the dash case.

// CORRECTIONS AND PREDICTION, slice 4a-2b-2, first commit (the #367 round-4 APPROVE's non-blocking items; the register is append-only, so nothing above is edited). n1: the S32 line in the round-4 OBSERVED list explains the second red backwards. Without O_NOFOLLOW the link is followed and read, so in "scan.accounted holds exactly the input paths ..." filesRead is 2, not 1, and `unreadable` is [], not [the link]. n3: the S39 mutant of round 3 dropped the count identity; the variant that accounts a path at the top of the loop but KEEPS the count identity (call it S44) is predicted EQUIVALENT: the "accounted holds exactly the input paths" test and every other test stay green, because the count identity (filesRead + foreign + vanished + unreadable === changed) already forces a skipped file to show, so that test does not close it. n2: the foreign bucket of that test now uses the first of /etc/master.passwd and /etc/shadow that exists and cannot be read, so it runs on a Linux CI runner too. Written and committed BEFORE the run of S44.
//   S44 scanWindow accounts a path at the top of the loop again (before disposal) and windowRow keeps the count identity  -> NOTHING goes red (equivalent mutant); expected to SURVIVE
// OBSERVED (slice 4a-2b-2, bun 1.3.14 on a Mac with bash as sh, 2026-11-18; the prediction above unchanged). S44 SURVIVED, as predicted: no test went red, so the "accounted holds exactly the input paths" test does not close it and the count identity does. It is recorded as an equivalent mutant, not as closed by that test.
