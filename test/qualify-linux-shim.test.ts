// WCLI-21 slice 4a-2b: the logging shim (the interposers, the environment row and
// the window rows) measured against fake tools, so no TPM is reached. The
// interposers are real shell scripts run by /bin/sh; the tools they front are
// small scripts written here.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
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

// A fake real tool: it echoes its arguments, copies stdin to stderr's sibling
// file named by $FAKE_STDIN_COPY... kept simple: it prints what the test tells
// it to print (a file's bytes), exits with the code in its code file, and
// reports what it received on stdin on stderr as a byte count.
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
        // The capture file is removed.
        expect(existsSync(`${log}.out.1`)).toBe(false);
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
  const callWith = (
    env: Record<string, string>,
    dir = "/run/interposers",
  ): ToolCall => ({
    tool: "tpm2_load",
    tcti: ruledTcti,
    args: [],
    env: Object.entries(env).map(([name, value]) => ({
      name,
      digest: sha256(Buffer.from(value)),
    })),
    ...(dir === "" ? {} : {}),
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
      .map((line) => line.split("=")[0])
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

  test("the row's detail carries names and counts, never a value", () => {
    const row = envRow(
      [callWith({ ...good, SECRET_NAME_ONLY: "value-that-must-not-appear" })],
      "/run/interposers",
      forms,
    );
    expect(JSON.stringify(row)).not.toContain("value-that-must-not-appear");
    expect(JSON.stringify(row.detail)).toContain("SECRET_NAME_ONLY");
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
    expect(
      windowRow(w.before, w.after, { ...w.scan, filesRead: 2 }, [dir]).ok,
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
    const oversize = {
      ...scan,
      unreadable: [join(dir, "big")],
    };
    expect(windowRow(before, after, oversize, [dir]).ok).toBe(false);
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
    expect(row.name).toBe("key-not-in-temp-files-of-the-window");
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
