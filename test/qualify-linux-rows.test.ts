// WCLI-21 slice 4a-2a: how each row of the Linux T26 harness is decided, and the
// helpers that touch only the directories they are handed. Nothing here reaches
// a TPM: the tool interposer is run against a fake tool, and the session rows
// are decided from logs written in the shape the interposer writes.
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
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import {
  bootIdRow,
  childEnvironment,
  createRunDirectory,
  groupsRow,
  handleListsRow,
  interposerScript,
  keyRows,
  noPersistentHandlesRow,
  parseToolLog,
  passwdHome,
  privateRow,
  realWardRow,
  removeRunDirectory,
  ruledRunDirectory,
  ruledTcti,
  saltedRow,
  scanRows,
  sessionPrintoutRows,
  stripOneNewline,
  tctiRow,
  type ToolCall,
  wardStoreSnapshot,
} from "../scripts/qualify-linux-rows.ts";
import {
  bootIdChanged,
  deriveKey,
  type HandleSnapshot,
  runDirectoryName,
  sha256,
} from "../scripts/qualify-linux-support.ts";

const root = mkdtempSync(join(tmpdir(), "ward-qualify-linux-rows-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let counter = 0;
const makeHome = (): string => {
  const dir = join(root, `home-${counter++}`);
  mkdirSync(dir);
  return realpathSync(dir);
};
const makeDir = (name: string): string => {
  const dir = join(root, `${name}-${counter++}`);
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  return dir;
};
const asRoot = process.getuid?.() === 0;
const nonceA =
  "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";
const bootA = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";
const bootB = "ffeeddcc-bbaa-4998-8776-655443322110";

describe("the run directory's home and path", () => {
  test("the home is the passwd entry's, whatever $HOME says", () => {
    const saved = process.env.HOME;
    try {
      process.env.HOME = "/nonexistent-home-for-the-test";
      expect(passwdHome()).toBe(userInfo().homedir);
      expect(passwdHome()).not.toBe("/nonexistent-home-for-the-test");
    } finally {
      process.env.HOME = saved;
    }
  });

  test("the run directory is computed from the home, never taken from an argument", () => {
    const home = makeHome();
    expect(ruledRunDirectory(home)).toBe(join(home, runDirectoryName));
    const linked = join(root, `linked-${counter++}`);
    symlinkSync(home, linked);
    expect(ruledRunDirectory(linked)).toBe(join(home, runDirectoryName));
  });
});

describe("creating and removing the run directory", () => {
  test("creation is exclusive, private, and never adopts a directory that is there", () => {
    const home = makeHome();
    const directory = join(home, runDirectoryName);
    createRunDirectory(directory, home, []);
    expect(statSync(directory).mode & 0o7777).toBe(0o700);
    expect(() => createRunDirectory(directory, home, [])).toThrow(
      /already exists/,
    );
    // A stale directory with content from an earlier run is not adopted either.
    writeFileSync(join(directory, "state.json"), "stale", { mode: 0o600 });
    expect(() => createRunDirectory(directory, home, [])).toThrow(
      /already exists/,
    );
    expect(readFileSync(join(directory, "state.json"), "utf8")).toBe("stale");
  });

  test("creation refuses any path but the literal one, and a home that does not resolve", () => {
    const home = makeHome();
    expect(() => createRunDirectory(join(home, "other"), home, [])).toThrow(
      /directly under the real home/,
    );
    expect(existsSync(join(home, "other"))).toBe(false);
    const missing = join(root, "no-such-home");
    expect(() =>
      createRunDirectory(join(missing, runDirectoryName), missing, []),
    ).toThrow(/cannot be resolved/);
  });

  test("removal deletes the tree, and a link inside it is removed, not followed", () => {
    const home = makeHome();
    const directory = join(home, runDirectoryName);
    createRunDirectory(directory, home, []);
    mkdirSync(join(directory, "store", "deep"), { recursive: true });
    writeFileSync(join(directory, "store", "deep", "f"), "x");
    const outside = join(root, `outside-${counter++}`);
    mkdirSync(outside);
    writeFileSync(join(outside, "keep"), "keep");
    symlinkSync(outside, join(directory, "link"));
    expect(removeRunDirectory(directory, home, [])).toBe(true);
    expect(existsSync(directory)).toBe(false);
    expect(readFileSync(join(outside, "keep"), "utf8")).toBe("keep");
    expect(removeRunDirectory(directory, home, [])).toBe(false);
  });

  test("removal re-asserts the path: a run directory swapped for a link is refused and the target survives", () => {
    const home = makeHome();
    const directory = join(home, runDirectoryName);
    createRunDirectory(directory, home, []);
    rmSync(directory, { recursive: true });
    const target = join(root, `swapped-${counter++}`);
    mkdirSync(target);
    writeFileSync(join(target, "keep"), "keep");
    symlinkSync(target, directory);
    expect(() => removeRunDirectory(directory, home, [])).toThrow(/symlink/);
    expect(readFileSync(join(target, "keep"), "utf8")).toBe("keep");
  });

  test("removal refuses the home itself, a sibling, and a trailing slash", () => {
    const home = makeHome();
    mkdirSync(join(home, "sibling"));
    writeFileSync(join(home, "sibling", "keep"), "keep");
    for (const path of [
      home,
      join(home, "sibling"),
      `${home}/${runDirectoryName}/`,
    ])
      expect(() => removeRunDirectory(path, home, [])).toThrow();
    expect(readFileSync(join(home, "sibling", "keep"), "utf8")).toBe("keep");
  });
});

describe("the environment of a packaged child", () => {
  test("it is built, holds the run's own home, and inherits nothing", () => {
    process.env.WARD_QUALIFY_INHERIT_PROBE = "leak";
    try {
      const env = childEnvironment("/run/home", "/run/tmp");
      expect(env).toEqual({
        HOME: "/run/home",
        PATH: "/usr/bin:/bin",
        TMPDIR: "/run/tmp",
        TERM: "xterm",
      });
      expect(JSON.stringify(env)).not.toContain("leak");
    } finally {
      delete process.env.WARD_QUALIFY_INHERIT_PROBE;
    }
  });
});

describe("the real ~/.ward, measured and not read", () => {
  test("a missing store is absent, and an untouched one reads the same twice", () => {
    const base = makeDir("ward");
    expect(wardStoreSnapshot(join(base, "none"))).toBe("absent");
    const ward = join(base, ".ward");
    mkdirSync(ward);
    writeFileSync(join(ward, "vault.db"), "vault");
    expect(wardStoreSnapshot(ward)).toBe(wardStoreSnapshot(ward));
    expect(wardStoreSnapshot(ward)).not.toBe("absent");
  });

  test("a new file, a changed file, a mode change, a deletion and a replacement each change it", () => {
    const base = makeDir("ward");
    const ward = join(base, ".ward");
    mkdirSync(ward);
    writeFileSync(join(ward, "vault.db"), "vault", { mode: 0o600 });
    // Each step is compared with a snapshot taken just before it: even a change
    // that is undone moves the directory's own mtime, which is a touch.
    const moves = (step: () => void): boolean => {
      const before = wardStoreSnapshot(ward);
      step();
      return wardStoreSnapshot(ward) !== before;
    };
    expect(moves(() => writeFileSync(join(ward, "new"), "x"))).toBe(true);
    expect(moves(() => writeFileSync(join(ward, "new"), "y"))).toBe(true);
    expect(moves(() => chmodSync(join(ward, "new"), 0o640))).toBe(true);
    expect(moves(() => rmSync(join(ward, "new")))).toBe(true);
    // The same bytes in a new file at the same path: the inode moves.
    expect(
      moves(() => {
        rmSync(join(ward, "vault.db"));
        writeFileSync(join(ward, "vault.db"), "vault", { mode: 0o600 });
      }),
    ).toBe(true);
    // A step that does nothing moves nothing.
    expect(moves(() => undefined)).toBe(false);
  });

  test("taking a snapshot never opens a file: an unreadable one still snapshots", () => {
    if (asRoot) return;
    const base = makeDir("ward");
    const ward = join(base, ".ward");
    mkdirSync(ward);
    writeFileSync(join(ward, "sealed"), "x", { mode: 0o600 });
    chmodSync(join(ward, "sealed"), 0o000);
    try {
      expect(() => wardStoreSnapshot(ward)).not.toThrow();
    } finally {
      chmodSync(join(ward, "sealed"), 0o600);
    }
  });

  test("the row holds only for two equal, non-empty snapshots", () => {
    expect(realWardRow("a", "a").ok).toBe(true);
    expect(realWardRow("absent", "absent").ok).toBe(true);
    expect(realWardRow("a", "b").ok).toBe(false);
    expect(realWardRow("absent", "a").ok).toBe(false);
    expect(realWardRow("", "").ok).toBe(false);
    expect(realWardRow("a", "a").name).toBe("real-ward-untouched");
  });
});

describe("the boot-id row", () => {
  test("exactly one trailing newline is stripped, and nothing else", () => {
    expect(stripOneNewline(`${bootA}\n`)).toBe(bootA);
    expect(stripOneNewline(`${bootA}\n\n`)).toBe(`${bootA}\n`);
    expect(stripOneNewline(bootA)).toBe(bootA);
    expect(stripOneNewline(` ${bootA}\n`)).toBe(` ${bootA}`);
    expect(stripOneNewline("")).toBe("");
  });

  test("a different, stable, valid boot passes, and each way to read it wrongly fails", () => {
    expect(bootIdRow(bootA, `${bootB}\n`, `${bootB}\n`).ok).toBe(true);
    expect(bootIdRow(bootA, bootB, bootB).ok).toBe(true);
    // The same boot: no reboot.
    expect(bootIdRow(bootA, `${bootA}\n`, `${bootA}\n`).ok).toBe(false);
    // Two valid ids that differ between the reads: the wrong file.
    expect(
      bootIdRow(bootA, `${bootB}\n`, `${bootA.replace("0b", "0c")}\n`).ok,
    ).toBe(false);
    for (const bad of [
      "",
      "\n",
      "unknown\n",
      `${bootB.toUpperCase()}\n`,
      `${bootB}\n\n`,
      ` ${bootB}\n`,
      "cat: /proc/sys/kernel/random/boot_id: No such file or directory\n",
    ])
      expect(bootIdRow(bootA, bad, bad).ok).toBe(false);
    expect(bootIdRow(bootA, bootB, bootB).name).toBe(
      "boot-id-differs-from-seal",
    );
  });

  test("the row's ok comes only from bootIdChanged and the stability of the two reads", () => {
    const reads = [
      "",
      bootA,
      `${bootA}\n`,
      bootB,
      `${bootB}\n`,
      `${bootB}\n\n`,
      ` ${bootB}`,
      bootB.toUpperCase(),
      "unknown",
      "ffeeddcc-bbaa-4998-8776-655443322111\n",
    ];
    const sealeds = [bootA, bootB, "", "x"];
    for (const sealed of sealeds)
      for (const first of reads)
        for (const second of reads) {
          const a = stripOneNewline(first);
          const b = stripOneNewline(second);
          let reference = false;
          try {
            reference = a === b && bootIdChanged(sealed, a);
          } catch {
            reference = false;
          }
          expect(bootIdRow(sealed, first, second).ok).toBe(reference);
        }
  });
});

describe("the handle rows", () => {
  const read = (stdout = "", exitCode = 0) => ({ exitCode, stdout });
  const snapshot = (over: Partial<HandleSnapshot> = {}): HandleSnapshot => ({
    "handles-transient": read(),
    "handles-persistent": read(),
    "handles-saved-session": read(),
    "handles-loaded-session": read(),
    ...over,
  });
  const call = (tool: string, args: string[] = []): ToolCall => ({
    tool,
    tcti: ruledTcti,
    args,
  });

  test("unchanged lists pass, a moved or an unread list fails, with the reason in the detail", () => {
    expect(handleListsRow(snapshot(), snapshot()).ok).toBe(true);
    const moved = handleListsRow(
      snapshot(),
      snapshot({ "handles-saved-session": read("- 0x2000000\n") }),
    );
    expect(moved.ok).toBe(false);
    expect(moved.detail).toEqual({ moved: ["handles-saved-session"] });
    const unread = handleListsRow(
      snapshot({ "handles-transient": read("", 1) }),
      snapshot(),
    );
    expect(unread.ok).toBe(false);
    expect(JSON.stringify(unread.detail)).toContain("not all read");
  });

  test("no persistent handle means the list is as it was and nothing persisted an object", () => {
    expect(noPersistentHandlesRow(snapshot(), snapshot(), []).ok).toBe(true);
    expect(
      noPersistentHandlesRow(snapshot(), snapshot(), [call("tpm2_load")]).ok,
    ).toBe(true);
    expect(
      noPersistentHandlesRow(snapshot(), snapshot(), [
        call("tpm2_evictcontrol"),
      ]).ok,
    ).toBe(false);
    expect(
      noPersistentHandlesRow(
        snapshot(),
        snapshot({ "handles-persistent": read("- 0x81000001\n") }),
        [],
      ).ok,
    ).toBe(false);
    // A persistent handle that was already there and did not move is not ours.
    const held = snapshot({ "handles-persistent": read("- 0x81000001\n") });
    expect(noPersistentHandlesRow(held, held, []).ok).toBe(true);
    // An unread list is never "unchanged".
    expect(
      noPersistentHandlesRow(
        snapshot({ "handles-persistent": read("", 1) }),
        snapshot(),
        [],
      ).ok,
    ).toBe(false);
  });
});

describe("the effective groups row", () => {
  test("numeric ids with as many names are recorded, anything else is not", () => {
    expect(groupsRow("1000 4 27\n", "ward adm sudo\n").ok).toBe(true);
    expect(groupsRow("1000", "ward").ok).toBe(true);
    for (const [ids, names] of [
      ["", ""],
      ["1000 4", "ward"],
      ["1000 x", "ward adm"],
      ["unavailable", "unavailable"],
      ["1000 4", ""],
      ["id: command not found", "ward adm"],
    ] as const)
      expect(groupsRow(ids, names).ok).toBe(false);
    expect(groupsRow("1000 4", "ward adm").detail).toEqual({
      ids: "1000 4",
      names: "ward adm",
    });
  });
});

describe("the key rows", () => {
  const key = deriveKey(nonceA);
  const digest = sha256(key);
  const byName = (rows: { name: string; ok: boolean }[], name: string) =>
    rows.find((row) => row.name === name)?.ok;

  test("the sealed bytes are compared to deriveKey(nonce) byte for byte", () => {
    const good = keyRows(nonceA, digest, Uint8Array.from(key));
    expect(byName(good, "synthetic-key-only")).toBe(true);
    expect(byName(good, "unseal-matches-sealed")).toBe(true);
    for (const at of [0, 15, 31]) {
      const wrong = Uint8Array.from(key);
      wrong[at] = (wrong[at] ?? 0) ^ 1;
      expect(
        byName(keyRows(nonceA, digest, wrong), "unseal-matches-sealed"),
      ).toBe(false);
    }
    expect(
      byName(
        keyRows(nonceA, digest, key.subarray(0, 31)),
        "unseal-matches-sealed",
      ),
    ).toBe(false);
    expect(
      byName(
        keyRows(nonceA, digest, new Uint8Array(0)),
        "unseal-matches-sealed",
      ),
    ).toBe(false);
  });

  test("a stored digest that is not the synthetic key's own fails the synthetic-key row", () => {
    const rows = keyRows(
      nonceA,
      sha256(Buffer.from("another key")),
      Uint8Array.from(key),
    );
    expect(byName(rows, "synthetic-key-only")).toBe(false);
    expect(byName(rows, "unseal-matches-sealed")).toBe(true);
    expect(rows.every((row) => !JSON.stringify(row).includes(nonceA))).toBe(
      true,
    );
  });
});

describe("the tool interposer, run against a fake tool", () => {
  const shell = (
    script: string,
    args: string[],
    input = "",
    env: Record<string, string> = {},
  ) =>
    Bun.spawnSync(["/bin/sh", script, ...args], {
      stdin: Buffer.from(input),
      env: { PATH: "/usr/bin:/bin", ...env },
    });
  const fixture = (name: string, body: string) => {
    const dir = makeDir(name);
    const fake = join(dir, "fake-tool");
    writeFileSync(fake, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
    chmodSync(fake, 0o700);
    return {
      dir,
      fake,
      log: join(dir, "tools.log"),
      wrapper: join(dir, "wrapper"),
    };
  };
  const install = (
    f: { fake: string; log: string; wrapper: string },
    tool: string,
    record: boolean,
  ) =>
    writeFileSync(f.wrapper, interposerScript(tool, f.fake, f.log, record), {
      mode: 0o700,
    });

  test("it records the call, passes stdin through, and records no stdout, and the tool's exit code survives", () => {
    const f = fixture(
      "interpose",
      'cat > "$(dirname "$0")/got-stdin"; echo to-stdout; exit 3',
    );
    install(f, "tpm2_create", false);
    const run = shell(f.wrapper, ["-u", "a b", "-Q"], "the-secret-key-bytes", {
      TPM2TOOLS_TCTI: ruledTcti,
    });
    expect(run.exitCode).toBe(3);
    expect(run.stdout.toString()).toBe("to-stdout\n");
    expect(readFileSync(join(f.dir, "got-stdin"), "utf8")).toBe(
      "the-secret-key-bytes",
    );
    const log = readFileSync(f.log, "utf8");
    expect(log).not.toContain("the-secret-key-bytes");
    expect(log).not.toContain("to-stdout");
    expect(parseToolLog(log)).toEqual([
      { tool: "tpm2_create", tcti: ruledTcti, args: ["-u", "a b", "-Q"] },
    ]);
  });

  test("a tool whose stdout is a printout has it recorded, and its exit code still survives", () => {
    const f = fixture(
      "interpose-out",
      'printf "Session-Handle: 0x1\\nSession-Attributes: continuesession|decrypt|encrypt\\n"; exit 0',
    );
    install(f, "tpm2_sessionconfig", true);
    const run = shell(f.wrapper, ["s.ctx"], "", { TPM2TOOLS_TCTI: ruledTcti });
    expect(run.exitCode).toBe(0);
    expect(run.stdout.toString()).toContain("decrypt|encrypt");
    const calls = parseToolLog(readFileSync(f.log, "utf8"));
    expect(calls.length).toBe(1);
    expect(calls[0]?.stdout).toContain(
      "Session-Attributes: continuesession|decrypt|encrypt",
    );
    const failing = fixture("interpose-fail", "echo oops; exit 5");
    install(failing, "tpm2_sessionconfig", true);
    expect(shell(failing.wrapper, ["s"], "", {}).exitCode).toBe(5);
  });

  test("an argument that holds a newline stops the call before anything runs or is logged", () => {
    const f = fixture("interpose-newline", 'touch "$(dirname "$0")/ran"');
    install(f, "tpm2_load", false);
    const run = shell(f.wrapper, ["a\nCALL forged"]);
    expect(run.exitCode).toBe(97);
    expect(existsSync(join(f.dir, "ran"))).toBe(false);
    expect(existsSync(f.log)).toBe(false);
  });

  test("the script is refused for a path or a tool name outside letters, digits and _ . / -", () => {
    for (const bad of ["a b", "a'b", "a;b", "$x", "a\nb"]) {
      expect(() =>
        interposerScript(bad, "/bin/true", "/x/log", false),
      ).toThrow();
      expect(() => interposerScript("t", bad, "/x/log", false)).toThrow();
      expect(() => interposerScript("t", "/bin/true", bad, false)).toThrow();
    }
  });
});

describe("the tool log parser", () => {
  test("each way of being malformed is refused", () => {
    for (const text of [
      "garbage\n",
      "CALL tpm2_load\nARG x\n",
      "CALL tpm2_load\nCALL tpm2_load\nEND\n",
      "OUT-BEGIN\nx\nOUT-END\nRC 0\nDONE\n",
      "CALL a\nEND\nOUT-BEGIN\nx\n",
      "CALL a\nEND\nOUT-BEGIN\nx\nOUT-END\nRC x\nDONE\n",
      "ARG x\n",
    ])
      expect(() => parseToolLog(text)).toThrow(/malformed/);
    expect(parseToolLog("")).toEqual([]);
  });
});

describe("the TCTI row", () => {
  const call = (tcti: string): ToolCall => ({
    tool: "tpm2_load",
    tcti,
    args: [],
  });
  test("every recorded call used the ruled TCTI, and no call at all is not a pass", () => {
    expect(tctiRow([call(ruledTcti), call(ruledTcti)]).ok).toBe(true);
    expect(tctiRow([]).ok).toBe(false);
    expect(tctiRow([call(ruledTcti), call("device:/dev/tpm0")]).ok).toBe(false);
    expect(tctiRow([call("")]).ok).toBe(false);
    expect(tctiRow([call("mssim:host=localhost")]).ok).toBe(false);
  });
});

describe("the session rows", () => {
  const on =
    "Session-Handle: 0x02000000\nSession-Attributes: continuesession|decrypt|encrypt\n";
  const off =
    "Session-Handle: 0x02000000\nSession-Attributes: continuesession\n";
  const make = (tool: string, args: string[], stdout?: string): ToolCall => ({
    tool,
    tcti: ruledTcti,
    args,
    ...(stdout === undefined ? {} : { stdout }),
  });
  const primary = "/scratch/primary.ctx";
  const session = "/scratch/session.ctx";
  // The sequence unsealKey runs, as the interposer would have logged it.
  const unseal = (
    over: { printout?: string; salt?: string; sessionFlag?: string } = {},
  ): ToolCall[] => [
    make("tpm2_createprimary", ["-C", "o", "-c", primary, "-Q"]),
    make("tpm2_load", ["-C", primary, "-c", "/scratch/key.ctx", "-Q"]),
    make("tpm2_startauthsession", [
      "--hmac-session",
      "-c",
      over.salt ?? primary,
      "-S",
      session,
      "-Q",
    ]),
    make("tpm2_sessionconfig", [
      "--enable-decrypt",
      "--enable-encrypt",
      session,
    ]),
    make("tpm2_sessionconfig", [session], over.printout ?? on),
    make("tpm2_unseal", [
      "-c",
      "/scratch/key.ctx",
      "-p",
      over.sessionFlag ?? `session:${session}`,
    ]),
  ];
  const rowOf = (calls: ToolCall[], name: string) =>
    [...sessionPrintoutRows(calls), saltedRow(calls)].find(
      (row) => row.name === name,
    )?.ok;

  test("the printout of the session the unseal ran under, reading on, passes all three rows", () => {
    const calls = unseal();
    expect(rowOf(calls, "session-printout-decrypt-encrypt")).toBe(true);
    expect(rowOf(calls, "session-printout-is-the-unseal-session")).toBe(true);
    expect(rowOf(calls, "session-salted-to-primary")).toBe(true);
  });

  test("a printout that reads off fails the printout row but is still the unseal's own session", () => {
    const calls = unseal({ printout: off });
    expect(rowOf(calls, "session-printout-decrypt-encrypt")).toBe(false);
    expect(rowOf(calls, "session-printout-is-the-unseal-session")).toBe(true);
    for (const printout of [
      "",
      "garbage",
      "Session-Handle: 0x1\n",
      `${on}extra\n`,
    ])
      expect(
        rowOf(unseal({ printout }), "session-printout-decrypt-encrypt"),
      ).toBe(false);
  });

  test("a printout of some other session, or an earlier one, is not the unseal's", () => {
    const other = unseal();
    other[4] = make("tpm2_sessionconfig", ["/scratch/other.ctx"], on);
    expect(rowOf(other, "session-printout-is-the-unseal-session")).toBe(false);
    expect(rowOf(other, "session-printout-decrypt-encrypt")).toBe(false);
    // A printout taken BEFORE the session was started does not count.
    const stale = unseal();
    const printout = stale.splice(4, 1)[0] as ToolCall;
    stale.unshift(printout);
    expect(rowOf(stale, "session-printout-is-the-unseal-session")).toBe(false);
    // The unseal under a path no startauthsession wrote.
    expect(
      rowOf(
        unseal({ sessionFlag: "session:/scratch/unknown.ctx" }),
        "session-printout-is-the-unseal-session",
      ),
    ).toBe(false);
    // The unseal not under a session at all.
    expect(
      rowOf(
        unseal({ sessionFlag: "/scratch/x" }),
        "session-printout-is-the-unseal-session",
      ),
    ).toBe(false);
  });

  test("no unseal in the log, or a second unseal with no printout of its own, is not a pass", () => {
    const none = unseal().slice(0, 5);
    for (const name of [
      "session-printout-decrypt-encrypt",
      "session-printout-is-the-unseal-session",
      "session-salted-to-primary",
    ])
      expect(rowOf(none, name)).toBe(false);
    const second = [
      ...unseal(),
      make("tpm2_unseal", [
        "-c",
        "/scratch/key.ctx",
        "-p",
        "session:/scratch/second.ctx",
      ]),
    ];
    expect(rowOf(second, "session-printout-is-the-unseal-session")).toBe(false);
    expect(rowOf(second, "session-salted-to-primary")).toBe(false);
  });

  test("the session is salted to the primary: not unsalted, not a policy session, not salted to another key", () => {
    const unsalted = unseal();
    unsalted[2] = make("tpm2_startauthsession", [
      "--hmac-session",
      "-S",
      session,
      "-Q",
    ]);
    expect(rowOf(unsalted, "session-salted-to-primary")).toBe(false);
    expect(
      rowOf(
        unseal({ salt: "/scratch/other-key.ctx" }),
        "session-salted-to-primary",
      ),
    ).toBe(false);
    const policy = unseal();
    policy[2] = make("tpm2_startauthsession", [
      "--policy-session",
      "-c",
      primary,
      "-S",
      session,
      "-Q",
    ]);
    expect(rowOf(policy, "session-salted-to-primary")).toBe(false);
    // No createprimary in the log: nothing says what the salt key was.
    const noPrimary = unseal().filter((c) => c.tool !== "tpm2_createprimary");
    expect(rowOf(noPrimary, "session-salted-to-primary")).toBe(false);
  });
});

describe("the secret-scan rows", () => {
  const scan = (filesRead: number, matches: string[] = []) => ({
    filesRead,
    matches,
  });
  const calls: ToolCall[] = [{ tool: "tpm2_load", tcti: ruledTcti, args: [] }];
  const byName = (rows: { name: string; ok: boolean }[], name: string) =>
    rows.find((row) => row.name === name)?.ok;

  test("clean scans that read files and a log with calls pass both rows", () => {
    const rows = scanRows(scan(3), scan(1), calls);
    expect(byName(rows, "secret-scan-clean")).toBe(true);
    expect(byName(rows, "key-not-in-argv-environment-or-temp-file")).toBe(true);
  });

  test("a match in the store fails both, and a match in the log fails the argv-and-environment row", () => {
    const store = scanRows(scan(3, ["store/x"]), scan(1), calls);
    expect(byName(store, "secret-scan-clean")).toBe(false);
    expect(byName(store, "key-not-in-argv-environment-or-temp-file")).toBe(
      false,
    );
    const log = scanRows(scan(3), scan(1, ["tools.log"]), calls);
    expect(byName(log, "key-not-in-argv-environment-or-temp-file")).toBe(false);
  });

  test("a scan that read nothing, or a log with no call, proves nothing", () => {
    for (const rows of [
      scanRows(scan(0), scan(1), calls),
      scanRows(scan(3), scan(0), calls),
      scanRows(scan(3), scan(1), []),
    ]) {
      expect(byName(rows, "secret-scan-clean")).toBe(false);
      expect(byName(rows, "key-not-in-argv-environment-or-temp-file")).toBe(
        false,
      );
    }
  });
});

describe("the private-directory row", () => {
  test("a private tree passes and a wider mode fails with the entry named", () => {
    const tree = makeDir("private");
    writeFileSync(join(tree, "ok"), "x", { mode: 0o600 });
    expect(privateRow(tree).ok).toBe(true);
    writeFileSync(join(tree, "wide"), "x");
    chmodSync(join(tree, "wide"), 0o660);
    const row = privateRow(tree);
    expect(row.ok).toBe(false);
    expect(row.detail).toEqual({ problems: ["wide: 660"] });
  });
});

// MUTANT REGISTER, WCLI-21 slice 4a-2a (the rows of the Linux T26 harness), written BEFORE any run of it. Bun 1.3.14 on each observation. Each mutant is applied to scripts/qualify-linux-rows.ts unless it names another file. "only" means no other test in the two qualify-linux test files goes red.
//   M1  passwdHome returns $HOME                                                        -> "the home is the passwd entry's, whatever $HOME says" only
//   M2  createRunDirectory makes the directory recursively (EEXIST no longer raised)    -> "creation is exclusive, private, and never adopts a directory that is there" only
//   M3  createRunDirectory skips the run-directory guard                                -> "creation refuses any path but the literal one, and a home that does not resolve" only
//   M4  removeRunDirectory skips the run-directory guard                                -> "removal re-asserts the path: a run directory swapped for a link is refused and the target survives", "removal refuses the home itself, a sibling, and a trailing slash"
//   M5  stripOneNewline trims instead                                                   -> "exactly one trailing newline is stripped, and nothing else", "a different, stable, valid boot passes, and each way to read it wrongly fails"
//   M6  bootIdRow drops the stability of the two reads                                  -> "a different, stable, valid boot passes, and each way to read it wrongly fails", "the row's ok comes only from bootIdChanged and the stability of the two reads"
//   M7  bootIdRow decides by first !== sealed instead of bootIdChanged                  -> "a different, stable, valid boot passes, and each way to read it wrongly fails", "the row's ok comes only from bootIdChanged and the stability of the two reads"
//   M8  wardStoreSnapshot drops the inode                                               -> "a new file, a changed file, a mode change, a deletion and a replacement each change it" only
//   M9  wardStoreSnapshot drops the mtime                                               -> "a new file, a changed file, a mode change, a deletion and a replacement each change it" only
//   M10 wardStoreSnapshot reads each file                                               -> "taking a snapshot never opens a file: an unreadable one still snapshots" only (a non-root user)
//   M11 realWardRow drops the non-empty requirement                                     -> "the row holds only for two equal, non-empty snapshots" only
//   M12 noPersistentHandlesRow ignores a tpm2_evictcontrol call                         -> "no persistent handle means the list is as it was and nothing persisted an object" only
//   M13 handleListsRow reads an unread list as ok                                       -> "unchanged lists pass, a moved or an unread list fails, with the reason in the detail" only
//   M14 groupsRow drops the ids-and-names count equality                                -> "numeric ids with as many names are recorded, anything else is not" only
//   M15 keyRows decides unseal-matches-sealed by the stored digest instead of the bytes -> "a stored digest that is not the synthetic key's own fails the synthetic-key row" only
//   M16 keyRows drops the length check before the constant-time compare                 -> "the sealed bytes are compared to deriveKey(nonce) byte for byte" only (it throws on a short key)
//   M17 interposerScript drops the newline-in-argument stop                             -> "an argument that holds a newline stops the call before anything runs or is logged" only
//   M18 interposerScript's recording path exits 0 whatever the tool returned            -> "a tool whose stdout is a printout has it recorded, and its exit code still survives" only
//   M19 parseToolLog ignores a line outside the format                                  -> "each way of being malformed is refused" only
//   M20 tctiRow drops the at-least-one-call requirement                                 -> "every recorded call used the ruled TCTI, and no call at all is not a pass" only
//   M21 sessionPrintoutRows looks for the printout from the start of the log, not after the session was started -> "a printout of some other session, or an earlier one, is not the unseal's" only
//   M22 sessionPrintoutRows takes any printout, not one on the unseal's session path   -> "a printout of some other session, or an earlier one, is not the unseal's" only
//   M23 saltedRow accepts any -c, not one a createprimary in the log wrote              -> "the session is salted to the primary: not unsalted, not a policy session, not salted to another key" only
//   M24 saltedRow drops the --hmac-session requirement                                  -> "the session is salted to the primary: not unsalted, not a policy session, not salted to another key" only
//   M25 scanRows drops the files-read control                                           -> "a scan that read nothing, or a log with no call, proves nothing" only
//   M26 (qualify-linux-support.ts) the deliver list drops real-ward-untouched           -> "each phase's list holds the (a29) and T26 rows it owes..." only
//   M27 (qualify-linux-support.ts) assertRunDirectory drops the .ward-component refusal -> "is refused even when the literal path would otherwise be right" only
