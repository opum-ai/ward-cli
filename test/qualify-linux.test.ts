// WCLI-21 slice 4a: the parts of the Linux T26 harness that need no TPM. The
// run itself (scripts/qualify-linux.ts) is measured on the hardware host, so
// everything it relies on that CAN be proved here, is: the directory guards
// that keep it on DEC-262 (a29)'s literal path and off /tmp, the handle
// comparison, the mode check, the state file, the secret scan and the verdict.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import {
  assertRunDirectory,
  bootIdChanged,
  containing,
  deriveKey,
  diffHandles,
  type HandleRead,
  type HandleSnapshot,
  handleLists,
  isInside,
  lastJsonLine,
  minimumNeedleBytes,
  modeProblems,
  type Phase,
  parseState,
  requiredChecks,
  runDirectoryName,
  secretNeedles,
  sha256,
  unreadHandles,
  verdict,
  volatileRoots,
  wideMode,
} from "../scripts/qualify-linux-support.ts";

const root = mkdtempSync(join(tmpdir(), "ward-qualify-linux-test-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let counter = 0;
// A real, resolved home under the test root. The volatile roots a guard call
// checks are passed explicitly (none by default), so the test root's own
// location under tmpdir() never decides a result.
const makeHome = (): string => {
  const dir = join(root, `home-${counter++}`);
  mkdirSync(dir);
  return realpathSync(dir);
};
const read = (stdout = "", exitCode = 0): HandleRead => ({ exitCode, stdout });
const snapshot = (over: Partial<HandleSnapshot> = {}): HandleSnapshot => ({
  "handles-transient": read(),
  "handles-persistent": read(),
  "handles-saved-session": read(),
  "handles-loaded-session": read(),
  ...over,
});
const digest = "a".repeat(64);
const bootA = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";
const nonceA =
  "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";
const stateOf = (over: Record<string, unknown> = {}) => ({
  nonce: nonceA,
  keyDigest: digest,
  handlesBefore: snapshot(),
  sealedAt: "2026-11-18T00:00:00Z",
  bootId: bootA,
  ...over,
});

describe("the run directory guard", () => {
  test("the literal path directly under the home directory is accepted", () => {
    const home = makeHome();
    expect(() =>
      assertRunDirectory(join(home, runDirectoryName), home, []),
    ).not.toThrow();
  });

  test("each way of naming the wrong place is refused", () => {
    const home = makeHome();
    const refused: [string, RegExp][] = [
      ["relative/path", /absolute/],
      [`${home}/../${runDirectoryName}`, /resolved form/],
      [`${home}/${runDirectoryName}/`, /resolved form/],
      [`/srv/${runDirectoryName}`, /directly under the real home/],
      [`${home}/${runDirectoryName}x`, /directly under the real home/],
      [`${home}/x${runDirectoryName}`, /directly under the real home/],
      [`${home}/sub/${runDirectoryName}`, /directly under the real home/],
      [`${home}/ward-qualify-linux-one`, /directly under the real home/],
      [`${home}/.ward`, /directly under the real home/],
      [`${home}/.ward/${runDirectoryName}`, /directly under the real home/],
      [home, /directly under the real home/],
    ];
    for (const [directory, message] of refused)
      expect(() => assertRunDirectory(directory, home, [])).toThrow(message);
  });

  test("the volatile roots are the four a reboot clears, plus the tmpdir", () => {
    expect([...volatileRoots].sort()).toEqual([
      "/dev/shm",
      "/run",
      "/tmp",
      "/var/tmp",
    ]);
  });

  test("a home under any volatile root is refused, as written and by its real path", () => {
    for (const label of ["tmp", "var-tmp", "shm", "run", "dotdot"]) {
      const volatile = join(root, `vol-${label}`);
      mkdirSync(volatile);
      const dir =
        label === "dotdot" ? join(volatile, "..x") : join(volatile, "h");
      mkdirSync(dir);
      const home = realpathSync(dir);
      expect(() =>
        assertRunDirectory(join(home, runDirectoryName), home, [volatile]),
      ).toThrow(/must not sit under/);
    }
  });

  test("a volatile root that is itself a symlink still catches a home under its target", () => {
    const real = join(root, "vol-real");
    mkdirSync(join(real, "h"), { recursive: true });
    const link = join(root, "vol-link");
    symlinkSync(real, link);
    const home = realpathSync(join(real, "h"));
    expect(() =>
      assertRunDirectory(join(home, runDirectoryName), home, [link]),
    ).toThrow(/must not sit under/);
    // A volatile root that does not exist on this host is skipped, not an error.
    expect(() =>
      assertRunDirectory(join(home, runDirectoryName), home, [
        join(root, "absent-root"),
      ]),
    ).not.toThrow();
    // A volatile root that cannot be resolved for another reason is refused.
    const loopA = join(root, "vol-loop-a");
    const loopB = join(root, "vol-loop-b");
    symlinkSync(loopB, loopA);
    symlinkSync(loopA, loopB);
    expect(() =>
      assertRunDirectory(join(home, runDirectoryName), home, [loopA]),
    ).toThrow(/ELOOP/);
  });

  test("the default guard refuses a home under the tmpdir", () => {
    const home = makeHome();
    expect(() =>
      assertRunDirectory(join(home, runDirectoryName), home),
    ).toThrow(/must not sit under/);
  });

  test("a symlinked run directory, a non-directory, and a symlinked home are refused", () => {
    const realHome = makeHome();
    const target = join(root, "elsewhere");
    mkdirSync(target);
    symlinkSync(target, join(realHome, runDirectoryName));
    expect(() =>
      assertRunDirectory(join(realHome, runDirectoryName), realHome, []),
    ).toThrow(/symlink/);

    const fileHome = makeHome();
    writeFileSync(join(fileHome, runDirectoryName), "x");
    expect(() =>
      assertRunDirectory(join(fileHome, runDirectoryName), fileHome, []),
    ).toThrow(/not a directory/);

    const linkedHome = join(root, "linked-home");
    symlinkSync(realHome, linkedHome);
    expect(() =>
      assertRunDirectory(join(linkedHome, runDirectoryName), linkedHome, []),
    ).toThrow(/directly under the real home/);
  });

  test("a home that does not resolve (missing, dangling, looping) is refused, not read lexically", () => {
    const missing = join(root, "no-such-home");
    const dangling = join(root, "dangling-home");
    symlinkSync(join(root, "nowhere"), dangling);
    const loopA = join(root, "loop-a");
    const loopB = join(root, "loop-b");
    symlinkSync(loopB, loopA);
    symlinkSync(loopA, loopB);
    for (const home of [missing, dangling, loopA])
      expect(() =>
        assertRunDirectory(join(home, runDirectoryName), home, []),
      ).toThrow(/home directory cannot be resolved/);
  });
});

describe("a home with a .ward component", () => {
  test("is refused even when the literal path would otherwise be right", () => {
    const outer = makeHome();
    const ward = join(outer, ".ward");
    mkdirSync(ward);
    const home = realpathSync(ward);
    expect(() =>
      assertRunDirectory(join(home, runDirectoryName), home, []),
    ).toThrow(/\.ward component/);
    const nested = join(ward, "deeper");
    mkdirSync(nested);
    const deeper = realpathSync(nested);
    expect(() =>
      assertRunDirectory(join(deeper, runDirectoryName), deeper, []),
    ).toThrow(/\.ward component/);
    // A name that merely contains the text is not a component of that name.
    const other = join(outer, "my.ward");
    mkdirSync(other);
    const fine = realpathSync(other);
    expect(() =>
      assertRunDirectory(join(fine, runDirectoryName), fine, []),
    ).not.toThrow();
  });
});

describe("the containment test is on path segments", () => {
  test("a name that begins with two dots is inside its parent, and a real parent is not", () => {
    expect(isInside("/tmp", "/tmp/..x/y")).toBe(true);
    expect(isInside("/home/u/.ward", "/home/u/.ward/..x/y")).toBe(true);
    expect(isInside("/tmp", "/tmp")).toBe(true);
    expect(isInside("/tmp", "/tmpx/y")).toBe(false);
    expect(isInside("/tmp/a", "/tmp/b")).toBe(false);
    expect(isInside("/tmp/a", "/tmp")).toBe(false);
    expect(isInside("/tmp/a/", "/tmp/a/b")).toBe(true);
  });
});

describe("the handle comparison", () => {
  test("identical lists show no movement, and each list that moved is named", () => {
    expect(diffHandles(snapshot(), snapshot())).toEqual([]);
    expect(
      diffHandles(
        snapshot(),
        snapshot({ "handles-saved-session": read("- 0x2000000\n") }),
      ),
    ).toEqual(["handles-saved-session"]);
    for (const list of handleLists)
      expect(
        diffHandles(snapshot(), snapshot({ [list]: read("- 0x1\n") })),
      ).toEqual([list]);
  });

  test("a list that was not read, on either side, is refused rather than compared", () => {
    for (const list of handleLists) {
      const failed = snapshot({ [list]: read("", 1) });
      expect(unreadHandles(failed)).toEqual([list]);
      expect(() => diffHandles(failed, snapshot())).toThrow(
        new RegExp(`before handle lists were not all read: ${list}`),
      );
      expect(() => diffHandles(snapshot(), failed)).toThrow(
        new RegExp(`after handle lists were not all read: ${list}`),
      );
      // Both unread: still refused, never "equal".
      expect(() => diffHandles(failed, failed)).toThrow(/not all read/);
    }
    const missing = {
      ...snapshot(),
      "handles-persistent": undefined,
    } as unknown as HandleSnapshot;
    expect(() => diffHandles(missing, missing)).toThrow(/handles-persistent/);
  });
});

describe("the synthetic key and the run state", () => {
  test("the key is 32 bytes, derived from the nonce, and different per nonce", () => {
    const a = deriveKey("aaaa");
    expect(a.length).toBe(32);
    expect(sha256(a)).toBe(sha256(deriveKey("aaaa")));
    expect(sha256(a)).not.toBe(sha256(deriveKey("bbbb")));
  });

  test("a state file round-trips, and each missing field is refused", () => {
    const good = stateOf();
    expect(parseState(JSON.stringify(good))).toEqual(good);
    for (const key of Object.keys(good))
      expect(() =>
        parseState(JSON.stringify({ ...good, [key]: undefined })),
      ).toThrow(/malformed/);
    expect(() =>
      parseState(
        JSON.stringify({
          ...good,
          handlesBefore: { "handles-transient": read() },
        }),
      ),
    ).toThrow(/malformed/);
    expect(() =>
      parseState(
        JSON.stringify({
          ...good,
          handlesBefore: { ...snapshot(), "handles-transient": "" },
        }),
      ),
    ).toThrow(/malformed/);
  });

  test("a nonce that is not 64 lowercase hex characters and a key digest that is not are refused", () => {
    for (const bad of [
      { nonce: "" },
      { nonce: "n" },
      { nonce: nonceA.slice(1) },
      { nonce: `${nonceA}0` },
      { nonce: nonceA.toUpperCase() },
      { nonce: `${nonceA.slice(1)}g` },
      { keyDigest: "d" },
      { keyDigest: "A".repeat(64) },
      { keyDigest: "a".repeat(63) },
      { keyDigest: `${digest}0` },
    ])
      expect(() => parseState(JSON.stringify(stateOf(bad)))).toThrow(
        /malformed/,
      );
  });

  test("a boot id that is not a lowercase UUID is refused, whatever else it looks like", () => {
    for (const bootId of [
      "",
      "b",
      "unknown",
      bootA.toUpperCase(),
      bootA.replaceAll("-", ""),
      `${bootA}\n`,
      ` ${bootA}`,
      `${bootA}0`,
      bootA.replace("a", "g"),
    ])
      expect(() => parseState(JSON.stringify(stateOf({ bootId })))).toThrow(
        /malformed/,
      );
    expect(parseState(JSON.stringify(stateOf({ bootId: bootA }))).bootId).toBe(
      bootA,
    );
  });

  test("the boot after the reboot is compared only when both ids are valid UUIDs", () => {
    const bootB = "ffeeddcc-bbaa-4998-8776-655443322110";
    expect(bootIdChanged(bootA, bootB)).toBe(true);
    expect(bootIdChanged(bootA, bootA)).toBe(false);
    for (const bad of [
      "",
      "unknown",
      "cat: /proc/sys/kernel/random/boot_id: No such file or directory",
      bootB.toUpperCase(),
      `${bootB}\n`,
      ` ${bootB}`,
      bootB.slice(1),
    ]) {
      expect(() => bootIdChanged(bootA, bad)).toThrow(/current boot id/);
      expect(() => bootIdChanged(bad, bootB)).toThrow(/sealed boot id/);
      expect(() => bootIdChanged(bad, bad)).toThrow(/boot id is not/);
    }
    expect(() => bootIdChanged(bootA, undefined as unknown as string)).toThrow(
      /current boot id/,
    );
  });

  test("a corrupt state file is malformed without quoting any of its text", () => {
    for (const text of [
      `{"nonce":"${nonceA}","keyDigest":`,
      `{"nonce":"${nonceA}" "x"}`,
      `${nonceA}`,
      "",
      "null",
      "[]",
      '"text"',
      "7",
    ]) {
      let message = "";
      try {
        parseState(text);
      } catch (error) {
        message = (error as Error).message;
        expect((error as Error).cause).toBeUndefined();
      }
      expect(message).toBe("the run state is malformed");
    }
  });

  test("a seal time that is not an ISO 8601 UTC timestamp is refused", () => {
    for (const sealedAt of [
      "",
      "t",
      "yesterday",
      "2026-11-18",
      "2026-11-18T00:00:00",
      "2026-11-18T00:00:00+01:00",
      "2026-13-45T99:99:99Z",
      "2026-02-30T00:00:00Z",
      "2026-04-31T00:00:00Z",
      "2026-11-18T24:00:01Z",
      "2026-11-18 00:00:00Z",
    ])
      expect(() => parseState(JSON.stringify(stateOf({ sealedAt })))).toThrow(
        /malformed/,
      );
    for (const sealedAt of [
      "2026-11-18T00:00:00Z",
      "2026-11-18T00:00:00.123Z",
      "2024-02-29T12:30:45Z",
    ])
      expect(parseState(JSON.stringify(stateOf({ sealedAt }))).sealedAt).toBe(
        sealedAt,
      );
  });

  test("a nonce that is not 64 lowercase hex characters gives no needles", () => {
    for (const bad of ["", "a-nonce", nonceA.slice(1), nonceA.toUpperCase()])
      expect(() => secretNeedles(bad)).toThrow(/64 lowercase hex/);
  });

  test("the scan looks for the key, the nonce and the nonce's decoded bytes", () => {
    const needles = secretNeedles(nonceA);
    expect(needles.length).toBe(3);
    expect(
      Buffer.from(needles[0] as Uint8Array).equals(deriveKey(nonceA)),
    ).toBe(true);
    expect(Buffer.from(needles[1] as Uint8Array).toString()).toBe(nonceA);
    expect(Buffer.from(needles[2] as Uint8Array).toString("hex")).toBe(nonceA);
  });
});

describe("the mode check", () => {
  const uid = process.getuid?.() ?? 0;
  const privateTree = (name: string): string => {
    const tree = join(root, name);
    mkdirSync(tree, { mode: 0o700 });
    chmodSync(tree, 0o700);
    return tree;
  };

  test("a private tree has no problems, and each wider mode, and a symlink, is named", () => {
    const tree = privateTree("tree");
    writeFileSync(join(tree, "ok"), "x", { mode: 0o600 });
    expect(modeProblems(tree)).toEqual([]);
    const wide = join(tree, "wide");
    writeFileSync(wide, "x");
    chmodSync(wide, 0o660);
    expect(modeProblems(tree)).toEqual(["wide: 660"]);
    symlinkSync(join(tree, "ok"), join(tree, "link"));
    expect(modeProblems(tree).sort()).toEqual(["link: symlink", "wide: 660"]);
  });

  test("setuid, setgid and sticky bits are named, not masked off", () => {
    // Set on the mode itself: some filesystems drop them on chmod (measured on
    // darwin /tmp), so the tree cannot carry them.
    expect(wideMode(0o100600, false)).toBeUndefined();
    expect(wideMode(0o40700, true)).toBeUndefined();
    expect(wideMode(0o104600, false)).toBe("4600");
    expect(wideMode(0o42700, true)).toBe("2700");
    expect(wideMode(0o41700, true)).toBe("1700");
    expect(wideMode(0o100660, false)).toBe("660");
    expect(wideMode(0o40755, true)).toBe("755");
    expect(wideMode(0o100700, false)).toBe("700");
  });

  test("a file with a second hard link is named", () => {
    const tree = privateTree("linked");
    writeFileSync(join(tree, "a"), "x", { mode: 0o600 });
    expect(modeProblems(tree)).toEqual([]);
    linkSync(join(tree, "a"), join(root, "hard-outside"));
    expect(modeProblems(tree)).toEqual(["a: 2 links"]);
  });

  test("a file owned by someone else is named, and a symlinked root names itself", () => {
    const tree = privateTree("owned");
    writeFileSync(join(tree, "f"), "x", { mode: 0o600 });
    expect(modeProblems(tree, uid)).toEqual([]);
    expect(modeProblems(tree, uid + 1).sort()).toEqual([
      `.: owner ${uid}`,
      `f: owner ${uid}`,
    ]);
    const link = join(root, "root-link");
    symlinkSync(tree, link);
    expect(modeProblems(link)).toEqual([".: symlink"]);
  });

  test("a host that gives no uid refuses the check instead of skipping the owner test", () => {
    const tree = privateTree("no-uid");
    const proc = process as { getuid?: () => number };
    const saved = proc.getuid;
    try {
      proc.getuid = undefined;
      expect(() => modeProblems(tree)).toThrow(/needs a uid/);
      expect(modeProblems(tree, uid)).toEqual([]);
    } finally {
      proc.getuid = saved;
    }
  });
});

describe("the scan for a secret", () => {
  const enc = (text: string): Uint8Array => new TextEncoder().encode(text);
  // Bytes whose base64 holds "+" and "/" so the url-safe form differs.
  const odd = Uint8Array.from([
    0xfb, 0xff, 0xfe, 0xfa, 0xf0, 0x3e, 0x3f, 0xbf, 0xef, 0xfb, 0x41, 0x42,
  ]);
  const scanTree = (name: string, files: Record<string, string | Buffer>) => {
    const tree = join(root, name);
    mkdirSync(tree);
    for (const [file, content] of Object.entries(files))
      writeFileSync(join(tree, file), content);
    return tree;
  };

  test("a value is found as is, in base64 and in hex, and a clean tree has none", () => {
    const tree = scanTree("scan", {
      plain: "xx synthetic-value yy",
      b64: Buffer.from("synthetic-value").toString("base64"),
      hex: Buffer.from("synthetic-value").toString("hex"),
      clean: "nothing here",
    });
    const found = containing(tree, [enc("synthetic-value")]);
    expect(found.matches.sort()).toEqual(["b64", "hex", "plain"]);
    expect(found.filesRead).toBe(4);
    const absent = containing(tree, [enc("absent-value")]);
    expect(absent.matches).toEqual([]);
    expect(absent.filesRead).toBe(4);
  });

  test("raw key bytes are found, and several needles are all searched", () => {
    const key = deriveKey(nonceA);
    const tree = scanTree("scan-raw", {
      raw: Buffer.concat([Buffer.from("pre"), key]),
      nonce: nonceA,
      decoded: Buffer.concat([Buffer.from("pre"), Buffer.from(nonceA, "hex")]),
      clean: "nothing",
    });
    expect(containing(tree, secretNeedles(nonceA)).matches.sort()).toEqual([
      "decoded",
      "nonce",
      "raw",
    ]);
  });

  test("base64 is found inside a longer stream at each of the three alignments", () => {
    const key = deriveKey("alignment");
    const files: Record<string, string> = {};
    for (const shift of [0, 1, 2])
      for (const tail of [0, 1, 2])
        files[`s${shift}t${tail}`] = Buffer.concat([
          Buffer.alloc(shift, 0x61),
          key,
          Buffer.alloc(tail, 0x7a),
        ]).toString("base64");
    const tree = scanTree("scan-align", { ...files, clean: "AAAA".repeat(30) });
    expect(containing(tree, [key]).matches.sort()).toEqual(
      Object.keys(files).sort(),
    );
  });

  test("base64url, uppercase hex and padded base64 are found, and a near miss is not", () => {
    const url = Buffer.from(odd)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    expect(Buffer.from(odd).toString("base64")).toMatch(/[+/]/);
    const tree = scanTree("scan-forms", {
      url: `x${url}`,
      upper: Buffer.from(odd).toString("hex").toUpperCase(),
      padded: Buffer.from(odd.slice(0, 11)).toString("base64"),
      near: Buffer.from(
        odd.slice(0, 11).map((byte, at) => (at === 5 ? byte ^ 1 : byte)),
      ).toString("base64"),
      clean: "nothing",
    });
    expect(containing(tree, [odd]).matches.sort()).toEqual(["upper", "url"]);
    const prefix = containing(tree, [odd.slice(0, 11)]).matches;
    expect(prefix).toContain("padded");
    expect(prefix).not.toContain("near");
    expect(prefix).not.toContain("clean");
  });

  test("an empty tree reads zero files, so a caller's positive control fails it", () => {
    const tree = scanTree("scan-empty", {});
    const scanned = containing(tree, [enc("needle-xx")]);
    expect(scanned.filesRead).toBe(0);
    expect(scanned.matches).toEqual([]);
  });

  test("a scan with no needle, or one shorter than the minimum, is refused rather than matching everything", () => {
    const tree = scanTree("scan-needles", { a: "abc" });
    expect(() => containing(tree, [])).toThrow(/at least one needle/);
    expect(() => containing(tree, [new Uint8Array(0)])).toThrow(
      /at least 8 bytes/,
    );
    expect(() =>
      containing(tree, [new Uint8Array(minimumNeedleBytes - 1)]),
    ).toThrow(/at least 8 bytes/);
    expect(() =>
      containing(tree, [new Uint8Array(minimumNeedleBytes).fill(7)]),
    ).not.toThrow();
  });

  // The fixtures below are the output of the real printers, not typed by hand:
  // Bun.inspect and util.inspect differ (util.inspect pads each entry to a
  // common width and wraps the array over lines, measured on Bun 1.3.14), and od
  // is run as a child.
  test("a byte array printed as decimals, and hex printed with a separator, are found", () => {
    // deriveKey hands back a Buffer, which inspects as hex: the Uint8Array copy
    // is what prints as a decimal list.
    const key = Uint8Array.from(deriveKey("printed"));
    const decimals = [...key];
    const pairs = Buffer.from(key).toString("hex").match(/../g) as string[];
    // Entries of one, two and three digits, so util.inspect actually pads.
    expect(new Set(decimals.map((d) => String(d).length)).size).toBeGreaterThan(
      1,
    );
    const od = Bun.spawnSync(["od", "-An", "-tx1", "-v"], {
      stdin: Buffer.from(key),
    });
    expect(od.exitCode).toBe(0);
    const tree = scanTree("scan-printed", {
      json: JSON.stringify(Buffer.from(key)),
      bunInspect: Bun.inspect(key),
      utilInspect: inspect(key),
      bufferInspect: inspect(Buffer.from(key)),
      od: od.stdout.toString(),
      xxdPerByte: `${pairs.join("\n")}\n`,
      spaced: decimals.join(" "),
      colon: pairs.join(":").toUpperCase(),
      dash: pairs.join("-"),
      clean: decimals.slice(0, 31).join(", "),
    });
    expect(inspect(key)).toContain("\n");
    expect(od.stdout.toString()).toContain("\n");
    expect(containing(tree, [key]).matches.sort()).toEqual([
      "bufferInspect",
      "bunInspect",
      "colon",
      "dash",
      "json",
      "od",
      "spaced",
      "utilInspect",
      "xxdPerByte",
    ]);
  });

  test("a FIFO under the tree is refused, not skipped or read", () => {
    const tree = scanTree("scan-fifo", { a: "abc" });
    const made = Bun.spawnSync(["mkfifo", join(tree, "pipe")]);
    expect(made.exitCode).toBe(0);
    expect(() => containing(tree, [enc("needle-xx")])).toThrow(
      /cannot read pipe/,
    );
  });

  test("a socket under the tree is refused, not skipped", async () => {
    // A unix socket path is short-limited, so this one lives under /tmp.
    const dir = mkdtempSync("/tmp/wq-");
    const server = createServer();
    try {
      await new Promise<void>((resolve) =>
        server.listen(join(dir, "s"), resolve),
      );
      expect(() => containing(dir, [enc("needle-xx")])).toThrow(
        /cannot read s: it is not a file/,
      );
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a symlinked directory is not followed, so a file outside the tree is not scanned", () => {
    const outside = scanTree("scan-outside", { secret: "outside-needle-here" });
    const tree = scanTree("scan-link", { inside: "nothing" });
    symlinkSync(outside, join(tree, "link"));
    symlinkSync(join(outside, "secret"), join(tree, "filelink"));
    const scanned = containing(tree, [enc("outside-needle")]);
    expect(scanned.matches).toEqual([]);
    expect(scanned.filesRead).toBe(1);
  });
});

describe("the verdict and the output line", () => {
  const phases = Object.keys(requiredChecks) as Phase[];
  const allOf = (phase: Phase) =>
    requiredChecks[phase].map((name) => ({ name, ok: true }));

  test("PASSED needs every check its phase requires, all ok, and no other failure", () => {
    for (const phase of phases) {
      expect(verdict(phase, allOf(phase))).toBe("PASSED");
      expect(verdict(phase, [])).toBe("FAILED");
      expect(verdict(phase, allOf(phase), ["error"])).toBe("FAILED");
      expect(
        verdict(phase, [...allOf(phase), { name: "extra", ok: false }]),
      ).toBe("FAILED");
    }
  });

  test("a required check that is missing, or failed, or failed once of two, is FAILED", () => {
    for (const phase of phases)
      for (const name of requiredChecks[phase]) {
        const checks = allOf(phase);
        expect(
          verdict(
            phase,
            checks.filter((c) => c.name !== name),
          ),
        ).toBe("FAILED");
        expect(
          verdict(
            phase,
            checks.map((c) => (c.name === name ? { ...c, ok: false } : c)),
          ),
        ).toBe("FAILED");
        expect(verdict(phase, [...checks, { name, ok: false }])).toBe("FAILED");
      }
  });

  test("ok must be true itself: a string or a number is not a pass, required or not", () => {
    const checks = allOf("seal");
    for (const ok of [
      "false",
      "true",
      1,
      "",
      null,
      {},
    ] as unknown as boolean[]) {
      expect(verdict("seal", [...checks, { name: "extra", ok }])).toBe(
        "FAILED",
      );
      expect(
        verdict(
          "seal",
          checks.map((c, i) => (i === 0 ? { ...c, ok } : c)),
        ),
      ).toBe("FAILED");
    }
  });

  test("a phase that is not one of the five is FAILED, never PASSED or a throw", () => {
    for (const phase of [
      "nonsense",
      "constructor",
      "hasOwnProperty",
      "__proto__",
      "toString",
      "",
    ])
      expect(verdict(phase as Phase, allOf("seal"))).toBe("FAILED");
  });

  test("the unseal phase after the reboot requires the boot-id proof, and the seal phase does not", () => {
    expect(requiredChecks.unseal).toContain("boot-id-differs-from-seal");
    expect(requiredChecks.seal).not.toContain("boot-id-differs-from-seal");
    const withoutBoot = allOf("unseal").filter(
      (c) => c.name !== "boot-id-differs-from-seal",
    );
    expect(verdict("unseal", withoutBoot)).toBe("FAILED");
    expect(verdict("seal", allOf("seal"))).toBe("PASSED");
  });

  test("each phase's list holds the (a29) and T26 rows it owes, and the unseal phase holds all of the seal phase's", () => {
    const owed: Record<Phase, string[]> = {
      // P0 owes only what its four commands can produce (DEC-262 a33).
      facts: [
        "effective-groups-recorded",
        "tpm-device-present",
        "tpm2-tools-present",
        "python3-recorded",
      ],
      deliver: [
        "run-directory-is-ruled-literal-path",
        "binaries-sha256-match-both-ends",
        "real-ward-metadata-unchanged",
      ],
      seal: [
        "run-directory-is-ruled-literal-path",
        "tcti-is-device-tpmrm0",
        "synthetic-key-only",
        "no-persistent-handles",
        "handle-lists-unchanged",
        "real-ward-metadata-unchanged",
        "effective-groups-recorded",
        "session-printout-decrypt-encrypt",
        "session-printout-is-the-unseal-session",
        "session-salted-to-primary",
        "key-not-in-store-or-tool-log",
        "secret-scan-clean",
      ],
      unseal: ["handle-lists-unchanged", "unseal-matches-sealed"],
      clean: [
        "run-directory-is-ruled-literal-path",
        "run-directory-removed",
        "tcti-is-device-tpmrm0",
        "handle-lists-unchanged",
        "real-ward-metadata-unchanged",
      ],
    };
    for (const phase of phases)
      for (const name of owed[phase])
        expect(requiredChecks[phase]).toContain(name);
    for (const name of requiredChecks.seal)
      expect(requiredChecks.unseal).toContain(name);
    for (const phase of phases)
      expect(new Set(requiredChecks[phase]).size).toBe(
        requiredChecks[phase].length,
      );
  });

  test("no check name claims the wire was measured (a29 Q1)", () => {
    for (const phase of phases)
      for (const name of requiredChecks[phase])
        expect(name).not.toMatch(/wire|on-the-wire|bus-encrypt|measured/i);
  });

  test("the last JSON line is read, and anything else is an empty object", () => {
    expect(lastJsonLine('noise\n{"a":1}\n{"kind":"x"}\n')).toEqual({
      kind: "x",
    });
    expect(lastJsonLine("no json")).toEqual({});
    expect(lastJsonLine("{broken")).toEqual({});
  });
});

// MUTANT REGISTER, WCLI-21 slice 4a-1 (the harness's pure parts), written BEFORE any run. Bun 1.3.14 on each observation. Each mutant is applied to scripts/qualify-linux-support.ts.
//   U1  assertRunDirectory stops refusing a volatile directory (/tmp and the like)   -> "each way of naming the wrong place is refused"
//   U2  assertRunDirectory stops refusing a path under the real ~/.ward                -> "each way of naming the wrong place is refused", "the real home's store is a refusal..."
//   U3  diffHandles stops comparing the loaded-session list                            -> "identical lists show no movement, and each list that moved is named"
//   U4  modeProblems ignores group bits                                                -> "a private tree has no problems, and each wider mode, and a symlink, is named"
//   U5  verdict reads an empty run as PASSED                                           -> "PASSED needs checks, all ok, and no other failure..."
//   U6  containing stops looking for the hex form                                      -> "a value is found as is, in base64 and in hex..."
//   U7  deriveKey ignores the nonce                                                    -> "the key is 32 bytes, derived from the nonce..."
//   U8  parseState stops requiring bootId                                              -> "a state file round-trips, and each missing field is refused"
// OBSERVED (slice 4a-1, bun 1.3.14, 2026-11-18; predictions above unchanged). U1-U8 each went red on exactly their predicted test(s); U2 also reddened the real-home test, as predicted.

// MUTANT REGISTER, WCLI-21 slice 4a-1 round 2 (the #358 fix round, B1-B5 and N1-N4), written BEFORE any run of it. Bun 1.3.14 on each observation. Each mutant is applied to scripts/qualify-linux-support.ts as fixed in this round. U1-U8 above were measured on 982c040 and are not re-run: U1/U3/U4/U6/U7/U8 sites changed shape or test names and are replaced by R-numbers below; U2's site (the ~/.ward refusal) is removed because the exact-path rule makes it unreachable, so there is no mutant to register for it; U5 is replaced by R7/R8.
//   R1  isInside tests rel.startsWith("..") as a string again                        -> "the containment test is on path segments", "a home that sits on a volatile path refuses, each of them" (the /tmp/..x home); no other test
//   R2  assertRunDirectory checks basename === runDirectoryName instead of the exact path -> "each way of naming the wrong place is refused" (the /srv, sub/ and .ward/ cases); the real-home test stays green
//   R3  assertRunDirectory drops the lstat symlink and not-a-directory checks          -> "a symlinked run directory, a non-directory, and a symlinked home are refused"
//   R4  assertRunDirectory takes realHome = resolve(home) (no realpath)                -> "a symlinked run directory, a non-directory, and a symlinked home are refused" (the linked-home case reports another refusal); no other test
//   R5  diffHandles stops refusing unread lists (compares stdout only)                 -> "a list that was not read, on either side, is refused rather than compared"
//   R6  unreadHandles ignores a non-zero exitCode (shape check only)                   -> "a list that was not read, on either side, is refused rather than compared"
//   R7  verdict stops checking the required names (non-empty checks, all ok)           -> "a required check that is missing, or failed, or failed once of two, is FAILED", "a verdict that requires nothing proves nothing"
//   R8  verdict drops the required.length > 0 clause                                   -> "a verdict that requires nothing proves nothing" only
//   R9  parseState accepts an empty nonce                                              -> "an empty nonce and a key digest that is not 64 hex characters are refused" only
//   R10 parseState drops the 64-hex test on keyDigest                                  -> "an empty nonce and a key digest that is not 64 hex characters are refused" only
//   R11 modeProblems stops comparing the owner uid                                     -> "a file owned by someone else is named, and a symlinked root names itself"
//   R12 modeProblems names a symlinked root "" instead of "."                          -> "a file owned by someone else is named, and a symlinked root names itself" only
//   R13 containing stops searching the raw bytes (hex and base64 only)                 -> "raw key bytes are found, and several needles are all searched" only
//   R14 containing returns filesRead 0 always                                          -> "a value is found as is, in base64 and in hex...", "an empty tree reads zero files..." is still green (0 is right there)
//   R15 secretNeedles drops the nonce                                                  -> "the scan looks for the key and for the nonce it is derived from", "raw key bytes are found, and several needles are all searched"
//   R16 the volatile list drops /run                                                   -> "a home that sits on a volatile path refuses, each of them" only
//   R17 diffHandles stops comparing the loaded-session list (the old U3)               -> "identical lists show no movement, and each list that moved is named"
// OBSERVED (round 2, bun 1.3.14, 2026-11-18; the predictions above are unchanged, the divergences are noted here). R1, R3-R6, R8-R12 and R14-R17 went red on exactly their predicted test(s). Divergences: R2 also reddened "a symlinked run directory, a non-directory, and a symlinked home are refused" (a name-only check accepts the symlinked-home case) and "the real home's store is never a target..." (the prediction that it stays green was wrong: a name-only check accepts ~/.ward/ward-t26-wcli21). R7 also reddened "PASSED needs every required check, all ok, and no other failure" (its missing-name case). R13 also reddened "a value is found as is, in base64 and in hex..." (the as-is form is the raw-bytes form). No mutant survived; the driver is a scratch script, not committed.

// MUTANT REGISTER, WCLI-21 slice 4a-1 round 3 (the #358 round-2 verdict: B1, N1, N2, N6, N7, N8, N9), written BEFORE any run of it. Bun 1.3.14 on each observation. Each mutant is applied to scripts/qualify-linux-support.ts as fixed in this round. Predictions name the red test(s); "only" means no other test goes red.
//   R18 parseState drops the boot-id UUID shape test                                  -> "a boot id that is not a lowercase UUID is refused..." only
//   R19 parseState drops the sealedAt ISO shape test (keeps the Date.parse test)      -> "a seal time that is not an ISO 8601 UTC timestamp is refused" only
//   R20 parseState drops the sealedAt Date.parse NaN test (keeps the shape test)      -> "a seal time that is not an ISO 8601 UTC timestamp is refused" only (the 2026-13-45T99:99:99Z case)
//   R21 requiredChecks.unseal drops "boot-id-differs-from-seal"                       -> "the unseal phase after the reboot requires the boot-id proof, and the seal phase does not" only
//   R22 verdict reads requiredChecks.seal for every phase                             -> "PASSED needs every check its phase requires...", "a required check that is missing, or failed, or failed once of two, is FAILED"
//   R23 verdict drops the required !== undefined guard                                -> "a phase that is not one of the five is FAILED, never PASSED" only (it throws)
//   R24 verdict reads check.ok truthily in the per-name map                           -> "ok must be true itself: a string or a number is not a pass, required or not" only
//   R25 verdict reads check.ok truthily in the checks.every clause                    -> "ok must be true itself: a string or a number is not a pass, required or not" only
//   R26 assertRunDirectory compares each volatile root as written only (no realpath)  -> "a volatile root that is itself a symlink still catches a home under its target" only
//   R27 realpathOrAbsent falls back to the lexical path on any error                  -> "a volatile root that is itself a symlink..." only (the loop root)
//   R28 assertRunDirectory falls back to resolve(home) when the home does not resolve -> "a home that does not resolve (missing, dangling, looping) is refused, not read lexically" only
//   R29 wideMode masks with 0o777 instead of 0o7777                                   -> "setuid, setgid and sticky bits are named, not masked off" only
//   R30 currentUid returns 0 instead of refusing when the host gives no uid           -> "a host that gives no uid refuses the check..." only
//   R31 the scan searches base64 at alignment 0 only                                  -> "base64 is found inside a longer stream at each of the three alignments" only
//   R32 the scan drops the uppercase hex form                                         -> "base64url, uppercase hex and padded base64 are found, and a near miss is not" only
//   R33 the scan drops the base64url form                                             -> "base64url, uppercase hex and padded base64 are found, and a near miss is not" only
//   R34 the scan keeps the "=" padding on base64 forms                                -> "base64 is found inside a longer stream at each of the three alignments" only
//   R35 containing drops the empty-needle refusal                                     -> "a scan with no needle, or an empty one, is refused rather than matching everything" only
//   R36 a check name claiming the wire was measured joins the seal and unseal lists   -> "no check name claims the wire was measured (a29 Q1)" only
//   R37 verdict drops the required.length > 0 clause                                  -> NONE: an equivalent mutant now, because every phase's list is a non-empty constant; registered so the survival is predicted, not discovered
//   R38 the volatile list drops /dev/shm                                              -> "the volatile roots are the four a reboot clears, plus the tmpdir" only
// OBSERVED (round 3, bun 1.3.14, 2026-11-18; the predictions above are unchanged, the divergences are noted here). R18-R21, R23, R25, R27-R36 and R38 went red on exactly their predicted test(s). Divergences: R22 also reddened "a phase that is not one of the five..." and "the unseal phase after the reboot requires the boot-id proof..." (the seal list is read for every phase, so both fail). R26 also reddened "a home under any volatile root is refused, as written and by its real path" and "the default guard refuses a home under the tmpdir" (on darwin the test homes' real path differs from the tmpdir written form, so every one of them depends on the real-path form). R24 SURVIVED, unpredicted: the per-name strictness it removes is also enforced by the checks.every clause and by the === true read of the map, so it was an equivalent mutant I did not see; the verdict body is simplified in the next commit so the redundancy is gone rather than tolerated, and R24 is withdrawn. R37 stayed green, as predicted (equivalent). R27's first attempt matched no pattern (the formatter had wrapped the line) and ran nothing; it was re-run with the corrected pattern and went red as predicted.
// OBSERVED (round 3, after the verdict body was simplified to a name set plus the strict checks.every clause): R21, R22, R23, R25, R36 went red on the same tests as before, and R37 stayed green (equivalent, as registered); R24 is withdrawn, its code no longer exists.

// MUTANT REGISTER, WCLI-21 slice 4a-1 round 4 (the #358 round-3 verdict: B1, N2, N4, N5, N6, N7, N8 and the cheap N9 items), written BEFORE any run of it. Bun 1.3.14 on each observation. Each mutant is applied to scripts/qualify-linux-support.ts as fixed in this round. "only" means no other test goes red.
//   R39 bootIdChanged skips the shape check on the current boot id                    -> "the boot after the reboot is compared only when both ids are valid UUIDs" only
//   R40 bootIdChanged skips the shape check on the sealed boot id                     -> "the boot after the reboot is compared only when both ids are valid UUIDs" only
//   R41 bootIdChanged returns true for two equal ids                                  -> "the boot after the reboot is compared only when both ids are valid UUIDs" only
//   R42 the nonce shape accepts any non-empty text                                    -> "a nonce that is not 64 lowercase hex characters and a key digest that is not are refused" only
//   R43 parseState runs JSON.parse without the wrapper                                -> "a corrupt state file is malformed without quoting any of its text" only
//   R44 the timestamp check drops the date round trip (Date.parse rolls 2026-02-30 over) -> "a seal time that is not an ISO 8601 UTC timestamp is refused" only
//   R45 verdict reads requiredChecks[phase] without Object.hasOwn                     -> "a phase that is not one of the five is FAILED, never PASSED or a throw" only
//   R46 the scan drops the decimal byte-list forms                                    -> "a byte array printed as decimals, and hex printed with a separator, are found" only
//   R47 the scan drops the separated-hex forms                                        -> "a byte array printed as decimals, and hex printed with a separator, are found" only
//   R48 the minimum needle length is 0                                                -> "a scan with no needle, or one shorter than the minimum, is refused rather than matching everything" only
//   R49 the walker stats symlinks and reads what they point at                        -> "a symlinked directory is not followed, so a file outside the tree is not scanned" only
//   R50 modeProblems drops the hard-link count check                                  -> "a file with a second hard link is named" only
// OBSERVED (round 4, bun 1.3.14, 2026-11-18; predictions above unchanged). R39-R50 each went red on exactly their one predicted test and no other; no mutant survived and no prediction diverged. Measured on the way, on Bun 1.3.14: Date.parse("2026-02-30T00:00:00Z") returns the March 2 instant instead of NaN, so the timestamp check needs its round trip (R44); readdirSync recursive lists the entries under a symlinked directory ("link", "link/f"), so the scan walks the tree itself and does not follow links (R49). During the work a near-miss fixture that flipped the last byte of an 11-byte needle still matched: its flipped bit sits in the dropped partial base64 character, so the fixture now flips a middle byte.

// MUTANT REGISTER, WCLI-21 slice 4a-2a module fixes (round-4 findings 1-4 of #358), written BEFORE any run of it. Bun 1.3.14 on each observation. Each mutant is applied to scripts/qualify-linux-support.ts. "only" means no other test goes red.
// Finding 1 is met by reading a whitespace run as one space (an od -An -tx1 listing and util.inspect's padded, wrapped array both match), not by adding newline separators; its mutant is R51.
//   R51 containing searches the raw bytes only, not the whitespace-collapsed copy      -> "a byte array printed as decimals, and hex printed with a separator, are found" only (the utilInspect, od and xxdPerByte fixtures)
//   R52 secretNeedles drops the nonce's decoded bytes                                  -> "the scan looks for the key, the nonce and the nonce's decoded bytes", "raw key bytes are found, and several needles are all searched"
//   R53 secretNeedles stops refusing a nonce that is not 64 lowercase hex              -> "a nonce that is not 64 lowercase hex characters gives no needles" only
//   R54 the walker skips a FIFO, a socket or a device in silence instead of throwing   -> "a FIFO under the tree is refused, not skipped or read", "a socket under the tree is refused, not skipped"
// NOT TESTABLE, said here rather than left implicit: the lstat fallback for a directory entry that names no kind (DT_UNKNOWN) cannot be produced on this host or in CI, so it has no test and no mutant; the fixtures are the output of the real printers (Bun.inspect, util.inspect, od run as a child), and "xxdPerByte" is built by hand in xxd -p -c1's documented one-pair-per-line shape because xxd is not installed everywhere.
// OBSERVED (slice 4a-2a module fixes, bun 1.3.14, 2026-11-18; predictions above unchanged). R51-R54 each went red on exactly their predicted test(s); no mutant survived and no prediction diverged. Measured first: Bun.inspect prints a Uint8Array on one line with single spaces, util.inspect pads each entry to a common width and wraps it over lines, and a Buffer inspects as "<Buffer 7b 1c ...>"; the whitespace-collapsing search matches all three. FINDING 7: the U2 register line (two registers up) names a mutant on the ~/.ward refusal that round 1 removed, and the R2 line names "the real-home test", which round 3 deleted; neither mutant exists on the landed module, so those two lines describe code that is gone, and R2's guard is now proved by "each way of naming the wrong place is refused" alone.
