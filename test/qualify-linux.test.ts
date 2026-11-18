// WCLI-21 slice 4a: the parts of the Linux T26 harness that need no TPM. The
// run itself (scripts/qualify-linux.ts) is measured on the hardware host, so
// everything it relies on that CAN be proved here, is: the directory guards
// that keep it on DEC-262 (a29)'s literal path and off /tmp and the real
// ~/.ward, the handle comparison, the mode check, the state file and the
// verdict.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertRunDirectory,
  containing,
  deriveKey,
  diffHandles,
  type HandleRead,
  type HandleSnapshot,
  handleLists,
  isInside,
  lastJsonLine,
  modeProblems,
  parseState,
  requiredChecks,
  runDirectoryName,
  secretNeedles,
  sha256,
  unreadHandles,
  verdict,
} from "../scripts/qualify-linux-support.ts";

const root = mkdtempSync(join(tmpdir(), "ward-qualify-linux-test-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));
const home = "/home/synthetic";
const read = (stdout = "", exitCode = 0): HandleRead => ({ exitCode, stdout });
const snapshot = (over: Partial<HandleSnapshot> = {}): HandleSnapshot => ({
  "handles-transient": read(),
  "handles-persistent": read(),
  "handles-saved-session": read(),
  "handles-loaded-session": read(),
  ...over,
});
const digest = "a".repeat(64);

describe("the run directory guard", () => {
  test("the literal path directly under the home directory is accepted", () => {
    expect(() =>
      assertRunDirectory(`${home}/${runDirectoryName}`, home),
    ).not.toThrow();
  });

  test("each way of naming the wrong place is refused", () => {
    const refused: [string, RegExp][] = [
      ["relative/path", /absolute/],
      [`${home}/../synthetic/${runDirectoryName}`, /resolved form/],
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
      expect(() => assertRunDirectory(directory, home)).toThrow(message);
  });

  test("a home that sits on a volatile path refuses, each of them", () => {
    for (const volatile of [
      "/tmp/h",
      "/var/tmp/h",
      "/dev/shm/h",
      "/run/h",
      `${tmpdir()}/h`,
      "/tmp/..x",
    ])
      expect(() =>
        assertRunDirectory(`${volatile}/${runDirectoryName}`, volatile),
      ).toThrow(/must not sit under/);
  });

  test("the real home's store is never a target, and the real home accepts only its own literal path", () => {
    expect(() =>
      assertRunDirectory(join(homedir(), ".ward", runDirectoryName), homedir()),
    ).toThrow();
    expect(() =>
      assertRunDirectory(
        join(realpathSync(homedir()), runDirectoryName),
        homedir(),
      ),
    ).not.toThrow();
  });

  test("a symlinked run directory, a non-directory, and a symlinked home are refused", () => {
    const realHome = realpathSync(mkdtempSync(join(root, "home-")));
    const target = join(root, "elsewhere");
    mkdirSync(target);
    symlinkSync(target, join(realHome, runDirectoryName));
    expect(() =>
      assertRunDirectory(join(realHome, runDirectoryName), realHome),
    ).toThrow(/symlink/);

    const fileHome = realpathSync(mkdtempSync(join(root, "home-")));
    writeFileSync(join(fileHome, runDirectoryName), "x");
    expect(() =>
      assertRunDirectory(join(fileHome, runDirectoryName), fileHome),
    ).toThrow(/not a directory/);

    const linkedHome = join(root, "linked-home");
    symlinkSync(realHome, linkedHome);
    expect(() =>
      assertRunDirectory(join(linkedHome, runDirectoryName), linkedHome),
    ).toThrow(/directly under the real home/);
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
    const good = {
      nonce: "n",
      keyDigest: digest,
      handlesBefore: snapshot(),
      sealedAt: "2026-11-18T00:00:00Z",
      bootId: "b",
    };
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

  test("an empty nonce and a key digest that is not 64 hex characters are refused", () => {
    const good = {
      nonce: "n",
      keyDigest: digest,
      handlesBefore: snapshot(),
      sealedAt: "t",
      bootId: "b",
    };
    for (const bad of [
      { nonce: "" },
      { keyDigest: "d" },
      { keyDigest: "A".repeat(64) },
      { keyDigest: "a".repeat(63) },
      { keyDigest: `${digest}0` },
    ])
      expect(() => parseState(JSON.stringify({ ...good, ...bad }))).toThrow(
        /malformed/,
      );
  });

  test("the scan looks for the key and for the nonce it is derived from", () => {
    const needles = secretNeedles("a-nonce");
    expect(needles.length).toBe(2);
    expect(
      Buffer.from(needles[0] as Uint8Array).equals(deriveKey("a-nonce")),
    ).toBe(true);
    expect(Buffer.from(needles[1] as Uint8Array).toString()).toBe("a-nonce");
  });
});

describe("the mode check", () => {
  test("a private tree has no problems, and each wider mode, and a symlink, is named", () => {
    const tree = join(root, "tree");
    mkdirSync(tree, { mode: 0o700 });
    chmodSync(tree, 0o700);
    writeFileSync(join(tree, "ok"), "x", { mode: 0o600 });
    expect(modeProblems(tree)).toEqual([]);
    const wide = join(tree, "wide");
    writeFileSync(wide, "x");
    chmodSync(wide, 0o660);
    expect(modeProblems(tree)).toEqual(["wide: 660"]);
    symlinkSync(join(tree, "ok"), join(tree, "link"));
    expect(modeProblems(tree).sort()).toEqual(["link: symlink", "wide: 660"]);
  });

  test("a file owned by someone else is named, and a symlinked root names itself", () => {
    const tree = join(root, "owned");
    mkdirSync(tree, { mode: 0o700 });
    chmodSync(tree, 0o700);
    writeFileSync(join(tree, "f"), "x", { mode: 0o600 });
    const uid = process.getuid?.() ?? 0;
    expect(modeProblems(tree, uid)).toEqual([]);
    expect(modeProblems(tree, uid + 1).sort()).toEqual([
      `.: owner ${uid}`,
      `f: owner ${uid}`,
    ]);
    const link = join(root, "root-link");
    symlinkSync(tree, link);
    expect(modeProblems(link)).toEqual([".: symlink"]);
  });
});

describe("the scan for a secret", () => {
  const enc = (text: string): Uint8Array => new TextEncoder().encode(text);

  test("a value is found as is, in base64 and in hex, and a clean tree has none", () => {
    const tree = join(root, "scan");
    mkdirSync(tree);
    writeFileSync(join(tree, "plain"), "xx synthetic-value yy");
    writeFileSync(
      join(tree, "b64"),
      Buffer.from("synthetic-value").toString("base64"),
    );
    writeFileSync(
      join(tree, "hex"),
      Buffer.from("synthetic-value").toString("hex"),
    );
    writeFileSync(join(tree, "clean"), "nothing here");
    const found = containing(tree, [enc("synthetic-value")]);
    expect(found.matches.sort()).toEqual(["b64", "hex", "plain"]);
    expect(found.filesRead).toBe(4);
    const absent = containing(tree, [enc("absent-value")]);
    expect(absent.matches).toEqual([]);
    expect(absent.filesRead).toBe(4);
  });

  test("raw key bytes are found, and several needles are all searched", () => {
    const tree = join(root, "scan-raw");
    mkdirSync(tree);
    const key = deriveKey("scan-nonce");
    writeFileSync(join(tree, "raw"), Buffer.concat([Buffer.from("pre"), key]));
    writeFileSync(join(tree, "nonce"), "scan-nonce");
    writeFileSync(join(tree, "clean"), "nothing");
    expect(
      containing(tree, secretNeedles("scan-nonce")).matches.sort(),
    ).toEqual(["nonce", "raw"]);
  });

  test("an empty tree reads zero files, so a caller's positive control fails it", () => {
    const tree = join(root, "scan-empty");
    mkdirSync(tree);
    const scanned = containing(tree, [enc("x")]);
    expect(scanned.filesRead).toBe(0);
    expect(scanned.matches).toEqual([]);
  });
});

describe("the verdict and the output line", () => {
  const all = requiredChecks.map((name) => ({ name, ok: true }));

  test("PASSED needs every required check, all ok, and no other failure", () => {
    expect(verdict(all, requiredChecks)).toBe("PASSED");
    expect(verdict([], requiredChecks)).toBe("FAILED");
    expect(verdict([{ name: "x", ok: true }], ["x"])).toBe("PASSED");
    expect(verdict(all, requiredChecks, ["error"])).toBe("FAILED");
    expect(
      verdict([...all, { name: "extra", ok: false }], requiredChecks),
    ).toBe("FAILED");
  });

  test("a required check that is missing, or failed, or failed once of two, is FAILED", () => {
    for (const name of requiredChecks) {
      expect(
        verdict(
          all.filter((c) => c.name !== name),
          requiredChecks,
        ),
      ).toBe("FAILED");
      expect(
        verdict(
          all.map((c) => (c.name === name ? { ...c, ok: false } : c)),
          requiredChecks,
        ),
      ).toBe("FAILED");
      expect(verdict([...all, { name, ok: false }], requiredChecks)).toBe(
        "FAILED",
      );
    }
  });

  test("a verdict that requires nothing proves nothing", () => {
    expect(verdict(all, [])).toBe("FAILED");
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
