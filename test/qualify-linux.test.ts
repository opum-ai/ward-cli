// WCLI-21 slice 4a: the parts of the Linux T26 harness that need no TPM. The
// run itself (scripts/qualify-linux.ts) is measured on the hardware host, so
// everything it relies on that CAN be proved here, is: the directory guards
// that keep it off /tmp and the real ~/.ward, the handle comparison, the mode
// check, the state file and the verdict.
import "./support/no-real-keychain.ts";
import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
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
  type HandleSnapshot,
  handleLists,
  lastJsonLine,
  modeProblems,
  parseState,
  runDirectoryPrefix,
  sha256,
  verdict,
} from "../scripts/qualify-linux-support.ts";

const root = mkdtempSync(join(tmpdir(), "ward-qualify-linux-test-"));
const home = "/home/synthetic";
const snapshot = (over: Partial<HandleSnapshot> = {}): HandleSnapshot => ({
  "handles-transient": "",
  "handles-persistent": "",
  "handles-saved-session": "",
  "handles-loaded-session": "",
  ...over,
});

describe("the run directory guard", () => {
  test("a persistent, resolved, prefixed directory outside the real store is accepted", () => {
    expect(() =>
      assertRunDirectory(`/srv/${runDirectoryPrefix}one`, home),
    ).not.toThrow();
  });

  test("each way of naming the wrong place is refused", () => {
    const refused: [string, RegExp][] = [
      ["relative/path", /absolute/],
      [`/srv/not-${runDirectoryPrefix}x`, /name begins/],
      [`/srv/../srv/${runDirectoryPrefix}x`, /resolved form/],
      [`/tmp/${runDirectoryPrefix}x`, /must not sit under/],
      [`/var/tmp/${runDirectoryPrefix}x`, /must not sit under/],
      [`/dev/shm/${runDirectoryPrefix}x`, /must not sit under/],
      [`${tmpdir()}/${runDirectoryPrefix}x`, /must not sit under/],
      [`${home}/.ward/${runDirectoryPrefix}x`, /real ~\/.ward/],
      [`${home}/.ward`, /name begins/],
    ];
    for (const [directory, message] of refused)
      expect(() => assertRunDirectory(directory, home)).toThrow(message);
  });

  test("the real home's store is a refusal for the real home too", () => {
    expect(() =>
      assertRunDirectory(
        join(homedir(), ".ward", `${runDirectoryPrefix}x`),
        homedir(),
      ),
    ).toThrow(/real ~\/.ward/);
  });
});

describe("the handle comparison", () => {
  test("identical lists show no movement, and each list that moved is named", () => {
    expect(diffHandles(snapshot(), snapshot())).toEqual([]);
    expect(
      diffHandles(
        snapshot(),
        snapshot({ "handles-saved-session": "- 0x2000000\n" }),
      ),
    ).toEqual(["handles-saved-session"]);
    for (const list of handleLists)
      expect(diffHandles(snapshot(), snapshot({ [list]: "- 0x1\n" }))).toEqual([
        list,
      ]);
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
      keyDigest: "d",
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
        JSON.stringify({ ...good, handlesBefore: { "handles-transient": "" } }),
      ),
    ).toThrow(/malformed/);
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
});

describe("the scan for a secret", () => {
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
    expect(containing(tree, "synthetic-value").sort()).toEqual([
      "b64",
      "hex",
      "plain",
    ]);
    expect(containing(tree, "absent-value")).toEqual([]);
  });
});

describe("the verdict and the output line", () => {
  test("PASSED needs checks, all ok, and no other failure; an empty run is FAILED", () => {
    expect(verdict([{ ok: true }, { ok: true }])).toBe("PASSED");
    expect(verdict([])).toBe("FAILED");
    expect(verdict([{ ok: true }, { ok: false }])).toBe("FAILED");
    expect(verdict([{ ok: true }], ["error"])).toBe("FAILED");
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
