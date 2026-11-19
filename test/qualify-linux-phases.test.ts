// WCLI-21 slice 4a-2b-2 part B, slice B1: the harness script's P0 wiring, its
// argument parsing, and the source test that the harness never reboots or
// reaches for a shell. No TPM is reached; importing the script runs nothing
// (its main is guarded), and the first test here would die if it did.
//
// MUTANT REGISTER (predictions committed before any observation, never edited;
// observations are appended below):
//   X1  support.ts: "systemctl" removed from forbiddenSpawnWords -> "each forbidden word in code is a finding" only
//   X2  qualify-linux.ts: groupIdsRow drops the numeric-id test (ok = status 0) -> "the groups row" only
//   X3  qualify-linux.ts: factsCommands gains a fifth command -> "P0 runs exactly its four commands" only
//   X4  qualify-linux.ts: `if (import.meta.main)` becomes `if (true)` -> the whole file dies on import (exit 2 from the usage branch), so every test here is red
//   X5  qualify-linux.ts: tpmDeviceRow's leading `c` test becomes `.` -> "the device row" only
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  factsCommands,
  groupIdsRow,
  type Probe,
  parseArgs,
  runFacts,
  tpmDeviceRow,
  tpmToolsRow,
} from "../scripts/qualify-linux.ts";
import {
  forbiddenSpawnWords,
  harnessSourceProblems,
  verdict,
} from "../scripts/qualify-linux-support.ts";

const ok = (stdout: string): Probe => ({ status: 0, stdout });
const device = "crw------- 1 root root 10, 125 Nov 19 05:00 /dev/tpmrm0\n";
const getcap =
  'tool="tpm2_getcap" version="5.6" tctis="libtss2-tctildr" tcti-default=tcti-device\n';

test("importing the script runs no phase", () => {
  expect(typeof runFacts).toBe("function");
});

describe("P0", () => {
  test("P0 runs exactly its four commands, in order, and a good host passes", () => {
    const seen: string[] = [];
    const out = runFacts((command, args) => {
      seen.push([command, ...args].join(" "));
      return ok(
        command.endsWith("/id")
          ? "1000 27 44\n"
          : command.endsWith("/uname")
            ? "Linux jetson 5.15 aarch64\n"
            : command.endsWith("/ls")
              ? device
              : getcap,
      );
    });
    expect(seen).toEqual([
      "/usr/bin/id -G",
      "/usr/bin/uname -a",
      "/usr/bin/tpm2_getcap --version",
      "/usr/bin/ls -l /dev/tpmrm0",
    ]);
    expect(factsCommands.length).toBe(4);
    expect(out.result).toBe("PASSED");
    expect(out.checks.map((c) => c.name)).toEqual([
      "effective-groups-recorded",
      "tpm-device-present",
      "tpm2-tools-present",
    ]);
  });

  test("the groups row", () => {
    expect(groupIdsRow(ok("1000 27 44\n")).ok).toBe(true);
    expect(groupIdsRow(ok("1000 root\n")).ok).toBe(false);
    expect(groupIdsRow({ status: 1, stdout: "1000\n" }).ok).toBe(false);
    expect(groupIdsRow(ok("")).ok).toBe(false);
  });

  test("the device row", () => {
    expect(tpmDeviceRow(ok(device)).ok).toBe(true);
    expect(
      tpmDeviceRow(ok("-rw-r--r-- 1 root root 0 Nov 19 05:00 /dev/tpmrm0\n"))
        .ok,
    ).toBe(false);
    expect(tpmDeviceRow({ status: 2, stdout: "" }).ok).toBe(false);
    expect(tpmDeviceRow(ok(`${device}${device}`)).ok).toBe(false);
  });

  test("the tools row, and a failed row makes the run FAILED", () => {
    expect(tpmToolsRow(ok(getcap)).detail).toEqual({ version: "5.6" });
    expect(tpmToolsRow(ok('tool="tpm2_other" version="5.6"\n')).ok).toBe(false);
    expect(tpmToolsRow({ status: null, stdout: getcap }).ok).toBe(false);
    expect(
      verdict("facts", [
        groupIdsRow(ok("1000\n")),
        tpmDeviceRow(ok(device)),
        tpmToolsRow({ status: 1, stdout: "" }),
      ]),
    ).toBe("FAILED");
  });
});

test("arguments", () => {
  expect(parseArgs(["--build", "out"])).toEqual({ kind: "build", dir: "out" });
  expect(parseArgs(["--build"])).toEqual({ kind: "usage" });
  expect(parseArgs(["--build", "--phase"])).toEqual({ kind: "usage" });
  expect(parseArgs(["--phase", "facts"])).toEqual({
    kind: "phase",
    phase: "facts",
  });
  expect(parseArgs([])).toEqual({ kind: "usage" });
});

describe("the harness source", () => {
  test("the real script has no reboot, shell or exec, and the check read it", () => {
    const source = readFileSync(
      new URL("../scripts/qualify-linux.ts", import.meta.url),
      "utf8",
    );
    expect(source.length).toBeGreaterThan(1000);
    expect(harnessSourceProblems(source)).toEqual([]);
  });

  test("each forbidden word in code is a finding, and a comment saying it is not", () => {
    for (const word of forbiddenSpawnWords) {
      expect(harnessSourceProblems(`spawnSync("${word}", []);`)).toEqual([
        `names ${word}`,
      ]);
      expect(harnessSourceProblems(`// never ${word}\nconst x = 1;`)).toEqual(
        [],
      );
      expect(harnessSourceProblems(`/* ${word} */ const x = 1;`)).toEqual([]);
    }
  });

  test("sh -c, a shell option and exec are findings; shell false is not", () => {
    expect(harnessSourceProblems('spawnSync("sh", ["-c", "id"]);')).toContain(
      "sh -c",
    );
    expect(
      harnessSourceProblems('spawnSync("id", [], { shell: true });'),
    ).toContain("shell option");
    expect(
      harnessSourceProblems('spawnSync("id", [], { shell: false });'),
    ).toEqual([]);
    expect(harnessSourceProblems('execSync("id");')).toContain("exec");
  });
});
