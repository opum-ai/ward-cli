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
//   X1b (after X1 measured green: the test iterated the mutated list itself) the same mutant against the test with the words spelled out -> "each forbidden word in code is a finding" only
//   X5  qualify-linux.ts: tpmDeviceRow's leading `c` test becomes `.` -> "the device row" only
//
// ROUND 2 (predictions committed before the run):
//   Y1  qualify-linux.ts: build() uses `dir` instead of `resolve(dir)` -> "a relative build dir is one absolute path" only
//   Y2  qualify-linux.ts: the refusal branch exits 0 instead of 2 -> "an unwired phase and no arguments exit 2" only
//   Y3  qualify-linux.ts: makeRunner passes `env: process.env` -> "the runner's environment is only PATH and LC_ALL" only
//   Y4  qualify-linux.ts: makeRunner drops its timeout -> "a probe past its timeout reads as failed" only
// OBSERVED (Mac, bun 1.3.14, 2026-11-19): X1 GREEN, a divergence: the test iterated the mutated list, so it could not see the removal; fixed by spelling the words out (commit after the first), then X1b red on exactly "each forbidden word in code is a finding". X2, X3, X5 red on exactly their predicted test. X4 killed the test process on import (the usage branch printed and exited 2), so no test ran: red as predicted. Mac only; none of these are Linux-only.
// B2: the source-tripwire tests (X1b and the shell/exec cases) moved to test/qualify-linux-source.test.ts with the check, which now lives in test/support/harness-source.ts; the X1-X5 observations below stay as recorded.
import { describe, expect, test } from "bun:test";
// OBSERVED, ROUND 2 (Mac, bun 1.3.14, 2026-11-19; predictions unchanged): Y1, Y2, Y3 and Y4 each red on exactly their predicted test (Y4 took the full 5s sleep). A new test, "a missing binary reads as failed", found a real defect before any mutant: under Bun a failed spawn (ENOENT) has status undefined, not null, so the runner now maps it to null. N-2 (review): the harness compiled natively (no --target, so no download) into the scratchpad and run with --phase facts on the Mac refused ("refusing: the Linux qualification runs on Linux", exit 2); a find for files newer than a marker taken before the build found nothing new under the repository or dist/ (dist/ward Sep 29 12:06 and dist/ward-qualify Oct 20 23:11, unchanged), only the built binary.
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import type { buildExecutable } from "./../scripts/build.ts";
import {
  build,
  factsCommands,
  groupIdsRow,
  makeRunner,
  type Probe,
  parseArgs,
  runFacts,
  tpmDeviceRow,
  tpmToolsRow,
} from "../scripts/qualify-linux.ts";
import { sha256, verdict } from "../scripts/qualify-linux-support.ts";

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

describe("the build directory", () => {
  test("a relative build dir is one absolute path for mkdir, outfile and read", () => {
    const home = process.cwd();
    const caller = realpathSync(mkdtempSync(join(tmpdir(), "ward-b1-caller-")));
    const root = realpathSync(mkdtempSync(join(tmpdir(), "ward-b1-root-")));
    const seen: string[] = [];
    // bun build runs with the repository root as its cwd, so a relative outfile
    // lands under root; an absolute one lands where it says.
    const fake = ((options: { outfile: string }) => {
      seen.push(options.outfile);
      writeFileSync(resolve(root, options.outfile), `built:${options.outfile}`);
      return options.outfile;
    }) as typeof buildExecutable;
    process.chdir(caller);
    try {
      const built = build("out", fake);
      expect(seen).toEqual([
        join(caller, "out", "ward"),
        join(caller, "out", "ward-qualify-linux"),
      ]);
      expect(seen.every((path) => isAbsolute(path))).toBe(true);
      expect(built).toEqual({
        ward: sha256(Buffer.from(`built:${seen[0]}`)),
        "ward-qualify-linux": sha256(Buffer.from(`built:${seen[1]}`)),
      });
    } finally {
      process.chdir(home);
      rmSync(caller, { recursive: true, force: true });
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("the dispatch and the probe runner", () => {
  const spawnHarness = (...args: string[]) => {
    const run = Bun.spawnSync(
      [process.execPath, "scripts/qualify-linux.ts", ...args],
      { cwd: new URL("..", import.meta.url).pathname },
    );
    return { code: run.exitCode, err: run.stderr.toString() };
  };

  // Never `--phase facts` here: CI is Linux and would really run P0.
  test("an unwired phase and no arguments exit 2 with the refusal or usage", () => {
    const seal = spawnHarness("--phase", "seal");
    expect(seal.code).toBe(2);
    expect(seal.err).toContain("phase seal is not wired");
    const none = spawnHarness();
    expect(none.code).toBe(2);
    expect(none.err).toContain("usage:");
  });

  test("the runner's environment is only PATH and LC_ALL", () => {
    process.env.WARD_PROBE_SECRET = "must-not-reach-a-probe";
    try {
      const out = makeRunner()("/usr/bin/env", []);
      expect(out.status).toBe(0);
      expect(out.stdout.split("\n").filter(Boolean).sort()).toEqual([
        "LC_ALL=C",
        "PATH=/usr/bin:/bin",
      ]);
    } finally {
      delete process.env.WARD_PROBE_SECRET;
    }
  });

  test("a probe past its timeout reads as failed", () => {
    const out = makeRunner(200)("/bin/sleep", ["5"]);
    expect(out.status).toBeNull();
  });

  test("a missing binary reads as failed", () => {
    expect(makeRunner()("/usr/bin/ward-no-such-tool", []).status).toBeNull();
  });
});
