// T26 on Linux, the run itself (WCLI-21 slice 4a-2b-2 part B, DEC-262, ADR 0028).
// The pure parts live in qualify-linux-support.ts, -rows.ts and -shim.ts and are
// measured by `bun test`; this file wires them to the phase plan P0-P4. Nothing
// runs on import (main is guarded), so no test can start a phase.
//
//   bun scripts/qualify-linux.ts --build <dir>      (local build host, no TPM)
//   ./ward-qualify-linux --phase facts              (P0, read-only)
//
// This slice wires P0 (facts) and --build. P1 deliver, P2 seal, P3 unseal and P4
// clean are not wired yet and are refused by name, so a half-built harness can
// never read as a run.
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { buildExecutable, entry } from "./build.ts";
import { type Check, sha256, verdict } from "./qualify-linux-support.ts";

export interface Probe {
  readonly status: number | null;
  readonly stdout: string;
}
export type Runner = (command: string, args: readonly string[]) => Probe;

// P0 runs exactly these four commands (DEC-262 a29 Q2 and a32), by absolute
// path, with no interposer and no write anywhere.
export const factsCommands: readonly (readonly [string, readonly string[]])[] =
  [
    ["/usr/bin/id", ["-G"]],
    ["/usr/bin/uname", ["-a"]],
    ["/usr/bin/tpm2_getcap", ["--version"]],
    ["/usr/bin/ls", ["-l", "/dev/tpmrm0"]],
  ];

export const tpmDevice = "/dev/tpmrm0";

// `id -G` as recorded: numeric group ids, none empty (P0 runs no `id -Gn`).
export function groupIdsRow(probe: Probe): Check {
  const ids = probe.stdout.trim().split(/\s+/);
  const ok = probe.status === 0 && ids.every((id) => /^\d+$/.test(id));
  return {
    name: "effective-groups-recorded",
    ok,
    detail: ok ? { ids: ids.join(" ") } : { malformed: true },
  };
}

// `ls -l /dev/tpmrm0` names a character device at that path.
export function tpmDeviceRow(probe: Probe): Check {
  const line = probe.stdout.trim();
  const ok =
    probe.status === 0 &&
    !line.includes("\n") &&
    /^c\S*\s.*\s\/dev\/tpmrm0$/.test(line);
  return { name: "tpm-device-present", ok, detail: ok ? { line } : {} };
}

// `tpm2_getcap --version` as measured on the Jetson (probe 5): tool="tpm2_getcap"
// version="5.6" ...
export function tpmToolsRow(probe: Probe): Check {
  const version = /\bversion="(\d+(?:\.\d+)*)"/.exec(probe.stdout)?.[1];
  const ok =
    probe.status === 0 &&
    /\btool="tpm2_getcap"/.test(probe.stdout) &&
    version !== undefined;
  return {
    name: "tpm2-tools-present",
    ok,
    detail: ok ? { version } : {},
  };
}

export function runFacts(run: Runner): {
  result: "PASSED" | "FAILED";
  checks: Check[];
  facts: { uname: string };
} {
  const [groups, uname, getcap, device] = factsCommands.map(([command, args]) =>
    run(command, args),
  ) as [Probe, Probe, Probe, Probe];
  const checks = [
    groupIdsRow(groups),
    tpmDeviceRow(device),
    tpmToolsRow(getcap),
  ];
  return {
    result: verdict("facts", checks),
    checks,
    facts: { uname: uname.status === 0 ? uname.stdout.trim() : "unavailable" },
  };
}

// No shell, a fixed environment, a bounded wait; a missing binary or a timeout
// reads as a failed probe, never as an empty success.
const spawnRunner: Runner = (command, args) => {
  const run = spawnSync(command, [...args], {
    encoding: "latin1",
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C" },
    timeout: 10_000,
    shell: false,
  });
  return { status: run.status, stdout: run.stdout ?? "" };
};

export type Command =
  | { kind: "build"; dir: string }
  | { kind: "phase"; phase: string }
  | { kind: "usage" };

export function parseArgs(argv: readonly string[]): Command {
  const flag = (name: string): string | undefined => {
    const at = argv.indexOf(name);
    return at === -1 ? undefined : argv[at + 1];
  };
  if (argv.includes("--build")) {
    const dir = flag("--build");
    return dir === undefined || dir.startsWith("--")
      ? { kind: "usage" }
      : { kind: "build", dir };
  }
  const phase = flag("--phase");
  return phase === undefined ? { kind: "usage" } : { kind: "phase", phase };
}

function build(dir: string): void {
  mkdirSync(dir, { recursive: true });
  const built = Object.fromEntries(
    [
      ["ward", entry],
      ["ward-qualify-linux", import.meta.path],
    ].map(([name, source]) => {
      const outfile = join(dir, name as string);
      buildExecutable({
        entry: source as string,
        outfile,
        target: "bun-linux-arm64",
      });
      return [name, sha256(readFileSync(outfile))];
    }),
  );
  console.log(JSON.stringify({ built }));
}

if (import.meta.main) {
  const command = parseArgs(process.argv.slice(2));
  if (command.kind === "build") {
    build(command.dir);
  } else if (command.kind === "phase" && command.phase === "facts") {
    if (process.platform !== "linux") {
      console.error("refusing: the Linux qualification runs on Linux");
      process.exit(2);
    }
    const report = runFacts(spawnRunner);
    console.log(JSON.stringify({ phase: "facts", ...report }));
    process.exit(report.result === "PASSED" ? 0 : 1);
  } else {
    console.error(
      command.kind === "phase"
        ? `refusing: phase ${command.phase} is not wired in this build (only facts)`
        : "usage: --build <dir> | --phase facts",
    );
    process.exit(2);
  }
}
