// WCLI-16: the shipped executable must not read the working directory's
// bunfig.toml or .env. Every hostile-directory check runs twice: against the
// packaged executable, where it must find nothing, and against `bun
// src/cli/ward.ts`, where it must find the planted files at work. A check
// that cannot fail on the unhardened launch proves nothing about the
// hardened one.
import { afterAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  buildCommand,
  buildExecutable,
  entry,
  outfile,
} from "../scripts/build.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { buildRoot, packagedWard } from "./support/packaged.ts";

const ROOT = join(import.meta.dir, "..");
const PROBE_ENTRY = join(import.meta.dir, "fixtures", "env-probe.ts");
const ARGV_SENTINEL = "ward-argv-sentinel-5d0e";
const PRELOAD_SENTINEL = "ward-preload-sentinel-3c81";
const DOTENV_KEY = "WARD_DOTENV_PROBE";
const DOTENV_SENTINEL = "ward-dotenv-sentinel-b52e";
const TOML_SENTINEL = "ward-toml-sentinel-e19a";

// Registered before anything is built, so a failed build still cleans up.
const work = mkdtempSync(join(tmpdir(), "ward-launcher-"));
// Built at module load rather than in a hook, so the compile is not subject
// to a per-hook timeout.
const packagedProbe = buildExecutable({
  entry: PROBE_ENTRY,
  outfile: join(buildRoot, "env-probe"),
});

// A repository an agent could have edited: a preload that records that it
// ran, prints argv and the .env value, and throws with argv.
const hostile = join(work, "repo");
const preloadMarker = join(hostile, "preload-ran");
mkdirSync(hostile);
writeFileSync(join(hostile, "bunfig.toml"), 'preload = ["./preload.ts"]\n');
writeFileSync(
  join(hostile, "preload.ts"),
  [
    'import { writeFileSync } from "node:fs";',
    `writeFileSync(${JSON.stringify(preloadMarker)}, "");`,
    `process.stderr.write(${JSON.stringify(PRELOAD_SENTINEL)} + JSON.stringify(process.argv) + String(process.env.${DOTENV_KEY}) + "\\n");`,
    `throw new Error(${JSON.stringify(PRELOAD_SENTINEL)} + process.argv.join(" "));`,
    "",
  ].join("\n"),
);
writeFileSync(join(hostile, ".env"), `${DOTENV_KEY}=${DOTENV_SENTINEL}\n`);

// The same .env with no bunfig.toml, so the unhardened control reaches the
// probe's own code instead of dying in the preload.
const dotenvOnly = join(work, "dotenv-only");
mkdirSync(dotenvOnly);
writeFileSync(join(dotenvOnly, ".env"), `${DOTENV_KEY}=${DOTENV_SENTINEL}\n`);

// A bunfig.toml that does not parse: Bun's parse error quotes the line.
const malformed = join(work, "malformed-bunfig");
mkdirSync(malformed);
writeFileSync(
  join(malformed, "bunfig.toml"),
  `preload = [ "${TOML_SENTINEL}\n= = [\n`,
);

// Neither variable is closed by the build flags (WCLI-19); an inherited one
// would make these results about the caller's shell, not the executable.
const env: Record<string, string | undefined> = { ...process.env };
delete env.BUN_OPTIONS;
delete env.BUN_BE_BUN;
delete env[DOTENV_KEY];

afterAll(() => rmSync(work, { recursive: true, force: true }));

// Findings are labels, never output, so a failure report cannot itself carry
// a sentinel.
function hostileLaunchFindings(command: string[]): string[] {
  rmSync(preloadMarker, { force: true });
  const run = Bun.spawnSync([...command, "help", ARGV_SENTINEL], {
    cwd: hostile,
    env,
  });
  const output = run.stdout.toString() + run.stderr.toString();
  const findings: string[] = [];
  if (existsSync(preloadMarker)) findings.push("bunfig.toml preload ran");
  const sentinels: [label: string, sentinel: string][] = [
    ["argv", ARGV_SENTINEL],
    ["preload", PRELOAD_SENTINEL],
    [".env", DOTENV_SENTINEL],
  ];
  for (const [label, sentinel] of sentinels)
    if (output.includes(sentinel))
      findings.push(`${label} sentinel in stdout/stderr`);
  if (run.exitCode !== exitCodes.usage)
    findings.push(`exit ${run.exitCode}, expected ${exitCodes.usage}`);
  return findings;
}

function dotenvKeysSeen(command: string[], cwd: string): string[] {
  const run = Bun.spawnSync([...command, DOTENV_KEY], { cwd, env });
  if (run.exitCode !== 0) return [`probe exited ${run.exitCode}`];
  return JSON.parse(run.stdout.toString()) as string[];
}

describe("packaged executable in a hostile working directory", () => {
  test("runs no preload and discloses nothing", () => {
    expect(hostileLaunchFindings([packagedWard])).toEqual([]);
  });

  test("control: `bun src/cli/ward.ts` runs the preload", () => {
    expect(hostileLaunchFindings([process.execPath, entry])).toContain(
      "bunfig.toml preload ran",
    );
  });

  test("still answers normally", () => {
    const run = Bun.spawnSync([packagedWard, "--version"], {
      cwd: hostile,
      env,
    });
    expect(run.exitCode).toBe(exitCodes.success);
    expect(run.stderr.toString()).toBe("");
  });
});

describe("malformed bunfig.toml", () => {
  function launch(command: string[]) {
    const run = Bun.spawnSync([...command, "--version"], {
      cwd: malformed,
      env,
    });
    return { exitCode: run.exitCode, stderr: run.stderr.toString() };
  }

  test("packaged executable neither parses nor echoes it", () => {
    const run = launch([packagedWard]);
    expect(run.exitCode).toBe(exitCodes.success);
    expect(run.stderr).toBe("");
  });

  test("control: `bun src/cli/ward.ts` echoes it", () => {
    expect(
      launch([process.execPath, entry]).stderr.includes(TOML_SENTINEL),
    ).toBe(true);
  });
});

describe(".env is not loaded into process.env", () => {
  test("packaged build, beside bunfig.toml and .env", () => {
    expect(dotenvKeysSeen([packagedProbe], hostile)).toEqual([]);
  });

  test("packaged build, beside .env alone", () => {
    expect(dotenvKeysSeen([packagedProbe], dotenvOnly)).toEqual([]);
  });

  test("control: `bun` loads it", () => {
    expect(dotenvKeysSeen([process.execPath, PROBE_ENTRY], dotenvOnly)).toEqual(
      [DOTENV_KEY],
    );
  });
});

describe("packaging", () => {
  test("package.json bin resolves to the built executable", async () => {
    const pkg = (await Bun.file(join(ROOT, "package.json")).json()) as {
      bin: Record<string, string>;
    };
    expect(Object.keys(pkg.bin)).toEqual(["ward"]);
    expect(resolve(ROOT, pkg.bin.ward ?? "")).toBe(outfile);
    expect(outfile.endsWith(".ts")).toBe(false);
  });

  test("the build command disables every runtime autoload", () => {
    const command = buildCommand({ entry, outfile });
    for (const flag of [
      "--compile",
      "--no-compile-autoload-bunfig",
      "--no-compile-autoload-dotenv",
      "--no-compile-autoload-package-json",
      "--no-compile-autoload-tsconfig",
    ])
      expect(command).toContain(flag);
  });
});
