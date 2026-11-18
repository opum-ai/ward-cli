// T26 on Linux: a real TPM2 seal-and-unseal run and a packaged-binary smoke
// across a reboot (WCLI-21 slice 4a, DEC-262, ADR 0028). The pure parts live in
// qualify-linux-support.ts and are measured by `bun test`; this file is the
// run itself, so it is NOT part of `bun test` or `bun run check`.
//
//   bun scripts/qualify-linux.ts --build <dir>          (on the build host)
//   WARD_QUALIFY_REAL_TPM=1 ./ward-qualify-linux --phase seal   --dir D --ward ./ward
//   ... the operator reboots the host ...
//   WARD_QUALIFY_REAL_TPM=1 ./ward-qualify-linux --phase unseal --dir D --ward ./ward
//   WARD_QUALIFY_REAL_TPM=1 ./ward-qualify-linux --phase clean  --dir D
//
// D is a persistent directory (not /tmp: the reboot clears it) named
// ward-qualify-linux-<anything>. Every run keeps to it: the packaged binary
// runs with HOME under D, so the developer's real ~/.ward is never opened.
// Only synthetic keys and values are used, and the seal phase leaves the sealed
// key in D for the unseal phase to find after the reboot.
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  classifySessionPrintoutForTest,
  createPrimary,
  detectTpm2,
  runTool,
  sealKey,
  type Tpm2Presence,
  unsealKey,
} from "../src/adapters/tpm2-tools.ts";
import { buildExecutable, entry } from "./build.ts";
import {
  assertRunDirectory,
  containing,
  deriveKey,
  diffHandles,
  type HandleSnapshot,
  handleLists,
  lastJsonLine,
  markerName,
  modeProblems,
  parseState,
  type RunState,
  sha256,
  verdict,
} from "./qualify-linux-support.ts";

const argv = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const at = argv.indexOf(name);
  return at === -1 ? undefined : argv[at + 1];
};
const SYSTEM_PATH = "/usr/bin:/bin";
const PROFILE = "example-profile";
const ALIAS = "example-token";

// Host side: compile the shipped ward and this harness for a Linux arm64 host.
// The build host needs no TPM, so no flag is asked for.
if (argv.includes("--build")) {
  const out = flag("--build");
  if (out === undefined) throw new Error("--build <dir>");
  mkdirSync(out, { recursive: true });
  const built = Object.fromEntries(
    [
      ["ward", entry],
      ["ward-qualify-linux", import.meta.path],
    ].map(([name, source]) => {
      const outfile = join(out, name as string);
      buildExecutable({
        entry: source as string,
        outfile,
        target: "bun-linux-arm64",
      });
      return [name, sha256(readFileSync(outfile))];
    }),
  );
  console.log(JSON.stringify({ built }));
  process.exit(0);
}

const phase = flag("--phase");
const dir = flag("--dir") ?? "";
if (process.platform !== "linux") {
  console.error("refusing: the Linux qualification runs on Linux");
  process.exit(2);
}
if (process.env.WARD_QUALIFY_REAL_TPM !== "1") {
  console.error("refusing: set WARD_QUALIFY_REAL_TPM=1");
  process.exit(2);
}
if (
  (phase !== "seal" && phase !== "unseal" && phase !== "clean") ||
  dir === ""
) {
  console.error("usage: --phase seal|unseal|clean --dir <run directory>");
  process.exit(2);
}
assertRunDirectory(dir, homedir());

if (phase === "clean") {
  // Only a directory this harness made: the marker is the proof.
  if (!existsSync(join(dir, markerName))) {
    console.error("refusing: no run marker, so this is not a run directory");
    process.exit(2);
  }
  rmSync(dir, { recursive: true, force: true });
  console.log(JSON.stringify({ phase, removed: dir, result: "PASSED" }));
  process.exit(0);
}

const wardBinary = flag("--ward");
if (wardBinary === undefined) {
  console.error("--ward <path to the packaged ward> is required");
  process.exit(2);
}

const homes = {
  first: join(dir, "home-first"),
  second: join(dir, "home-second"),
};
const checkout = join(dir, "checkout");
const checkoutSecond = join(dir, "checkout-second");
const statePath = join(dir, "state.json");
const checks: { label: string; ok: boolean; detail?: unknown }[] = [];
const failures: string[] = [];
const report: Record<string, unknown> = { phase, dir, checks };
const check = (label: string, ok: boolean, detail?: unknown): void => {
  checks.push({ label, ok, ...(detail === undefined ? {} : { detail }) });
};

const state: RunState | undefined =
  phase === "seal" ? undefined : parseState(readFileSync(statePath, "utf8"));
const nonce = state?.nonce ?? randomBytes(12).toString("hex");
const VALUE = `ward-qualify-value-${nonce}`;
const PASSPHRASE = `ward-qualify-pass-${nonce}`;

function facts(): Record<string, unknown> {
  const run = (cmd: string[]): string => {
    try {
      return Bun.spawnSync(cmd, { env: { PATH: SYSTEM_PATH } })
        .stdout.toString()
        .trim();
    } catch {
      return "unavailable";
    }
  };
  return {
    uname: run(["uname", "-srm"]),
    groupIds: run(["id", "-G"]),
    groupNames: run(["id", "-Gn"]),
    uid: process.getuid?.(),
    stdinIsTty: process.stdin.isTTY === true,
    device: run(["ls", "-l", "/dev/tpmrm0"]),
    python3: run(["python3", "--version"]),
    tpm2Tools: run(["tpm2_getcap", "--version"]),
    bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
    wardSha256: createHash("sha256")
      .update(readFileSync(wardBinary as string))
      .digest("hex"),
    harnessBun: Bun.version,
  };
}

async function handles(presence: Tpm2Presence): Promise<HandleSnapshot> {
  const out: Partial<Record<(typeof handleLists)[number], string>> = {};
  for (const list of handleLists)
    out[list] = Buffer.from(
      (await runTool(presence, "tpm2_getcap", [list])).stdout,
    ).toString("utf8");
  return out as HandleSnapshot;
}

interface Run {
  exit: number;
  stdout: string;
  stderr: string;
}
const leaks: string[] = [];
const answers: [RegExp, string][] = [
  [/\[y\/N\] $/, "y\n"],
  [/passphrase[^\n]*: $/, `${PASSPHRASE}\n`],
  [/confirm: $/, `${PASSPHRASE}\n`],
];
// A terminal for the prompts, as in the macOS run: registration, approval and a
// backup passphrase are asked on one.
const ptyBridge = `
import os, pty, select, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
watch = [fd, 0]
while fd in watch:
    ready, _, _ = select.select(watch, [], [])
    if fd in ready:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        os.write(1, data)
    if 0 in ready:
        data = os.read(0, 4096)
        if data:
            os.write(fd, data)
        else:
            watch.remove(0)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
`;

async function ward(
  home: string,
  cwd: string,
  args: string[],
  options: { tty?: boolean; stdin?: string } = {},
): Promise<Run> {
  const command = options.tty
    ? ["python3", "-I", "-c", ptyBridge, wardBinary as string, ...args]
    : [wardBinary as string, ...args];
  const child = Bun.spawn(command, {
    cwd,
    env: {
      HOME: home,
      PATH: SYSTEM_PATH,
      TMPDIR: join(dir, "tmp"),
      TERM: "xterm",
    },
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });
  const timer = setTimeout(() => child.kill(), 90_000);
  let seen = 0;
  let stdout = "";
  const read = async (
    stream: ReadableStream<Uint8Array>,
    answer: boolean,
  ): Promise<string> => {
    const decoder = new TextDecoder();
    let text = "";
    for await (const chunk of stream) {
      const piece = decoder.decode(chunk, { stream: true });
      text += piece;
      if (!answer) continue;
      stdout += piece;
      for (const [pattern, reply] of answers)
        if (pattern.test(stdout.slice(seen))) {
          seen = stdout.length;
          try {
            child.stdin.write(reply);
            child.stdin.flush();
          } catch {
            // The child already exited; nothing is left to answer.
          }
        }
    }
    return text;
  };
  if (options.stdin !== undefined) {
    child.stdin.write(options.stdin);
    child.stdin.end();
  } else if (!options.tty) child.stdin.end();
  const [out, err] = await Promise.all([
    read(child.stdout, true),
    read(child.stderr, false),
  ]);
  const exit = await child.exited;
  clearTimeout(timer);
  if (
    (out + err).includes(VALUE) ||
    (!options.tty && (out + err).includes(PASSPHRASE))
  )
    leaks.push(args.slice(0, 2).join(" "));
  return { exit, stdout: out, stderr: err };
}

// Ward's own sequence, run through the real adapter on the real host: the
// direct seal and unseal, and an independent look at the session printout.
async function direct(presence: Tpm2Presence): Promise<void> {
  const tpm = join(dir, "direct-tpm");
  if (phase === "seal") {
    const key = deriveKey(nonce);
    await sealKey(presence, key, tpm);
    check(
      "a second seal into the same directory is refused",
      await sealKey(presence, key, tpm).then(
        () => false,
        () => true,
      ),
    );
  }
  const unsealed = await unsealKey(presence, tpm);
  const digest = sha256(unsealed);
  check(
    phase === "seal"
      ? "unsealKey end to end returns the sealed key"
      : "after the reboot, unsealKey returns the key sealed before it",
    digest === (state?.keyDigest ?? sha256(deriveKey(nonce))),
  );
  check(
    "the sealed blobs are user-private",
    modeProblems(tpm).length === 0,
    modeProblems(tpm),
  );
  if (phase === "seal") {
    // The salted HMAC session on its own: its printout, verbatim, and the
    // verdict Ward's parser reaches on it.
    const probe = join(dir, "probe");
    const primary = await createPrimary(presence, probe);
    const session = join(probe, "s.ctx");
    await runTool(
      presence,
      "tpm2_startauthsession",
      ["--hmac-session", "-c", primary, "-S", session, "-Q"],
      { cwd: probe },
    );
    await runTool(
      presence,
      "tpm2_sessionconfig",
      ["--enable-decrypt", "--enable-encrypt", session],
      { cwd: probe },
    );
    const printout = Buffer.from(
      (await runTool(presence, "tpm2_sessionconfig", [session], { cwd: probe }))
        .stdout,
    ).toString("utf8");
    report.sessionPrintout = printout;
    check(
      "the salted session's printout reads decrypt and encrypt on",
      classifySessionPrintoutForTest(printout) === "on",
      printout,
    );
    await runTool(presence, "tpm2_flushcontext", [session], { cwd: probe });
  }
}

async function packaged(): Promise<void> {
  const here = homes.first;
  const gate = (label: string, run: Run): void =>
    check(label, run.exit === 0, {
      exit: run.exit,
      kind: lastJsonLine(run.stdout).kind,
    });
  if (phase === "seal") {
    gate("setup", await ward(here, checkout, ["setup", "--json"]));
    gate(
      "init registers the checkout",
      await ward(here, checkout, ["init", "--json"], { tty: true }),
    );
    const manifestPath = join(checkout, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      profiles?: unknown;
    };
    manifest.profiles = {
      [PROFILE]: {
        adapter: "http",
        method: "GET",
        url: "https://api.example.invalid/status",
        auth: { type: "bearer", secret: ALIAS },
        requestBody: "none",
        output: "status",
      },
    };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    gate(
      "secret set --stdin",
      await ward(
        here,
        checkout,
        ["secret", "set", ALIAS, "--stdin", "--json"],
        { stdin: VALUE },
      ),
    );
    gate(
      "profile approve",
      await ward(here, checkout, ["profile", "approve", PROFILE, "--json"], {
        tty: true,
      }),
    );
    gate("check is ready", await ward(here, checkout, ["check", "--json"]));
    return;
  }
  gate(
    "check is ready after the reboot",
    await ward(here, checkout, ["check", "--json"]),
  );
  const run = await ward(here, checkout, ["run", PROFILE, "--json"]);
  const code = (() => {
    try {
      return (
        JSON.parse(run.stderr.trim().split("\n").pop() ?? "{}") as {
          code?: string;
        }
      ).code;
    } catch {
      return undefined;
    }
  })();
  check(
    "run is admitted and refused at the destination, sending nothing",
    run.exit !== 0 && code === "run_destination_unresolved",
    { exit: run.exit, code },
  );
  const audit = await ward(here, checkout, ["audit", "--json"]);
  const phases = (
    audit.stdout.match(/"phase"\s*:\s*"(admission|completion)"/g) ?? []
  )
    .map((m) => m.replace(/.*"(admission|completion)"/, "$1"))
    .sort();
  check(
    "audit records the admission and the completion of that one run",
    audit.exit === 0 && phases.join(",") === "admission,completion",
    { phases },
  );
  for (const name of ["status", "doctor"] as const)
    gate(name, await ward(here, checkout, [name, "--json"]));
  const backup = join(dir, "backup.json");
  gate(
    "backup",
    await ward(here, checkout, ["backup", "--output", backup, "--json"], {
      tty: true,
    }),
  );
  mkdirSync(join(checkoutSecond, ".git"), { recursive: true });
  gate(
    "restore into a second store, with only the passphrase",
    await ward(
      homes.second,
      checkoutSecond,
      ["restore", "--input", backup, "--json"],
      { tty: true },
    ),
  );
  gate(
    "unregister",
    await ward(here, checkout, ["unregister", "--json"], { tty: true }),
  );
  const refused = await ward(here, checkout, ["run", PROFILE, "--json"]);
  check("a run after unregister is refused", refused.exit !== 0, {
    exit: refused.exit,
  });
  for (const [label, needle] of [
    ["secret value", VALUE],
    ["backup passphrase", PASSPHRASE],
  ] as const) {
    const found = containing(dir, needle);
    check(`no ${label} anywhere under the run directory`, found.length === 0, {
      found: found.length,
    });
  }
  check(
    "no command output held the secret value or the passphrase",
    leaks.length === 0,
    { leaks },
  );
  for (const home of [homes.first, homes.second]) {
    const tpm = join(home, ".ward", "tpm");
    if (existsSync(tpm))
      check(
        `the blob directory under ${home} is user-private`,
        modeProblems(tpm).length === 0,
        modeProblems(tpm),
      );
  }
}

try {
  if (phase === "seal") {
    if (existsSync(dir) && readdirSync(dir).length > 0)
      throw new Error("the run directory is not empty: clean it first");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
    writeFileSync(join(dir, markerName), "ward-qualify-linux\n");
    for (const path of [
      homes.first,
      homes.second,
      join(dir, "tmp"),
      join(checkout, ".git"),
    ])
      mkdirSync(path, { recursive: true });
  } else {
    check(
      "this is a different boot from the seal phase",
      readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() !==
        state?.bootId,
      { sealed: state?.bootId },
    );
  }
  report.facts = facts();
  const presence = detectTpm2();
  check("the real host's TPM is detected", true, { device: presence.device });
  const before =
    phase === "seal"
      ? await handles(presence)
      : (state as RunState).handlesBefore;
  await direct(presence);
  await packaged();
  const after = await handles(presence);
  const moved = diffHandles(before, after);
  check("all four handle lists are as before the run", moved.length === 0, {
    moved,
  });
  if (phase === "seal")
    writeFileSync(
      statePath,
      `${JSON.stringify({ nonce, keyDigest: sha256(deriveKey(nonce)), handlesBefore: before, sealedAt: new Date().toISOString(), bootId: (report.facts as { bootId: string }).bootId } satisfies RunState, null, 2)}\n`,
      { mode: 0o600 },
    );
} catch (error) {
  failures.push(String(error));
  report.error = String(error);
}
report.result = verdict(checks, failures);
console.log(JSON.stringify(report, null, 2));
process.exit(report.result === "PASSED" ? 0 : 1);
