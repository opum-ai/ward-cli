// T26: the packaged-binary smoke and real key-provider run, on macOS (WCLI-15,
// DEC-217 (a2)).
//
// NOT part of `bun test` or `bun run check`: it creates items in the
// developer's real login keychain and runs a compiled executable, so it needs
// WARD_QUALIFY_REAL_KEYCHAIN=1 and a person to start it.
//
//   WARD_QUALIFY_REAL_KEYCHAIN=1 bun scripts/qualify-packaged.ts
//
// What keeps it away from real data, and how each part is proved rather than
// promised:
//   - It runs dist/ward-qualify, compiled with a credential-store service of
//     its own, opum.ward.qualify-<random>. The shipped executable has no
//     runtime override (test/qualify-build.test.ts), so this is a build, not a
//     setting. The run prints the build's single-line diff against the shipped
//     bundle and the service found inside the executable.
//   - HOME is a fresh temporary directory, so the store is <tmp>/.ward and the
//     developer's ~/.ward is never opened by the child. The temporary HOME links
//     the login keychain file and nothing else, because the credential store is
//     found under $HOME (a bare temporary HOME fails every call). The proof is a digest of
//     that tree (every path, type, size, mode, mtime and content hash) taken
//     before and after, which must match. It does NOT read, list or probe the
//     real opum.ward credential-store item, not even its metadata: a read can
//     raise a keychain prompt with no operator at the host.
//   - A `finally` deletes every item this run created from its own service and
//     checks each is gone.
// The executable is driven with PATH=/usr/bin:/bin, so T23's "neither Lore nor
// Quest" is checked on the packaged build too. A terminal is supplied by a
// small Python pty bridge, because registration, approval and a backup
// passphrase are asked on one. The only network activity is the resolver lookup of an
// unresolvable .invalid name: `ward run` reaches admission and is refused at
// the destination, so nothing is sent (the answer to the T26 network A/B).
import { createHash, randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import {
  buildExecutable,
  entry,
  newQualifyService,
  qualifyOutfile,
  serviceDefine,
} from "./build.ts";

if (process.platform !== "darwin") {
  console.error("refusing: the macOS qualification runs on macOS");
  process.exit(2);
}
if (process.env.WARD_QUALIFY_REAL_KEYCHAIN !== "1") {
  console.error("refusing: set WARD_QUALIFY_REAL_KEYCHAIN=1");
  process.exit(2);
}

const ROOT = join(import.meta.dir, "..");
const SYSTEM_PATH = "/usr/bin:/bin";
const PROFILE = "example-profile";
const ALIAS = "example-token";
const VALUE = `ward-qualify-value-${randomBytes(6).toString("hex")}`;
const PASSPHRASE = `ward-qualify-pass-${randomBytes(6).toString("hex")}`;

// A tree, as one digest and a count. mtime is part of it: a vault the child
// merely opened and closed would move it.
function treeDigest(path: string): {
  present: boolean;
  entries: number;
  digest: string;
} {
  try {
    lstatSync(path);
  } catch {
    return { present: false, entries: 0, digest: "absent" };
  }
  const lines: string[] = [];
  const walk = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const full = join(directory, name);
      const stat = lstatSync(full);
      const kind = stat.isDirectory() ? "d" : stat.isSymbolicLink() ? "l" : "f";
      const content =
        kind === "f"
          ? createHash("sha256").update(readFileSync(full)).digest("hex")
          : "-";
      lines.push(
        [
          full.slice(path.length),
          kind,
          stat.size,
          (stat.mode & 0o7777).toString(8),
          stat.mtimeMs,
          content,
        ].join("\t"),
      );
      if (kind === "d") walk(full);
    }
  };
  walk(path);
  return {
    present: true,
    entries: lines.length,
    digest: createHash("sha256").update(lines.join("\n")).digest("hex"),
  };
}

function containing(directory: string, needle: string): string[] {
  const forms = [
    needle,
    Buffer.from(needle).toString("base64"),
    Buffer.from(needle).toString("hex"),
  ].map((form) => Buffer.from(form));
  return readdirSync(directory, { recursive: true })
    .map(String)
    .filter((name) => lstatSync(join(directory, name)).isFile())
    .filter((name) => {
      const content = readFileSync(join(directory, name));
      return forms.some((form) => content.includes(form));
    });
}

const realHome = homedir();
const realWard = join(realHome, ".ward");
const before = treeDigest(realWard);

const service = newQualifyService();
const tmpRoot = mkdtempSync(join(tmpdir(), "ward-qualify-"));
const homes = {
  first: join(tmpRoot, "home-first"),
  second: join(tmpRoot, "home-second"),
};
// A temporary HOME also hides the login keychain: the Security framework finds
// it under $HOME/Library/Keychains, so a bare temporary HOME makes every call
// fail with vault_key_unavailable (measured). Each temporary HOME therefore
// links that one file, the login keychain, and nothing else of the real HOME.
for (const home of [homes.first, homes.second]) {
  mkdirSync(join(home, "Library", "Keychains"), { recursive: true });
  symlinkSync(
    join(realHome, "Library", "Keychains", "login.keychain-db"),
    join(home, "Library", "Keychains", "login.keychain-db"),
  );
}
mkdirSync(join(tmpRoot, "tmp"));
const report: Record<string, unknown> = {
  service,
  bun: Bun.version,
  macos: Bun.spawnSync(["/usr/bin/sw_vers", "-productVersion"])
    .stdout.toString()
    .trim(),
  realWard: { path: realWard, before },
  steps: [] as unknown[],
};
const steps = report.steps as unknown[];
let failed = false;
let lastRun: Run | undefined;
const check = (label: string, ok: boolean, detail?: unknown): void => {
  // A failing step carries the last command's output, clipped. Nothing the
  // executable prints holds the synthetic value (asserted below), so this is
  // safe to keep in a report.
  const output =
    ok || lastRun === undefined
      ? {}
      : {
          stdout: lastRun.stdout.slice(0, 600),
          stderr: lastRun.stderr.slice(0, 600),
        };
  steps.push({
    label,
    ok,
    ...(detail === undefined ? {} : { detail }),
    ...output,
  });
  if (!ok) failed = true;
};

interface Run {
  exit: number;
  stdout: string;
  stderr: string;
}

// Answers, by what the prompt ends with. A pty echoes what is typed, so only
// the PROMPT patterns are matched, and each answer is written once per prompt.
const answers: [RegExp, string][] = [
  [/\[y\/N\] $/, "y\n"],
  [/passphrase[^\n]*: $/, `${PASSPHRASE}\n`],
  [/confirm: $/, `${PASSPHRASE}\n`],
];

// Runs a command on a pseudo-terminal and relays bytes both ways, so the
// executable sees a real tty on stdin and /dev/tty. (/usr/bin/script refuses a
// socket for stdin, which is what a spawned pipe is.) Exits with the child's
// status.
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
  binary: string,
  home: string,
  cwd: string,
  args: string[],
  options: { tty?: boolean; stdin?: string } = {},
): Promise<Run> {
  const command = options.tty
    ? ["/usr/bin/python3", "-I", "-c", ptyBridge, binary, ...args]
    : [binary, ...args];
  const child = Bun.spawn(command, {
    cwd,
    env: {
      HOME: home,
      PATH: SYSTEM_PATH,
      TMPDIR: join(tmpRoot, "tmp"),
      TERM: "xterm",
    },
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });
  const timeout = setTimeout(() => child.kill(), 90_000);
  let stdout = "";
  let seen = 0;
  const read = async (
    stream: ReadableStream<Uint8Array>,
    keep: boolean,
  ): Promise<string> => {
    const decoder = new TextDecoder();
    let text = "";
    for await (const chunk of stream) {
      const piece = decoder.decode(chunk, { stream: true });
      text += piece;
      if (keep) {
        stdout += piece;
        for (const [pattern, reply] of answers) {
          const tail = stdout.slice(seen);
          if (pattern.test(tail)) {
            seen = stdout.length;
            try {
              child.stdin.write(reply);
              child.stdin.flush();
            } catch {
              // The child already exited; there is nothing left to answer.
            }
          }
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
  clearTimeout(timeout);
  lastRun = { exit, stdout: out, stderr: err };
  return lastRun;
}

const parse = (run: Run): Record<string, unknown> => {
  const line = run.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("{"))
    .pop();
  try {
    return JSON.parse(line ?? "{}") as Record<string, unknown>;
  } catch {
    return {};
  }
};

async function cleanup(): Promise<void> {
  const results: unknown[] = [];
  for (const [name, home] of Object.entries(homes)) {
    try {
      const id = createSqliteVaultStore({
        directory: join(home, ".ward"),
      }).header()?.vaultId;
      if (id === undefined) {
        results.push({ home: name, vault: "none created" });
        continue;
      }
      // Deleted with /usr/bin/security, by exact service and account, because
      // an item is owned by the build that created it: this process is not
      // that build, and AsyncEntry refuses with "Invalid attempt to change the
      // owner of this item" (measured). Neither command asks for the secret.
      const account = `vault-${id}`;
      const removed = Bun.spawnSync([
        "/usr/bin/security",
        "delete-generic-password",
        "-s",
        service,
        "-a",
        account,
      ]);
      const deleted = removed.exitCode === 0;
      const lookup = Bun.spawnSync([
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        service,
        "-a",
        account,
      ]);
      const goneBy =
        lookup.exitCode !== 0 ? "lookup finds nothing" : "STILL PRESENT";
      if (!deleted || lookup.exitCode === 0) failed = true;
      results.push({ home: name, deleted, afterDelete: goneBy });
    } catch (error) {
      results.push({ home: name, error: String(error) });
      failed = true;
    }
  }
  report.cleanup = results;
}

process.on("SIGINT", () => {
  void cleanup().finally(() => process.exit(130));
});

try {
  // Build, and the proof that the build names its own service.
  buildExecutable({ entry, outfile: qualifyOutfile, service });
  const binary = qualifyOutfile;
  report.binary = {
    path: binary,
    sha256: createHash("sha256").update(readFileSync(binary)).digest("hex"),
    embedsService: readFileSync(binary).includes(Buffer.from(service)),
  };
  check(
    "the executable embeds its own service",
    (report.binary as { embedsService: boolean }).embedsService,
  );
  const bundleLines = (define: string, index: number): string[] => {
    const outfile = join(tmpRoot, `bundle-${index}.js`);
    const run = Bun.spawnSync(
      [
        process.execPath,
        "build",
        "--target",
        "bun",
        "--external",
        "@napi-rs/*",
        "--define",
        define,
        entry,
        "--outfile",
        outfile,
      ],
      { cwd: ROOT },
    );
    if (run.exitCode !== 0) throw new Error(run.stderr.toString());
    return readFileSync(outfile, "utf8").split("\n");
  };
  const shippedBundle = bundleLines(serviceDefine("opum.ward"), 0);
  const qualifyBundle = bundleLines(serviceDefine(service), 1);
  const differing = shippedBundle
    .map((line, index) => [line, qualifyBundle[index] ?? ""] as const)
    .filter(([a, b]) => a !== b);
  report.buildDiff = differing;
  check(
    "the shipped and qualification bundles differ in the service line only",
    shippedBundle.length === qualifyBundle.length && differing.length === 1,
  );
  check(
    "no lore or quest on the PATH the executable runs under",
    Bun.which("lore", { PATH: SYSTEM_PATH }) === null &&
      Bun.which("quest", { PATH: SYSTEM_PATH }) === null,
  );

  // The packaged workflow, against a temporary store and the test service.
  const checkout = join(tmpRoot, "checkout");
  mkdirSync(join(checkout, ".git"), { recursive: true });
  const here = homes.first;
  const setup = await ward(binary, here, checkout, ["setup", "--json"]);
  check("setup", setup.exit === 0, {
    exit: setup.exit,
    kind: parse(setup).kind,
  });
  check(
    "the store is under the temporary HOME",
    readdirSync(join(here, ".ward")).length > 0,
  );
  const init = await ward(binary, here, checkout, ["init", "--json"], {
    tty: true,
  });
  check("init registers the checkout", init.exit === 0, { exit: init.exit });
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
  const set = await ward(
    binary,
    here,
    checkout,
    ["secret", "set", ALIAS, "--stdin", "--json"],
    { stdin: VALUE },
  );
  check("secret set --stdin", set.exit === 0, { exit: set.exit });
  const approve = await ward(
    binary,
    here,
    checkout,
    ["profile", "approve", PROFILE, "--json"],
    { tty: true },
  );
  check("profile approve", approve.exit === 0, { exit: approve.exit });
  const ready = await ward(binary, here, checkout, ["check", "--json"]);
  check("check is ready", ready.exit === 0, { exit: ready.exit });
  const run = await ward(binary, here, checkout, ["run", PROFILE, "--json"]);
  const audit = await ward(binary, here, checkout, ["audit", "--json"]);
  const runError = (() => {
    try {
      return JSON.parse(run.stderr.trim().split("\n").pop() ?? "{}") as {
        code?: string;
      };
    } catch {
      return {};
    }
  })();
  report.run = {
    exit: run.exit,
    code: runError.code,
    stdoutBytes: run.stdout.length,
  };
  check(
    "run is admitted and refused at the destination, sending nothing",
    run.exit !== 0 &&
      typeof runError.code === "string" &&
      !run.stdout.includes(VALUE) &&
      !run.stderr.includes(VALUE),
    { exit: run.exit, code: runError.code },
  );
  const phases = (
    audit.stdout.match(/"phase"\s*:\s*"(admission|completion)"/g) ?? []
  )
    .map((match) => match.replace(/.*"(admission|completion)"/, "$1"))
    .sort();
  check(
    "audit records the admission and the completion of that one run",
    audit.exit === 0 && phases.join(",") === "admission,completion",
    { exit: audit.exit, phases },
  );
  for (const name of ["status", "doctor"] as const) {
    const result = await ward(binary, here, checkout, [name, "--json"]);
    check(name, result.exit === 0, { exit: result.exit });
  }
  const backup = join(tmpRoot, "backup.json");
  const made = await ward(
    binary,
    here,
    checkout,
    ["backup", "--output", backup, "--json"],
    { tty: true },
  );
  check("backup", made.exit === 0, { exit: made.exit });
  const second = join(tmpRoot, "checkout-second");
  mkdirSync(join(second, ".git"), { recursive: true });
  const restored = await ward(
    binary,
    homes.second,
    second,
    ["restore", "--input", backup, "--json"],
    { tty: true },
  );
  check(
    "restore into a second store, with only the passphrase",
    restored.exit === 0,
    { exit: restored.exit },
  );
  const gone = await ward(binary, here, checkout, ["unregister", "--json"], {
    tty: true,
  });
  check("unregister", gone.exit === 0, { exit: gone.exit });
  const refused = await ward(binary, here, checkout, [
    "run",
    PROFILE,
    "--json",
  ]);
  check("a run after unregister is refused", refused.exit !== 0, {
    exit: refused.exit,
  });

  // T05 on the packaged build: the whole root, and every output above.
  for (const [label, needle] of [
    ["secret value", VALUE],
    ["backup passphrase", PASSPHRASE],
  ] as const) {
    const found = containing(tmpRoot, needle);
    check(`no ${label} anywhere under the temporary root`, found.length === 0, {
      found: found.length,
    });
  }

  // The key provider on its own, through the real keychain: create, load, a
  // second create refused, delete.
  const probePath = buildExecutable({
    entry: join(ROOT, "test", "qualification", "keychain-roundtrip.ts"),
    outfile: join(tmpRoot, "keychain-roundtrip"),
  });
  const probe = Bun.spawnSync([probePath], {
    env: {
      PATH: SYSTEM_PATH,
      HOME: homes.second,
      WARD_QUALIFY_REAL_KEYCHAIN: "1",
    },
  });
  const probeResult = JSON.parse(
    probe.stdout.toString().trim().split("\n").pop() ?? "{}",
  ) as Record<string, unknown>;
  report.keychainRoundTrip = probeResult;
  check(
    "the key provider round trip on the real keychain",
    probe.exitCode === 0 &&
      probeResult.create === "ok" &&
      probeResult.load === "ok" &&
      probeResult.loadMatches === true &&
      probeResult.secondCreate !== "ok" &&
      probeResult.stillOriginal === true &&
      probeResult.deleted === true &&
      String(probeResult.service).startsWith("opum.ward.qualify-"),
    { exit: probe.exitCode },
  );
} catch (error) {
  failed = true;
  report.error = String(error);
} finally {
  await cleanup();
  const after = treeDigest(realWard);
  report.realWard = {
    path: realWard,
    before,
    after,
    unchanged: before.digest === after.digest,
  };
  if (before.digest !== after.digest) failed = true;
  rmSync(tmpRoot, { recursive: true, force: true });
  report.result = failed ? "FAILED" : "PASSED";
  console.log(JSON.stringify(report, null, 2));
  process.exit(failed ? 1 : 0);
}
