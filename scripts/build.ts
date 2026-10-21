// Builds the ward executable, the only artifact that may be installed as
// `ward` (WCLI-16). Launched through `bun`, Ward would read the working
// directory's bunfig.toml and .env before its own code runs: a planted
// preload executes with argv in reach, and .env lands in process.env. Ward
// runs inside repositories an agent can edit, so every runtime autoload is
// switched off here, including the two Bun already defaults off, so that a
// change of default cannot silently turn one back on.
//
// Not closed by these flags, measured on bun 1.3.14: BUN_OPTIONS in the
// inherited environment still preloads code, and BUN_BE_BUN=1 turns the
// executable into the full bun CLI (WCLI-19).
import { join } from "node:path";

const root = join(import.meta.dir, "..");

export const entry = join(root, "src", "cli", "ward.ts");
export const outfile = join(root, "dist", "ward");

export const hardeningFlags = [
  "--no-compile-autoload-dotenv",
  "--no-compile-autoload-bunfig",
  "--no-compile-autoload-tsconfig",
  "--no-compile-autoload-package-json",
] as const;

export const productionService = "opum.ward";
// The qualification build's service namespace. It must never equal the
// production service, so a qualification run cannot reach the real item.
export const qualifyServicePrefix = "opum.ward.qualify-";
export const qualifyOutfile = join(root, "dist", "ward-qualify");

// The compile-time definition both builds pass, so a test measures the same
// flag that ships.
export function serviceDefine(service: string): string {
  return `WARD_KEYCHAIN_SERVICE=${JSON.stringify(service)}`;
}

// The guard for anything that deletes a credential-store item by service name:
// only a name under the qualification prefix, with a non-empty suffix, is
// accepted, so the production service can never be named by a caller.
export function assertQualifyService(name: string): void {
  if (
    !name.startsWith(qualifyServicePrefix) ||
    name.length === qualifyServicePrefix.length
  )
    throw new Error(
      `refusing to touch credential-store service ${JSON.stringify(name)}: only a name beginning ${qualifyServicePrefix} is allowed`,
    );
}

export function newQualifyService(): string {
  const suffix = [...crypto.getRandomValues(new Uint8Array(4))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `${qualifyServicePrefix}${suffix}`;
}

// The argv buildExecutable runs, exposed so a test can assert what is
// actually passed to `bun build` rather than what the list above declares.
// The credential-store service is always defined at compile time (see
// src/adapters/keychain.ts): the production service unless a qualification
// service is named, and a qualification service must sit under its own prefix.
export function buildCommand(options: {
  entry: string;
  outfile: string;
  service?: string;
}): string[] {
  const service = options.service ?? productionService;
  if (
    service !== productionService &&
    !service.startsWith(qualifyServicePrefix)
  )
    throw new Error(
      `a build's credential-store service is ${productionService} or begins ${qualifyServicePrefix}`,
    );
  if (/[^A-Za-z0-9._-]/.test(service))
    throw new Error("a credential-store service is letters, digits and . _ -");
  return [
    process.execPath,
    "build",
    "--compile",
    ...hardeningFlags,
    "--define",
    serviceDefine(service),
    options.entry,
    "--outfile",
    options.outfile,
  ];
}

// Tests build their executables and a probe entry through this same
// function, so the flags they measure are the flags that ship.
export function buildExecutable(options: {
  entry: string;
  outfile: string;
  service?: string;
}): string {
  const run = Bun.spawnSync(buildCommand(options), { cwd: root });
  if (run.exitCode !== 0)
    throw new Error(
      `bun build exited ${run.exitCode}\n${run.stderr.toString()}`,
    );
  return options.outfile;
}

// `bun scripts/build.ts` builds the shipped executable. `--qualify` builds the
// qualification executable beside it, under a fresh service of its own, and
// prints the service so a run can name it and clean up after itself.
if (import.meta.main) {
  if (process.argv.includes("--qualify")) {
    const service = newQualifyService();
    buildExecutable({ entry, outfile: qualifyOutfile, service });
    console.log(JSON.stringify({ outfile: qualifyOutfile, service }));
  } else buildExecutable({ entry, outfile });
}
