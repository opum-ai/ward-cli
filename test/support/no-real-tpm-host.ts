// Makes a test that reaches the REAL TPM host fail loudly (WCLI-21 3d-2b ii-b,
// the #352 reviewer's item A). The real host is the one a caller gets by
// leaving the device unset, or by naming /dev/tpmrm0: that device and this
// process's PATH, so a Linux machine with a TPM and tpm2-tools would run real
// tpm2_createprimary, tpm2_load and tpm2_getcap. A test names a fake host (an
// explicit other device) or a detect seam instead.
//
// A trip throws, but doctor folds a probe's exception into a quiet
// `tpm2_absent`, which would let a test pass green. So every trip is also
// recorded, and a global afterEach fails the test that caused it. A test that
// trips the guard ON PURPOSE takes the record with takeRealTpmHostTrips().
//
// Preloaded by bunfig.toml and imported by no-real-keychain.ts, which every
// test that can reach the adapters already imports first (test-isolation.test.ts
// enforces that), so running from outside the repository root is covered too.
// Compiled fixtures are separate processes and are not covered; each names its
// own host.
import { afterEach, mock } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tpm2Host } from "../../src/adapters/tpm2-tools.ts";

export const realTpmHostRefusal =
  "test processes must not reach the real TPM host";

// A host with no TPM at all, for an in-process command test that runs doctor on
// Linux (where the TPM probe is wired) without reaching the real device: the
// device is a path that does not exist, so detection reports tpm_absent.
export const noTpmHost: Tpm2Host = {
  path: "",
  device: join(tmpdir(), "ward-no-such-tpmrm0"),
};

const real = await import("../../src/adapters/tpm2-tools.ts");
// Captured before the mock replaces the module: the namespace's bindings are
// live, so reading them later would find the wrappers and recurse.
const snapshot = { ...real };
const originals = {
  detectTpm2: real.detectTpm2,
  detectTpm2ForTest: real.detectTpm2ForTest,
  diagnoseTpm2: real.diagnoseTpm2,
  diagnoseTpm2ForTest: real.diagnoseTpm2ForTest,
};

const trips: string[] = [];

export function takeRealTpmHostTrips(): readonly string[] {
  return trips.splice(0, trips.length);
}

function refuseRealHost(name: string, host: Tpm2Host | undefined): void {
  if (host?.device !== undefined && host.device !== real.tpmDevicePath) return;
  trips.push(name);
  throw new Error(realTpmHostRefusal);
}

mock.module("../../src/adapters/tpm2-tools.ts", () => ({
  ...snapshot,
  detectTpm2: (host?: Tpm2Host) => {
    refuseRealHost("detectTpm2", host);
    return originals.detectTpm2(host);
  },
  detectTpm2ForTest: (...args: Parameters<typeof real.detectTpm2ForTest>) => {
    refuseRealHost("detectTpm2ForTest", args[0]);
    return originals.detectTpm2ForTest(...args);
  },
  diagnoseTpm2: (...args: Parameters<typeof real.diagnoseTpm2>) => {
    refuseRealHost("diagnoseTpm2", args[0]);
    return originals.diagnoseTpm2(...args);
  },
  diagnoseTpm2ForTest: (
    ...args: Parameters<typeof real.diagnoseTpm2ForTest>
  ) => {
    refuseRealHost("diagnoseTpm2ForTest", args[0]);
    return originals.diagnoseTpm2ForTest(...args);
  },
}));

afterEach(() => {
  const seen = takeRealTpmHostTrips();
  if (seen.length > 0)
    throw new Error(`${realTpmHostRefusal} (${seen.join(", ")})`);
});
