// Makes a test that reaches the REAL TPM host fail loudly (WCLI-21 3d-2b ii-b,
// the #352 reviewer's item A). The real host is the one a caller gets by
// leaving the device unset: /dev/tpmrm0 and this process's PATH, so a Linux
// machine with a TPM and tpm2-tools would run real tpm2_createprimary,
// tpm2_load and tpm2_getcap. A test names a fake host (an explicit device) or
// a detect seam instead. Preloaded by bunfig.toml; compiled fixtures are
// separate processes and are not covered, and each names its own host.
import { mock } from "bun:test";
import type { Tpm2Host } from "../../src/adapters/tpm2-tools.ts";

export const realTpmHostRefusal =
  "test processes must not reach the real TPM host";

const real = await import("../../src/adapters/tpm2-tools.ts");

function refuseRealHost(host: Tpm2Host | undefined): void {
  if (host === undefined || host.device === undefined)
    throw new Error(realTpmHostRefusal);
}

mock.module("../../src/adapters/tpm2-tools.ts", () => ({
  ...real,
  detectTpm2: (host?: Tpm2Host) => {
    refuseRealHost(host);
    return real.detectTpm2(host);
  },
  diagnoseTpm2: (...args: Parameters<typeof real.diagnoseTpm2>) => {
    refuseRealHost(args[0]);
    return real.diagnoseTpm2(...args);
  },
}));
