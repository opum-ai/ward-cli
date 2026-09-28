// A separate process for test/setup.test.ts (WCLI-20): the explicit-exit
// contract must be observed in a real process, where a pending native
// credential-store call would keep the event loop alive after its bound
// expired. The provider's check read succeeds and its write lands, but the
// confirmation read hangs; the bound is 100 ms; the process must exit on
// its own with the indeterminate envelope.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../../src/adapters/keychain.ts";
import { runWard } from "../../src/cli/main.ts";
import { MemoryKeychain } from "../support/memory-keychain.ts";

const directory = join(mkdtempSync(join(tmpdir(), "ward-exit-")), ".ward");
const keychain = new MemoryKeychain();
keychain.mode = "hang-after-write";
const keyProvider = createKeychainKeyProvider({
  service: "opum.ward.exit",
  timeoutMs: 100,
  entry: keychain.entry,
});
// A pending native credential-store call would hold the event loop open on
// its own; a leaked interval stands in for that handle, so the probe only
// exits when runWard's explicit-exit contract is honored.
setInterval(() => {}, 60_000);
const result = await runWard(["setup"], {
  wardDirectory: directory,
  keyProvider,
});
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
if (result.exitExplicitly) process.exit(result.exitCode);
process.exitCode = result.exitCode;
