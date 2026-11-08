// A separate process for test/setup.test.ts (WCLI-20): run `ward setup`
// with a file-backed credential store and block at a chosen stage, so the
// test can kill the process and rerun setup against the surviving files.
// Modes:
//   before-write <store-dir> <ward-dir>  block inside the key write, before
//                                        anything is stored
//   after-write <store-dir> <ward-dir>   store the key, then block before
//                                        the write confirms
//   plain <store-dir> <ward-dir>         run setup normally and report
//   lock-hold <anything> <ward-dir>      hold the setup lock with flock(2)
//                                        and block until killed
// The key survives the kill because the store is files on disk.
import { dlopen } from "bun:ffi";
import { constants as fileConstants, openSync, writeSync } from "node:fs";
import { join } from "node:path";
import { prepareVaultDirectory } from "../../src/adapters/sqlite-vault-store.ts";
import { createKeychainKeyProvider } from "../../src/adapters/keychain.ts";
import { runWard } from "../../src/cli/main.ts";
import { FileKeychain } from "../support/file-keychain.ts";

const [mode, storeDirectory, wardDirectory] = process.argv.slice(2);
if (
  mode === undefined ||
  storeDirectory === undefined ||
  wardDirectory === undefined
)
  throw new Error("usage: <mode> <store-dir> <ward-dir>");

if (mode === "lock-hold") {
  prepareVaultDirectory(wardDirectory, process.getuid?.());
  const fd = openSync(
    join(wardDirectory, "setup.lock"),
    fileConstants.O_CREAT |
      fileConstants.O_RDWR |
      fileConstants.O_TRUNC |
      fileConstants.O_NOFOLLOW,
    0o600,
  );
  const flock = dlopen(
    process.platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : "libc.so.6",
    {
      flock: { args: ["int", "int"], returns: "int" },
    },
  ).symbols.flock as (fd: number, operation: number) => number;
  if (flock(fd, 2 | 4) !== 0) throw new Error("could not take the lock");
  writeSync(fd, `${process.pid}\n`);
  writeSync(1, "ready\n");
  blockForever();
}

const keychain = new FileKeychain(storeDirectory);
const provider =
  mode === "plain"
    ? createKeychainKeyProvider({
        service: "opum.ward.stage",
        timeoutMs: 60_000,
        entry: keychain.entry,
      })
    : createKeychainKeyProvider({
        service: "opum.ward.stage",
        timeoutMs: 60_000,
        entry: (service, account) => {
          const entry = keychain.entry(service, account);
          return {
            getSecret: entry.getSecret,
            setSecret: async (secret) => {
              if (mode === "before-write") {
                writeSync(1, "ready\n");
                blockForever();
              }
              await entry.setSecret(secret);
              if (mode === "after-write") {
                writeSync(1, "ready\n");
                blockForever();
              }
            },
          };
        },
      });

function blockForever(): never {
  const cell = new Int32Array(new SharedArrayBuffer(4));
  for (;;) Atomics.wait(cell, 0, 0);
}

const result = await runWard(["setup"], {
  wardDirectory,
  keyProvider: provider,
});
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
if (result.exitExplicitly) process.exit(result.exitCode);
process.exitCode = result.exitCode;
