// Real-keychain qualification probe for the Keychain adapter (WCLI-5
// criterion 2, and the macOS half of T26 later). NOT part of `bun test`:
// the file name has no .test.ts suffix, and it refuses to run without
// WARD_QUALIFY_REAL_KEYCHAIN=1. It writes one throwaway item to the
// developer's real login keychain, so run it only with their explicit
// authorisation. It uses a fresh opum.ward.probe-* service, never the
// production opum.ward service, prints no key bytes, and deletes the item.
//
//   bun -e 'import("./scripts/build.ts").then((m) => m.buildExecutable({
//     entry: "test/qualification/keychain-roundtrip.ts",
//     outfile: "<scratch>/keychain-roundtrip" }))'
//   WARD_QUALIFY_REAL_KEYCHAIN=1 <scratch>/keychain-roundtrip
import "../../src/cli/guard.ts";
import { randomBytes, randomUUID } from "node:crypto";
import { AsyncEntry } from "@napi-rs/keyring";
import { createKeychainKeyProvider } from "../../src/adapters/keychain.ts";
import { WardError } from "../../src/contract/errors.ts";
import { generateVaultKey } from "../../src/domain/envelope.ts";

if (process.env.WARD_QUALIFY_REAL_KEYCHAIN !== "1") {
  process.stderr.write("refusing: set WARD_QUALIFY_REAL_KEYCHAIN=1\n");
  process.exit(2);
}

const service = `opum.ward.probe-${randomBytes(4).toString("hex")}`;
const vaultId = randomUUID();
const provider = createKeychainKeyProvider({ service });

async function outcome(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
    return "ok";
  } catch (error) {
    return error instanceof WardError ? error.code : "non-ward-error";
  }
}

const key = generateVaultKey();
const expected = [...key];
const matches = (candidate: Uint8Array) =>
  candidate.length === expected.length &&
  candidate.every((byte, index) => byte === expected[index]);

const result: Record<string, unknown> = { service };
try {
  result.loadBefore = await outcome(() => provider.load(vaultId));
  let started = performance.now();
  result.create = await outcome(() => provider.create(vaultId, key));
  result.createMs = Math.round(performance.now() - started);
  started = performance.now();
  let loaded: Uint8Array | undefined;
  result.load = await outcome(async () => {
    loaded = await provider.load(vaultId);
  });
  result.loadMs = Math.round(performance.now() - started);
  result.loadMatches = loaded !== undefined && matches(loaded);
  result.secondCreate = await outcome(() =>
    provider.create(vaultId, generateVaultKey()),
  );
  result.stillOriginal = matches(await provider.load(vaultId));
} finally {
  result.deleted = await new AsyncEntry(
    service,
    `vault-${vaultId}`,
  ).deleteCredential();
  result.loadAfterDelete = await outcome(() => provider.load(vaultId));
}
process.stdout.write(`${JSON.stringify(result)}\n`);
