// MUTANT REGISTER for slice 3d-1b (WCLI-21), written and committed BEFORE any
// run. Each line is a one-site mutation and the tests predicted to go red, by
// the first words of their titles; every other test in the file must stay
// green. Run against a saved copy of the source, restored after each. A
// prediction is never edited after its run: the observation is annotated
// beside it.
//   K1  the router takes the first holder without probing the rest -> "two holders refuse as ambiguous"
//   K2  the ambiguous refusal drops the store names                  -> "two holders refuse as ambiguous"
//   K3  load goes to the init backend, not the holder                -> "an existing vault keeps the backend that holds its key"
//   K4  a probe that fails reads as not held (a fallback)            -> "an unavailable holder refuses by name"
//   K5  a probed key of a refused holder is not zeroed               -> "two holders refuse as ambiguous"
//   K6  linux initialises on the keychain backend                    -> "linux initialises on TPM2 when detection passes"
//   K7  linux falls back to the keychain when detection fails        -> "linux with no usable TPM refuses and creates nothing"
//   K8  linux with no holder passes the keychain's unsupported       -> "linux with no sealed key is a missing key"
//   K9  prepareDirectory repairs a wider directory to 0700           -> "a pre-existing directory that is not 0700 is refused and left alone"
//   K10 the blob directory drops the vault id segment                -> "the blob directory is <ward>/tpm/<vaultId>"
//   K11 holdsSealedKey looks for the public blob                     -> "a lone private blob counts as held and a lone public blob does not"
//   K12 main.ts keeps one createKeychainKeyProvider site             -> "no command composes the keychain provider directly"
//   K13 a wired command ignores keySelection                         -> "ward setup on linux seals through the selected backend"
//   K14 abandonedCall ignores a flushFailure of tool_timeout         -> test/tpm2-provider.test.ts "a timed-out flush"
//   K15 translate drops the path                                     -> test/tpm2-provider.test.ts "a Tpm2Error rides on the WardError"
//   K16 a non-Tpm2Error wrap carries String(error) as detail         -> test/tpm2-provider.test.ts "a non-Tpm2Error from the unseal", test/tpm2-tools.test.ts "a non-Tpm2Error unseal failure keeps flushFailure"
//   K17 the mid-seal list drops tool_failed                          -> test/tpm2-provider.test.ts "a tool failure mid-seal is unconfirmed"
//   K18 the mid-seal list drops tool_output_too_large                -> test/tpm2-provider.test.ts "a tool failure mid-seal is unconfirmed"
//   K19 observeKey reads one tpm_* code as a throw                   -> test/reporting.test.ts "every TPM code is reported as an unavailable key"
//   K20 a wired command whose tool timed out does not exit explicitly -> "a ward command whose tpm2 tool times out exits"
// OBSERVED (annotated after the runs; the predictions above are unchanged).
// Every mutant went red on its predicted tests; none survived. Extras, not predicted:
//   K3  also reddened "a probe that already read the key is not read twice"
//   K4  also reddened "another platform is refused as an unsupported store" (win32 reads as not held)
//   K6  also reddened the four directory tests, "ward setup on linux seals..." and "a ward command whose tpm2 tool times out exits"
//   K8  also reddened "no holder is a missing key, and load never creates one", "ward setup on linux seals..." and "a ward command whose tpm2 tool times out exits"
//   K10 also reddened "linux initialises on TPM2...", "a fresh path is created 0700", "a pre-existing 0700 directory is accepted", "a lone private blob on linux is incomplete..." and "ward setup on linux seals..."
//   K11 also reddened "a lone private blob on linux is incomplete, never missing and never re-initialised"
//   K12 also reddened "ward setup on linux seals..." and "a ward command whose tpm2 tool times out exits"
//   K13 also reddened "a ward command whose tpm2 tool times out exits"
//   K19 also reddened "a TPM refusal is reported as an unavailable key" (it lists tool_untrusted)
// Run 2026-11-15 against the 3d-1b working tree, bun 1.3.14.
// MUTANT REGISTER, DEC-262 (a23) round, written and committed BEFORE any run of
// these mutants. Same rules as above.
//   H1  the Linux init refusal drops the Secret Service note        -> "the Linux init refusal says Secret Service is not implemented"
//   H2  the note's text suggests a weaker store                     -> "the Linux init refusal says Secret Service is not implemented"
//   H3  the error envelope drops the notes                          -> "the Linux init refusal says Secret Service is not implemented"
//   H4  --json mode writes the human sentence                       -> "under --json the leak warning is exactly one line", "the leak warning carries no path or handle"
//   H5  human mode writes the JSON line                             -> "in human mode the leak warning is a sentence"
//   H6  the --json line carries an extra field                      -> "under --json the leak warning is exactly one line", "the leak warning carries no path or handle"
//   H7  the warning is appended to stdout instead of stderr         -> "the warning is on stderr and the stdout envelope is untouched"
//   H8  a failing command loses the warning                         -> "a warning before a failing command still reaches stderr"
//   H9  the output-contract sentence is deleted from ADR 0028       -> "the output contract documents the stderr warning"
//   H10 the warning is appended AFTER the error envelope (order swapped) -> "a warning before a failing command still reaches stderr"
// MUTANT REGISTER, round 4 (the #341 round-3 verdict), written BEFORE any run of these. Bun 1.3.14 recorded on each observation.
//   C1  toolsVersion does not call onAbandon on a timed-out --version          -> test/tpm2-tools.test.ts "a tpm2-tools version probe that times out still calls onAbandon"
//   C2  the probe's flush phase loses the sink's OR (told never sets explicit)  -> "a ward command whose tpm2 tool times out exits" (the "flush exit=0 explicit=true" line)
//   C3  the flush-after-good-unseal onAbandon call is removed from unsealKey    -> "a ward command whose tpm2 tool times out exits", test/tpm2-tools.test.ts "a flush timeout after a good unseal calls onAbandon..."
// OBSERVED for round 4 (bun 1.3.14, 2026-11-17 read from `date -u`; predictions unchanged). None survived. C1 and C3 went red on exactly their predicted tests. C2 also reddened the two round-3 sink tests ("a good unseal whose flush timed out..." and "the same abandon survives..."), since they share the same OR.
// MUTANT REGISTER, round 3 (the #341 round-2 verdict), written BEFORE any run of these. Bun is recorded on each observation.
//   A1  the runWard sink does not OR the abandon into a success result        -> "a good unseal whose flush timed out asks for an explicit exit on a root that never read the provider flag"
//   A2  the runWard sink is not applied on the failure path                   -> "the same abandon survives a later non-TPM failure"
//   A3  the provider's abandon does not call options.onAbandon                -> "a good unseal whose flush timed out asks for ... never read the provider flag", "the same abandon survives a later non-TPM failure"
//   A4  the sink sets the flag even with no abandon (always true)             -> "a good unseal without an abandon does not ask for one"
//   A5  a sentence of the code's human warning drifts from the concept        -> "the stderr contract concept pins the warning forms"
//   (nit 3, JSON mode from parsed flags, has no test: no command reaches a differing argv without a project, so it is a code-only change.)
// OBSERVED for round 3 (bun 1.3.14, 2026-11-17; predictions unchanged). None survived. Differences: A1 removes the OR from the one `told` helper, so it also reddened "the same abandon survives a later non-TPM failure"; A4 also reddened "a refusal that is not a timeout does not ask for one". A2, A3, A5 went red on exactly their predicted tests.
// MUTANT REGISTER, round 2 of the #341 review (B1-B4 and the nits), written and committed BEFORE any run of these.
//   Q1  TpmKeyError.abandoned ignores a flushFailure of tool_timeout        -> "a propagated flush timeout still asks for an explicit exit"
//   Q2  runWard's catch ignores the TpmKeyError abandoned mark              -> "a propagated tool timeout still asks for an explicit exit", "a propagating ward command whose tpm2 tool times out exits"
//   Q3  unsealKey does not call onAbandon on a success-path flush timeout   -> test/tpm2-tools.test.ts "a flush timeout after a good unseal", test/tpm2-provider.test.ts "a flush timeout after a good unseal marks the call abandoned"
//   Q4  named() rebuilds a plain WardError (drops the subclass and .tpm2)   -> "a probe that passes and a load that refuses carries the store and .tpm2"
//   Q5  the final provider.load is not named                                -> "a probe that passes and a load that refuses carries the store and .tpm2"
//   Q6  named() also tags vault_key_store_unsupported                       -> "another platform is refused as an unsupported store"
//   Q7  the init note is added only for tpm_absent                          -> "the init note reaches every detection refusal"
//   Q8  a load-path refusal also carries the init note                      -> "the init note does not print on a load refusal"
//   Q9  no per-command de-duplication of the warning line                   -> "a repeated warning is one line per command"
//   Q10 the router does not zero a probed key when a later probe throws     -> "a key-returning probe followed by a throwing probe zeroes the key"
//   S1  a sentence of the stderr-contract concept is deleted               -> "the stderr contract concept pins the warning forms"
//   Q11 the selection spread lets a seam replace directoryFor               -> "a seam cannot redirect the blob directory"
// OBSERVED for round 2 (the Q runs recorded no version at the time (2026-11-15, taken as the 1.3.14 the K and H rounds record on that date); annotated after the runs; predictions unchanged). None survived. Differences from the predictions:
//   S1  went red on exactly its predicted test (run 2026-11-17, bun 1.3.14; an earlier note here said 1.4.2, which was the quest binary's runtime, not this repo's).
//   Q3  went red only on test/tpm2-tools.test.ts "a flush timeout after a good unseal calls onAbandon...": the provider test
//       supplies its own unseal that calls onAbandon, so it cannot see the real unseal's call (it pins the provider's reaction).
//   Q2  also reddened "a propagated flush timeout still asks for an explicit exit"; the probe test is titled
//       "a ward command whose tpm2 tool times out exits" (it now covers the propagating backup too).
//   Q4  also reddened both propagated-exit tests and the probe test (a plain WardError has no abandoned mark).
//   Q10 also reddened "two holders refuse as ambiguous, naming both" (it checks the stray key is zeroed).
//   Q1, Q5-Q9, Q11 went red on exactly their predicted tests.
// OBSERVED for the (a23) round (annotated after the runs; predictions unchanged). None survived.
// Extras, not predicted: H4 also reddened "the warning is on stderr and the stdout envelope is untouched" and
// "a warning before a failing command still reaches stderr"; H5 also reddened those two and "under --json the
// leak warning is exactly one line"; H6 also reddened those two runWard tests; H7 also reddened
// "a warning before a failing command still reaches stderr". H10 went red on exactly its predicted test.
// Run 2026-11-15, bun 1.3.14.
// The mock is imported first (test-isolation.test.ts).
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createRoutingKeyProvider,
  formatKeyWarning,
  type KeyBackend,
  selectKeyProvider,
  tpm2Backend,
  tpm2DirectoryFor,
} from "../src/adapters/key-backend.ts";
import {
  holdsSealedKey,
  preparePrivateDirectory,
  sealedPrivateName,
  sealedPublicName,
  Tpm2Error,
  type Tpm2Presence,
  tpm2ErrorCodes,
} from "../src/adapters/tpm2-tools.ts";
import { TpmKeyError } from "../src/adapters/tpm2-provider.ts";
import type { KeyProvider } from "../src/application/key-provider.ts";
import { runWard } from "../src/cli/main.ts";
import { errorEnvelope, WardError } from "../src/contract/errors.ts";

const VAULT_ID = "3f1c2b7e-9a4d-4e6f-8b21-5c7d9e0a1b2c";
const root = mkdtempSync(join(tmpdir(), "ward-key-backend-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let cases = 0;
const fresh = () => mkdtempSync(join(root, `case-${++cases}-`));
const synthetic = (byte = 0x5a) => new Uint8Array(32).fill(byte);

async function caught(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function stubProvider(
  load: () => Promise<Uint8Array>,
  created: string[] = [],
  name = "stub",
): KeyProvider {
  return {
    load,
    create: async () => {
      created.push(name);
    },
  };
}

function backend(
  name: KeyBackend["name"],
  probe: KeyBackend["probe"],
  provider: KeyProvider = stubProvider(async () => synthetic(0x11)),
): KeyBackend {
  return {
    name,
    id: name === "TPM2" ? "tpm2" : "macos-keychain",
    provider,
    probe,
  };
}

describe("the router says which store it settled on (DEC-262 a24)", () => {
  const held = async () => ({ held: true as const });
  const notHeld = async () => ({ held: false as const });

  test("the holder of the key is the backend in use, even when initialisation would pick another", async () => {
    const tpm = backend("TPM2", held);
    const keychain = backend("macOS Keychain", notHeld);
    const router = createRoutingKeyProvider({
      backends: [keychain, tpm],
      initialisation: () => keychain,
    });
    await router.load(VAULT_ID);
    expect(router.backend?.()).toBe("tpm2");
  });

  test("before any load, or when no store holds the key, it is where a new key would go", async () => {
    const tpm = backend("TPM2", notHeld);
    const router = createRoutingKeyProvider({
      backends: [tpm],
      initialisation: () => tpm,
    });
    expect(router.backend?.()).toBe("tpm2");
    await router.load(VAULT_ID).catch(() => undefined);
    expect(router.backend?.()).toBe("tpm2");
  });

  test("two holders leave no backend in use", async () => {
    const router = createRoutingKeyProvider({
      backends: [backend("macOS Keychain", held), backend("TPM2", held)],
      initialisation: () => backend("TPM2", held),
    });
    await router.load(VAULT_ID).catch(() => undefined);
    expect(router.backend?.()).toBeNull();
  });

  test("a host that can take no new key reports none", () => {
    const router = createRoutingKeyProvider({
      backends: [backend("TPM2", notHeld)],
      initialisation: () => {
        throw new Tpm2Error("tpm_absent");
      },
    });
    expect(router.backend?.()).toBeNull();
  });

  test("a later load does not inherit an earlier load's store", async () => {
    let tpmHolds = true;
    const tpm = backend("TPM2", async () => ({ held: tpmHolds }));
    const keychain = backend("macOS Keychain", notHeld);
    const router = createRoutingKeyProvider({
      backends: [tpm, keychain],
      initialisation: () => keychain,
    });
    await router.load(VAULT_ID);
    expect(router.backend?.()).toBe("tpm2");
    tpmHolds = false;
    await router.load(VAULT_ID).catch(() => undefined);
    expect(router.backend?.()).toBe("macos-keychain");
  });
});

describe("the router picks by presence of the key itself", () => {
  test("an existing vault keeps the backend that holds its key", async () => {
    const loads: string[] = [];
    const tpm = backend(
      "TPM2",
      async () => ({ held: true }),
      stubProvider(async () => {
        loads.push("TPM2");
        return synthetic(0x22);
      }),
    );
    const keychain = backend("macOS Keychain", async () => ({ held: false }));
    const router = createRoutingKeyProvider({
      backends: [keychain, tpm],
      // Initialisation would choose the keychain; a holder wins over it.
      initialisation: () => keychain,
    });
    expect(Array.from(await router.load(VAULT_ID))).toEqual(
      Array.from(synthetic(0x22)),
    );
    expect(loads).toEqual(["TPM2"]);
  });

  test("a probe that already read the key is not read twice", async () => {
    let loads = 0;
    const keychain = backend(
      "macOS Keychain",
      async () => ({ held: true, key: synthetic(0x33) }),
      stubProvider(async () => {
        loads += 1;
        return synthetic();
      }),
    );
    const router = createRoutingKeyProvider({
      backends: [keychain],
      initialisation: () => keychain,
    });
    expect(Array.from(await router.load(VAULT_ID))).toEqual(
      Array.from(synthetic(0x33)),
    );
    expect(loads).toBe(0);
  });

  test("two holders refuse as ambiguous, naming both", async () => {
    const stray = synthetic(0x44);
    const router = createRoutingKeyProvider({
      backends: [
        backend("macOS Keychain", async () => ({ held: true, key: stray })),
        backend("TPM2", async () => ({ held: true })),
      ],
      initialisation: () => {
        throw new Error("never");
      },
    });
    const error = await caught(() => router.load(VAULT_ID));
    expect(error).toBeInstanceOf(WardError);
    expect((error as WardError).code).toBe("vault_key_ambiguous");
    expect((error as WardError).stores).toEqual(["macOS Keychain", "TPM2"]);
    expect(errorEnvelope(error as WardError).message).toContain(
      "stores: macOS Keychain, TPM2",
    );
    // A key read from a refused holder is not left in memory.
    expect(Array.from(stray)).toEqual(new Array(32).fill(0));
  });

  test("an unavailable holder refuses by name, with no fallback", async () => {
    const other = backend("TPM2", async () => ({ held: true }));
    const unavailable = backend("macOS Keychain", async () => {
      throw new WardError("vault_key_unavailable");
    });
    const router = createRoutingKeyProvider({
      backends: [unavailable, other],
      initialisation: () => other,
    });
    const error = await caught(() => router.load(VAULT_ID));
    expect((error as WardError).code).toBe("vault_key_unavailable");
    expect((error as WardError).stores).toEqual(["macOS Keychain"]);
  });

  test("no holder is a missing key, and load never creates one", async () => {
    const created: string[] = [];
    const only = backend(
      "TPM2",
      async () => ({ held: false }),
      stubProvider(async () => synthetic(), created),
    );
    const router = createRoutingKeyProvider({
      backends: [only],
      initialisation: () => only,
    });
    const error = await caught(() => router.load(VAULT_ID));
    expect((error as WardError).code).toBe("vault_key_missing");
    expect(created).toEqual([]);
  });

  test("create goes to the initialisation backend", async () => {
    const created: string[] = [];
    const a = backend(
      "macOS Keychain",
      async () => ({ held: false }),
      stubProvider(async () => synthetic(), created, "a"),
    );
    const b = backend(
      "TPM2",
      async () => ({ held: false }),
      stubProvider(async () => synthetic(), created, "b"),
    );
    await createRoutingKeyProvider({
      backends: [a, b],
      initialisation: () => b,
    }).create(VAULT_ID, synthetic());
    expect(created).toEqual(["b"]);
  });
});

const presence = { device: "/dev/null", tools: {} } as unknown as Tpm2Presence;

// A seal that leaves what the real one leaves: the private directory, and a
// blob pair in it.
function fakeSeal(sealedIn: string[]) {
  return async (
    _presence: Tpm2Presence,
    _key: Uint8Array,
    directory: string,
  ) => {
    preparePrivateDirectory(directory);
    writeFileSync(join(directory, sealedPublicName), "pub");
    writeFileSync(join(directory, sealedPrivateName), "priv");
    sealedIn.push(directory);
    return { publicBlob: "a", privateBlob: "b" };
  };
}

function linux(ward: string, extra: Record<string, unknown> = {}) {
  const sealedIn: string[] = [];
  const provider = selectKeyProvider(ward, {
    platform: "linux",
    keychain: stubProvider(async () => {
      throw new Error("the keychain is never read on linux");
    }),
    tpm2: {
      detect: () => presence,
      seal: fakeSeal(sealedIn),
      unseal: async () => synthetic(),
      ...extra,
    },
  });
  return { provider, sealedIn };
}

describe("platform selection", () => {
  test("darwin uses the keychain only", async () => {
    const provider = selectKeyProvider(fresh(), {
      platform: "darwin",
      keychain: stubProvider(async () => synthetic(0x66)),
    });
    expect(Array.from(await provider.load(VAULT_ID))).toEqual(
      Array.from(synthetic(0x66)),
    );
  });

  test("linux initialises on TPM2 when detection passes", async () => {
    const ward = fresh();
    const { provider, sealedIn } = linux(ward);
    await provider.create(VAULT_ID, synthetic());
    expect(sealedIn).toEqual([join(ward, "tpm", VAULT_ID)]);
  });

  test("linux with no usable TPM refuses and creates nothing", async () => {
    const ward = fresh();
    const { provider, sealedIn } = linux(ward, {
      detect: () => {
        throw new Tpm2Error("tpm_absent");
      },
    });
    const error = await caught(() => provider.create(VAULT_ID, synthetic()));
    expect((error as WardError).code).toBe("tpm_absent");
    expect(sealedIn).toEqual([]);
    expect(existsSync(join(ward, "tpm"))).toBe(false);
  });

  test("linux with no sealed key is a missing key", async () => {
    const { provider } = linux(fresh());
    const error = await caught(() => provider.load(VAULT_ID));
    expect((error as WardError).code).toBe("vault_key_missing");
  });

  test("linux after init keeps the TPM2 key by presence", async () => {
    const { provider } = linux(fresh());
    await provider.create(VAULT_ID, synthetic());
    expect(Array.from(await provider.load(VAULT_ID))).toEqual(
      Array.from(synthetic()),
    );
  });

  test("another platform is refused as an unsupported store", async () => {
    const provider = selectKeyProvider(fresh(), { platform: "win32" });
    const error = await caught(() => provider.load(VAULT_ID));
    expect((error as WardError).code).toBe("vault_key_store_unsupported");
    // No store is named: this platform never had one.
    expect((error as WardError).stores).toEqual([]);
    expect(errorEnvelope(error as WardError).message).not.toContain("store:");
  });
});

const modeOf = (path: string) => statSync(path).mode & 0o777;

describe("the blob directory", () => {
  test("the blob directory is <ward>/tpm/<vaultId>", () => {
    expect(tpm2DirectoryFor("/w")(VAULT_ID)).toBe(`/w/tpm/${VAULT_ID}`);
    expect(() => tpm2DirectoryFor("/w")("../x")).toThrow(WardError);
  });

  test("a fresh path is created 0700", async () => {
    const ward = fresh();
    chmodSync(ward, 0o700);
    await linux(ward).provider.create(VAULT_ID, synthetic());
    expect(modeOf(join(ward, "tpm"))).toBe(0o700);
    expect(modeOf(join(ward, "tpm", VAULT_ID))).toBe(0o700);
  });

  test("a pre-existing 0700 directory is accepted", async () => {
    const ward = fresh();
    chmodSync(ward, 0o700);
    mkdirSync(join(ward, "tpm"), { mode: 0o700 });
    await linux(ward).provider.create(VAULT_ID, synthetic());
    expect(modeOf(join(ward, "tpm", VAULT_ID))).toBe(0o700);
  });

  test("a pre-existing directory that is not 0700 is refused and left alone", async () => {
    const ward = fresh();
    chmodSync(ward, 0o700);
    mkdirSync(join(ward, "tpm"), { mode: 0o755 });
    chmodSync(join(ward, "tpm"), 0o755);
    const { provider, sealedIn } = linux(ward);
    const error = await caught(() => provider.create(VAULT_ID, synthetic()));
    expect((error as WardError).code).toBe("tpm_blob_not_user_private");
    expect(modeOf(join(ward, "tpm"))).toBe(0o755);
    expect(sealedIn).toEqual([]);
  });

  test("a lone private blob counts as held and a lone public blob does not", () => {
    const directory = fresh();
    expect(holdsSealedKey(directory)).toBe(false);
    writeFileSync(join(directory, sealedPublicName), "pub");
    expect(holdsSealedKey(directory)).toBe(false);
    rmSync(join(directory, sealedPublicName));
    writeFileSync(join(directory, sealedPrivateName), "priv");
    expect(holdsSealedKey(directory)).toBe(true);
  });

  test("a lone private blob on linux is incomplete, never missing and never re-initialised", async () => {
    const ward = fresh();
    chmodSync(ward, 0o700);
    const directory = join(ward, "tpm", VAULT_ID);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    writeFileSync(join(directory, sealedPrivateName), "priv");
    // The real unseal path, no stub: withLoadedKey's own check refuses a lone
    // private blob before any tool runs.
    const { provider } = linux(ward, { unseal: undefined });
    const error = await caught(() => provider.load(VAULT_ID));
    expect((error as WardError).code).toBe("tpm_key_incomplete");
  });
});

describe("the commands are wired to the selection", () => {
  test("no command composes the keychain provider directly", () => {
    const source = readFileSync(
      join(import.meta.dir, "..", "src", "cli", "main.ts"),
      "utf8",
    );
    expect(source).not.toContain("createKeychainKeyProvider");
    expect(
      source.match(/selectKeyProvider\(directory, options\.keySelection\)/g)
        ?.length,
    ).toBe(12);
  });

  test("ward setup on linux seals through the selected backend", async () => {
    const ward = join(fresh(), ".ward");
    const sealedIn: string[] = [];
    const result = await runWard(["setup", "--json"], {
      wardDirectory: ward,
      keySelection: {
        platform: "linux",
        keychain: stubProvider(async () => {
          throw new Error("never");
        }),
        tpm2: {
          detect: () => presence,
          seal: fakeSeal(sealedIn),
          unseal: async () => synthetic(),
        },
      },
    });
    expect(result.exitCode).toBe(0);
    expect(sealedIn.length).toBe(1);
    expect(sealedIn[0]?.startsWith(join(ward, "tpm") + "/")).toBe(true);
  });

  test(
    "a ward command whose tpm2 tool times out exits",
    async () => {
      const base = fresh();
      const probe = join(
        import.meta.dir,
        "fixtures",
        "tpm2-command-exit-probe.ts",
      );
      const child = Bun.spawn([process.execPath, probe, base, root], {
        stdout: "pipe",
        stderr: "pipe",
      });
      try {
        const outcome = await Promise.race([
          child.exited.then(() => "exited"),
          new Promise<string>((resolve) =>
            setTimeout(() => resolve("still running"), 30_000),
          ),
        ]);
        expect(outcome).toBe("exited");
        const out = await new Response(child.stdout).text();
        // The command asked for an explicit exit, and the grandchild was killed
        // with the tool, so the loop drained too.
        expect(out).toContain("done explicit=true");
        // doctor's own stdout parsed and reported the key unavailable.
        expect(out).toContain("doctor key=unavailable");
        // A propagating command (backup) asked for the exit too.
        expect(out).toContain("backup explicit=true code=tpm_tool_timeout");
        // A good unseal whose flush hangs, on a root that never read the
        // provider flag, succeeds, warns and asks for the exit.
        expect(out).toContain("flush exit=0 explicit=true warned=true");
      } finally {
        child.kill(9);
        try {
          const pid = Number(
            readFileSync(join(base, "records", "grandchild.pid"), "utf8"),
          );
          if (Number.isInteger(pid) && pid > 0) process.kill(pid, 9);
        } catch {
          // No grandchild, or already gone.
        }
      }
    },
    { timeout: 60_000 },
  );
});

describe("DEC-262 (a23): the init hint and the leak warning", () => {
  const weaker =
    /file|keyring|passphrase|environment|plaintext|weaker|fallback/i;

  test("the Linux init refusal says Secret Service is not implemented", async () => {
    const { provider } = linux(fresh(), {
      detect: () => {
        throw new Tpm2Error("tpm_absent");
      },
    });
    const error = (await caught(() =>
      provider.create(VAULT_ID, synthetic()),
    )) as WardError;
    // The specific code stays; the hint adds the gap and suggests no store.
    expect(error.code).toBe("tpm_absent");
    const { hint } = errorEnvelope(error);
    expect(hint).toContain("Secret Service is not implemented");
    expect(hint).not.toMatch(weaker);
  });

  const leak = { code: "tpm_session_leaked" } as const;

  test("under --json the leak warning is exactly one line", () => {
    expect(formatKeyWarning(leak, true)).toBe(
      '{"warning":"tpm_session_leaked"}\n',
    );
  });

  test("in human mode the leak warning is a sentence", () => {
    const text = formatKeyWarning(leak, false);
    expect(text).toContain("tpm_session_leaked");
    expect(text).toContain("reset or reboot");
    expect(text.trim().startsWith("{")).toBe(false);
  });

  test("the leak warning carries no path or handle", () => {
    for (const json of [true, false]) {
      const text = formatKeyWarning(leak, json);
      expect(text).not.toMatch(/\/|0x[0-9a-f]/i);
      expect(text.split("\n").filter(Boolean).length).toBe(1);
    }
  });

  // A vault sealed with fakes, then a command whose unseal fires the warning.
  async function leaking(args: string[], unsealAfterSetup: unknown) {
    const base = fresh();
    const checkout = join(base, "checkout");
    mkdirSync(checkout);
    Bun.spawnSync(["git", "init", "-q", checkout]);
    const ward = join(base, ".ward");
    const sealedIn: string[] = [];
    const selection = (unseal: unknown) => ({
      platform: "linux",
      keychain: stubProvider(async () => {
        throw new Error("never");
      }),
      tpm2: {
        detect: () => presence,
        seal: fakeSeal(sealedIn),
        unseal: unseal as never,
      },
    });
    const setup = await runWard(["setup", "--json"], {
      wardDirectory: ward,
      keySelection: selection(async () => synthetic()),
    });
    expect(setup.exitCode).toBe(0);
    return await runWard(args, {
      wardDirectory: ward,
      cwd: checkout,
      keySelection: selection(unsealAfterSetup),
    });
  }

  const warnOnce = async (
    _presence: Tpm2Presence,
    _directory: string,
    options?: {
      onWarning?: (warning: { code: "tpm_session_leaked" }) => unknown;
    },
  ) => {
    options?.onWarning?.(leak);
    return synthetic();
  };

  test("the warning is on stderr and the stdout envelope is untouched", async () => {
    const result = await leaking(["doctor", "--json"], warnOnce);
    expect(result.stderr).toBe('{"warning":"tpm_session_leaked"}\n');
    expect(result.stdout).not.toContain("tpm_session_leaked");
    // stdout is still exactly one JSON envelope.
    expect(() => JSON.parse(result.stdout)).not.toThrow();
    const human = await leaking(["doctor"], warnOnce);
    expect(human.stderr).toContain("reset or reboot");
    expect(human.stdout).not.toContain("tpm_session_leaked");
  });

  test("a warning before a failing command still reaches stderr", async () => {
    // The read-back after sealing hears the warning and returns another key,
    // so setup fails as unconfirmed; the resolving load then fails too.
    const base = fresh();
    let calls = 0;
    const result = await runWard(["setup", "--json"], {
      wardDirectory: join(base, ".ward"),
      keySelection: {
        platform: "linux",
        keychain: stubProvider(async () => {
          throw new Error("never");
        }),
        tpm2: {
          detect: () => presence,
          seal: fakeSeal([]),
          unseal: async (_p, _d, options) => {
            calls += 1;
            if (calls > 1) throw new Tpm2Error("tool_failed", "tpm2_unseal");
            options?.onWarning?.(leak);
            return synthetic(0x11);
          },
        },
      },
    });
    expect(result.exitCode).not.toBe(0);
    const lines = result.stderr.trim().split("\n");
    expect(lines[0]).toBe('{"warning":"tpm_session_leaked"}');
    expect(JSON.parse(lines[lines.length - 1] as string).code).toBe(
      "vault_key_write_unconfirmed",
    );
  });

  test("the output contract documents the stderr warning", () => {
    const adr = readFileSync(
      join(
        import.meta.dir,
        "..",
        "docs",
        "adr",
        "0028-tpm2-key-custody-on-linux-tool-trust-the-leaked-session-slot-and-the-stored-format-template.md",
      ),
      "utf8",
    );
    expect(adr).toContain('{"warning":"tpm_session_leaked"}');
    expect(adr).toContain("**stderr**");
  });

  test("the stderr contract concept pins the warning forms", () => {
    const concept = readFileSync(
      join(
        import.meta.dir,
        "..",
        "docs",
        "reference",
        "ward-s-stderr-output-contract.md",
      ),
      "utf8",
    );
    expect(concept).toContain('{"warning":"tpm_session_leaked"}');
    expect(concept).toContain(
      "warning: tpm_session_leaked: a TPM session slot may be leaked; it is cleared by a reset or reboot.",
    );
    expect(concept).toContain(
      "the error envelope is always the last stderr line",
    );
    expect(concept).toContain("never a path or a handle");
    const leak = { code: "tpm_session_leaked" as const };
    expect(concept).toContain(formatKeyWarning(leak, false).trim());
    expect(concept).toContain(formatKeyWarning(leak, true).trim());
  });
});

describe("#341 round 2: explicit exit, naming, notes and de-duplication", () => {
  const timeoutFlush = () =>
    new Tpm2Error("tool_failed", "tpm2_unseal", {
      flushFailure: "tool_timeout",
    });

  // A vault sealed with fakes, then one command with a chosen unseal.
  async function afterSetup(
    args: string[],
    unseal: unknown,
    extra: Record<string, unknown> = {},
    register = false,
  ) {
    const base = fresh();
    const ward = join(base, ".ward");
    const selection = (u: unknown) => ({
      platform: "linux",
      keychain: stubProvider(async () => {
        throw new Error("never");
      }),
      tpm2: { detect: () => presence, seal: fakeSeal([]), unseal: u as never },
    });
    const setup = await runWard(["setup", "--json"], {
      wardDirectory: ward,
      keySelection: selection(async () => synthetic()),
    });
    expect(setup.exitCode).toBe(0);
    if (register) {
      const checkout = join(base, "checkout");
      mkdirSync(join(checkout, ".git"), { recursive: true });
      const init = await runWard(["init", "--json"], {
        wardDirectory: ward,
        keySelection: selection(async () => synthetic()),
        approver: { available: () => true, ask: () => "approved" as const },
        cwd: checkout,
      });
      expect(init.exitCode).toBe(0);
      extra = { cwd: checkout, ...extra };
    }
    return await runWard(args, {
      wardDirectory: ward,
      keySelection: selection(unseal),
      passphrases: {
        available: () => true,
        read: () => new TextEncoder().encode("synthetic-passphrase"),
      },
      ...extra,
    });
  }
  const backup = (base = fresh()) => [
    "backup",
    "--output",
    join(base, "out.bak"),
    "--json",
  ];

  test("a propagated tool timeout still asks for an explicit exit", async () => {
    const result = await afterSetup(backup(), async () => {
      throw new Tpm2Error("tool_timeout", "tpm2_unseal");
    });
    expect(
      JSON.parse(result.stderr.trim().split("\n").pop() as string).code,
    ).toBe("tpm_tool_timeout");
    expect(result.exitExplicitly).toBe(true);
  });

  test("a propagated flush timeout still asks for an explicit exit", async () => {
    const result = await afterSetup(backup(), async () => {
      throw timeoutFlush();
    });
    expect(result.exitExplicitly).toBe(true);
  });

  const abandoningUnseal = async (
    _presence: unknown,
    _directory: unknown,
    options: { onAbandon?: () => void },
  ) => {
    options.onAbandon?.();
    return synthetic();
  };

  test("a good unseal whose flush timed out asks for an explicit exit on a root that never read the provider flag", async () => {
    const result = await afterSetup(
      ["key", "generate", "k1", "--json"],
      abandoningUnseal,
      {},
      true,
    );
    expect(result.exitCode).toBe(0);
    expect(result.exitExplicitly).toBe(true);
  });

  test("the same abandon survives a later non-TPM failure", async () => {
    const base = fresh();
    const result = await afterSetup(
      [
        "backup",
        "--output",
        join(base, "no-such-directory", "out.bak"),
        "--json",
      ],
      abandoningUnseal,
    );
    expect(result.exitCode).not.toBe(0);
    expect(
      JSON.parse(result.stderr.trim().split("\n").pop() as string).code,
    ).not.toMatch(/^tpm_|^vault_key_/);
    expect(result.exitExplicitly).toBe(true);
  });

  test("a good unseal without an abandon does not ask for one", async () => {
    const result = await afterSetup(
      ["key", "generate", "k1", "--json"],
      async () => synthetic(),
      {},
      true,
    );
    expect(result.exitCode).toBe(0);
    expect(result.exitExplicitly).toBeUndefined();
  });

  test("without --json the warning is the human sentence on a root that has no flag for it", async () => {
    const leak = { code: "tpm_session_leaked" as const };
    const result = await afterSetup(
      ["secret", "list"],
      async (
        _p: unknown,
        _d: unknown,
        options: { onWarning?: (w: typeof leak) => unknown },
      ) => {
        options.onWarning?.(leak);
        return synthetic();
      },
    );
    expect(result.stderr).toContain("warning: tpm_session_leaked");
    expect(result.stderr).not.toContain('{"warning"');
  });

  test("a refusal that is not a timeout does not ask for one", async () => {
    const result = await afterSetup(backup(), async () => {
      throw new Tpm2Error("tool_failed", "tpm2_unseal");
    });
    expect(result.exitExplicitly).toBeUndefined();
  });

  test("a probe that passes and a load that refuses carries the store and .tpm2", async () => {
    const tpm2 = new Tpm2Error("tool_failed", "tpm2_unseal");
    const holder = tpm2Backend(
      stubProvider(async () => {
        throw new TpmKeyError("tpm_tool_failed", tpm2);
      }),
      () => "/synthetic",
    );
    const router = createRoutingKeyProvider({
      backends: [{ ...holder, probe: async () => ({ held: true }) }],
      initialisation: () => holder,
    });
    const error = (await caught(() => router.load(VAULT_ID))) as TpmKeyError;
    expect(error).toBeInstanceOf(TpmKeyError);
    expect(error.stores).toEqual(["TPM2"]);
    expect(error.tpm2).toBe(tpm2);
  });

  const detectionRefusals = [
    "tpm_absent",
    "tools_absent",
    "tpm_not_accessible",
    "tpm_unusable",
    "tool_untrusted",
  ] as const;

  test("the init note reaches every detection refusal", async () => {
    for (const reason of detectionRefusals) {
      const { provider } = linux(fresh(), {
        detect: () => {
          throw new Tpm2Error(reason);
        },
      });
      const error = (await caught(() =>
        provider.create(VAULT_ID, synthetic()),
      )) as WardError;
      expect(error.code).toBe(tpm2ErrorCodes[reason]);
      expect(errorEnvelope(error).hint).toContain(
        "Secret Service is not implemented",
      );
    }
  });

  test("the init note does not print on a load refusal", async () => {
    for (const reason of detectionRefusals) {
      const ward = fresh();
      chmodSync(ward, 0o700);
      const directory = join(ward, "tpm", VAULT_ID);
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      writeFileSync(join(directory, sealedPrivateName), "priv");
      writeFileSync(join(directory, sealedPublicName), "pub");
      const { provider } = linux(ward, {
        detect: () => {
          throw new Tpm2Error(reason);
        },
        unseal: undefined,
      });
      const error = (await caught(() => provider.load(VAULT_ID))) as WardError;
      expect(error.code).toBe(tpm2ErrorCodes[reason]);
      expect(errorEnvelope(error).hint ?? "").not.toContain("Secret Service");
    }
  });

  test("a repeated warning is one line per command", async () => {
    // Every unseal hears of the leak; the read-back returns another key, so
    // setup resolves through a second load, and the line is still one.
    const base = fresh();
    let calls = 0;
    const result = await runWard(["setup", "--json"], {
      wardDirectory: join(base, ".ward"),
      keySelection: {
        platform: "linux",
        keychain: stubProvider(async () => {
          throw new Error("never");
        }),
        tpm2: {
          detect: () => presence,
          seal: fakeSeal([]),
          unseal: async (_p, _d, options) => {
            calls += 1;
            options?.onWarning?.({ code: "tpm_session_leaked" });
            return synthetic(0x11);
          },
        },
      },
    });
    expect(calls).toBeGreaterThan(1);
    expect(result.stderr).toBe('{"warning":"tpm_session_leaked"}\n');
  });

  test("a key-returning probe followed by a throwing probe zeroes the key", async () => {
    const key = synthetic(0x77);
    const router = createRoutingKeyProvider({
      backends: [
        backend("macOS Keychain", async () => ({ held: true, key })),
        backend("TPM2", async () => {
          throw new WardError("vault_key_unavailable");
        }),
      ],
      initialisation: () => {
        throw new Error("never");
      },
    });
    const error = (await caught(() => router.load(VAULT_ID))) as WardError;
    expect(error.code).toBe("vault_key_unavailable");
    expect(Array.from(key)).toEqual(new Array(32).fill(0));
  });

  test("a seam cannot redirect the blob directory", async () => {
    const ward = fresh();
    chmodSync(ward, 0o700);
    const sealedIn: string[] = [];
    const provider = selectKeyProvider(ward, {
      platform: "linux",
      tpm2: {
        detect: () => presence,
        seal: fakeSeal(sealedIn),
        unseal: async () => synthetic(),
        ...({ directoryFor: () => join(ward, "elsewhere") } as object),
      },
    });
    await provider.create(VAULT_ID, synthetic());
    expect(sealedIn).toEqual([join(ward, "tpm", VAULT_ID)]);
  });
});
