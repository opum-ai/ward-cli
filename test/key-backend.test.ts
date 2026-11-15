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
  type KeyBackend,
  selectKeyProvider,
  tpm2DirectoryFor,
} from "../src/adapters/key-backend.ts";
import {
  holdsSealedKey,
  preparePrivateDirectory,
  sealedPrivateName,
  sealedPublicName,
  Tpm2Error,
  type Tpm2Presence,
} from "../src/adapters/tpm2-tools.ts";
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
  return { name, provider, probe };
}

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
    const { provider } = linux(ward, {
      unseal: async () => {
        throw new Tpm2Error("key_incomplete", directory);
      },
    });
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
    expect(source.match(/selectKeyProvider\(/g)?.length).toBe(12);
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
