// MUTANT REGISTER for slice 3d-1a (WCLI-21), written and committed BEFORE any
// run. Each line is a one-site mutation and the tests predicted to go red, by
// the first words of their titles; every other test in the file must stay
// green. Run against a saved copy of the source, restored after each. A
// prediction is never edited after its run: the observation is annotated
// beside it.
//   P1  the provider omits onWarning                      -> "a leaked session warning reaches the sink"
//   P2  the provider detects once and caches              -> "detection runs again before every load"
//   P3  key_incomplete maps to vault_key_missing          -> "a lone private blob is tpm_key_incomplete"
//   P4  the provider drops the tpm2 side channel          -> "a Tpm2Error rides on the WardError", "detection runs again before every load"
//   P5  the provider never marks a timeout abandoned      -> "a timed-out tool marks the call abandoned"
//   P6  create reads the key after its first await        -> "create copies the key before any await"
//   P7  create skips the read-back comparison             -> "a read-back that differs is unconfirmed"
//   P8  key_not_sealed passes through untranslated        -> "no sealed key is vault_key_missing"
//   P9  unsealKey drops flushFailure for a non-Tpm2Error  -> test/tpm2-tools.test.ts "a non-Tpm2Error unseal failure keeps flushFailure"
//   P10 runTool kills the child but not its group         -> test/tpm2-tools.test.ts "a timed-out tool's grandchild is killed"
//   P11 spawnTool does not detach the child               -> test/tpm2-tools.test.ts "a timed-out tool's grandchild is killed"
//   R1  observeKey maps tpm_key_incomplete to missing     -> test/reporting.test.ts "a lone private blob is never reported as a missing key"
//   R2  observeKey lets other tpm_* codes throw           -> test/reporting.test.ts "a TPM refusal is reported as an unavailable key"
//   S1  setup treats tpm_key_incomplete as missing        -> test/setup.test.ts "setup refuses over an incomplete sealed key"
// OBSERVED (annotated after the runs; the predictions above are unchanged).
// Every mutant went red on its predicted tests. Extras, not predicted:
//   P3  also reddened "an existing key is vault_key_exists and a lone private blob is not" (its create half)
//   P4  also reddened "a non-Tpm2Error from the unseal is wrapped as tool_failed" (it reads .tpm2)
//   P10, P11 also reddened "a timed-out tool lets the process exit" beside the grandchild test
//   R2  also reddened "a lone private blob is never reported as a missing key" (the incomplete code starts with tpm_)
// Survivors: none. Run 2026-11-15 against the 3d-1a working tree, bun 1.3.14.
// The mock is imported first (test-isolation.test.ts).
import "./support/no-real-keychain.ts";
import { describe, expect, test } from "bun:test";
import {
  createTpm2KeyProvider,
  TpmKeyError,
} from "../src/adapters/tpm2-provider.ts";
import {
  type Tpm2Presence,
  Tpm2Error,
  type Tpm2Reason,
  type Tpm2Warning,
  tpm2StateFor,
} from "../src/adapters/tpm2-tools.ts";
import { WardError } from "../src/contract/errors.ts";

const VAULT_ID = "3f1c2b7e-9a4d-4e6f-8b21-5c7d9e0a1b2c";
const presence = {
  device: "/dev/null",
  tools: {},
} as unknown as Tpm2Presence;
const synthetic = () => new Uint8Array(32).fill(0x5a);

async function caught(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

const refusing = (reason: Tpm2Reason, detail?: string) => async () => {
  throw new Tpm2Error(reason, detail);
};

function provider(
  overrides: Partial<Parameters<typeof createTpm2KeyProvider>[0]> = {},
) {
  return createTpm2KeyProvider({
    directoryFor: () => "/synthetic/blobs",
    detect: () => presence,
    unseal: async () => synthetic(),
    seal: async () => ({ publicBlob: "a", privateBlob: "b" }),
    ...overrides,
  });
}

describe("load", () => {
  test("a good unseal returns the key", async () => {
    expect(Array.from(await provider().load(VAULT_ID))).toEqual(
      Array.from(synthetic()),
    );
  });

  test("a leaked session warning reaches the sink once, with the code only", async () => {
    const warnings: Tpm2Warning[] = [];
    const key = await provider({
      onWarning: (warning) => warnings.push(warning),
      unseal: async (_presence, _directory, options) => {
        options?.onWarning?.({ code: "tpm_session_leaked" });
        return synthetic();
      },
    }).load(VAULT_ID);
    expect(key.length).toBe(32);
    expect(warnings).toEqual([{ code: "tpm_session_leaked" }]);
  });

  test("detection runs again before every load", async () => {
    let detections = 0;
    const p = provider({
      detect: () => {
        detections += 1;
        if (detections > 1) throw new Tpm2Error("tpm_not_accessible");
        return presence;
      },
    });
    await p.load(VAULT_ID);
    const error = await caught(() => p.load(VAULT_ID));
    expect(detections).toBe(2);
    // Revoked access is access refused, never an unloadable key.
    expect(error).toMatchObject({ code: "tpm_access_refused" });
    const state = tpm2StateFor((error as TpmKeyError).tpm2);
    expect(state.state).not.toBe("key_unloadable");
  });

  test("a Tpm2Error rides on the WardError for tpm2StateFor", async () => {
    const error = await caught(() =>
      provider({
        unseal: refusing("tool_untrusted", "/x/tpm2_unseal"),
      }).load(VAULT_ID),
    );
    expect(error).toBeInstanceOf(WardError);
    expect((error as TpmKeyError).tpm2).toBeInstanceOf(Tpm2Error);
    expect((error as TpmKeyError).tpm2.reason).toBe("tool_untrusted");
    expect((error as TpmKeyError).tpm2.detail).toBe("/x/tpm2_unseal");
  });

  test("no sealed key is vault_key_missing", async () => {
    const error = await caught(() =>
      provider({ unseal: refusing("key_not_sealed") }).load(VAULT_ID),
    );
    expect((error as WardError).code).toBe("vault_key_missing");
  });

  test("a lone private blob is tpm_key_incomplete, never missing", async () => {
    const error = await caught(() =>
      provider({ unseal: refusing("key_incomplete") }).load(VAULT_ID),
    );
    expect((error as WardError).code).toBe("tpm_key_incomplete");
  });

  test("a non-Tpm2Error from the unseal is wrapped as tool_failed", async () => {
    const error = await caught(() =>
      provider({
        unseal: async () => {
          throw new Error("spawn exploded at /private/path");
        },
      }).load(VAULT_ID),
    );
    expect((error as TpmKeyError).tpm2.reason).toBe("tool_failed");
    expect((error as WardError).message).not.toContain("/private/path");
  });

  test("a bad vault id is refused before anything runs", async () => {
    let detections = 0;
    const error = await caught(() =>
      provider({
        detect: () => {
          detections += 1;
          return presence;
        },
      }).load("../../etc"),
    );
    expect((error as WardError).code).toBe("vault_record_malformed");
    expect(detections).toBe(0);
  });
});

describe("abandoned calls", () => {
  test("a timed-out tool marks the call abandoned", async () => {
    const p = provider({ unseal: refusing("tool_timeout", "tpm2_unseal") });
    expect(p.abandonedCall?.()).toBe(false);
    await caught(() => p.load(VAULT_ID));
    expect(p.abandonedCall?.()).toBe(true);
  });

  test("a refusal that is not a timeout does not", async () => {
    const p = provider({ unseal: refusing("tool_failed") });
    await caught(() => p.load(VAULT_ID));
    expect(p.abandonedCall?.()).toBe(false);
  });
});

describe("create", () => {
  test("create copies the key before any await", async () => {
    let sealed: Uint8Array | undefined;
    const key = synthetic();
    const p = provider({
      seal: async (_presence, given) => {
        await Promise.resolve();
        sealed = new Uint8Array(given);
        return { publicBlob: "a", privateBlob: "b" };
      },
    });
    const pending = p.create(VAULT_ID, key);
    // The caller may zero its own buffer as soon as it has called create.
    key.fill(0);
    await pending.catch(() => undefined);
    expect(Array.from(sealed ?? [])).toEqual(Array.from(synthetic()));
  });

  test("create seals, reads back and compares, and zeroes its copy", async () => {
    const calls: string[] = [];
    let given: Uint8Array | undefined;
    const p = provider({
      seal: async (_presence, key) => {
        calls.push("seal");
        given = key;
        return { publicBlob: "a", privateBlob: "b" };
      },
      unseal: async () => {
        calls.push("unseal");
        return synthetic();
      },
    });
    await p.create(VAULT_ID, synthetic());
    expect(calls).toEqual(["seal", "unseal"]);
    expect(Array.from(given ?? [1])).toEqual(new Array(32).fill(0));
  });

  test("a read-back that differs is unconfirmed", async () => {
    const error = await caught(() =>
      provider({
        unseal: async () => new Uint8Array(32).fill(0x11),
      }).create(VAULT_ID, synthetic()),
    );
    expect((error as WardError).code).toBe("vault_key_write_unconfirmed");
  });

  test("a tool that timed out mid-seal is unconfirmed and abandoned", async () => {
    const p = provider({ seal: refusing("tool_timeout", "tpm2_create") });
    const error = await caught(() => p.create(VAULT_ID, synthetic()));
    expect((error as WardError).code).toBe("vault_key_write_unconfirmed");
    expect(p.abandonedCall?.()).toBe(true);
  });

  test("an existing key is vault_key_exists and a lone private blob is not", async () => {
    const exists = await caught(() =>
      provider({ seal: refusing("key_exists") }).create(VAULT_ID, synthetic()),
    );
    expect((exists as WardError).code).toBe("vault_key_exists");
    const incomplete = await caught(() =>
      provider({ seal: refusing("key_incomplete") }).create(
        VAULT_ID,
        synthetic(),
      ),
    );
    expect((incomplete as WardError).code).toBe("tpm_key_incomplete");
  });

  test("a wrong-sized key is refused before anything runs", async () => {
    let detections = 0;
    const error = await caught(() =>
      provider({
        detect: () => {
          detections += 1;
          return presence;
        },
      }).create(VAULT_ID, new Uint8Array(16)),
    );
    expect((error as WardError).code).toBe("vault_key_invalid");
    expect(detections).toBe(0);
  });
});
