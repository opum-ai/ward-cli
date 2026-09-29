// WCLI-11: the format-2 gate and what a vault this build cannot read is told
// (DEC-19 B, DEC-25, DEC-26 A, DEC-30 A).
//
// Three properties, and each is a decision rather than a consequence.
//
// One code, one sentence, three sites. `vault_format_unsupported` is raised
// for the sealed envelope's version, for a stored profile snapshot's version
// and for the state document's version, and the wording is deliberately the
// same at all three: it says a different build wrote this without naming which
// version was found or expected, because with no recovery path (DEC-25) there
// is nothing a reader could do with either number. The sentence is written out
// here rather than read back from the catalog — an assertion that read the
// catalog would pass on any wording at all, which is the failure it exists to
// catch.
//
// No recovery surface. Format-1 vaults are refused, not raised: there is no
// `ward migrate`, no read-out and no domain function that rewrites a document
// from another build. This is asserted as an absence with a positive control
// beside it, because an absent signal and a passing one are different facts.
//
// Read-only against the developer's machine. Every case runs on a temporary
// vault, an in-memory credential store and a throwaway checkout.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type { RegistrationApprover } from "../src/application/approvals.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { errorEnvelope, WardError } from "../src/contract/errors.ts";
import { commands } from "../src/contract/manifest.ts";
import {
  formatVersion as envelopeFormatVersion,
  generateVaultKey,
  open,
  seal,
} from "../src/domain/envelope.ts";
import * as vaultState from "../src/domain/vault-state.ts";
import {
  parseVaultState,
  vaultStateFormatVersion,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

// The sentence DEC-30 A fixed, written out verbatim rather than imported: the
// point of this assertion is that the shipped text is this text.
const DEC_30 =
  "This vault was written by a different version of Ward, and this build cannot read it. Ward did not change it.";

const encoder = new TextEncoder();
const root = mkdtempSync(join(tmpdir(), "ward-format-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
const vaultId = "44b05c92-8a6e-4f15-9dcb-65ae5d371456";
const timestamp = "2026-09-29T00:00:00.000Z";
const PROFILE = "example-profile";

const document = (value: unknown) => encoder.encode(JSON.stringify(value));

// The refusal a call raises, as the caller sees it: the code and the exact
// text the error envelope would print.
function refusalOf(run: () => unknown): { code: string; message: string } {
  try {
    run();
  } catch (error) {
    if (error instanceof WardError) {
      const envelope = errorEnvelope(error);
      return { code: envelope.code, message: envelope.message };
    }
    throw error;
  }
  throw new Error("expected a refusal, and the call returned instead");
}

const unsupported = { code: "vault_format_unsupported", message: DEC_30 };

describe("the refusals a format-2 build gives", () => {
  test("the catalog carries the DEC-30 sentence, with no hint and no version numbers", () => {
    expect(errorEnvelope(new WardError("vault_format_unsupported"))).toEqual({
      error_type: "validation",
      code: "vault_format_unsupported",
      message: DEC_30,
      principal: null,
    });
    // No hint key at all, which is what DEC-25 left: a hint would name a
    // recovery the build does not have.
    expect(
      Object.hasOwn(
        errorEnvelope(new WardError("vault_format_unsupported")),
        "hint",
      ),
    ).toBe(false);
    // And nothing numeric, so no reader can take a found or expected version
    // out of the sentence and act on it.
    expect(DEC_30).not.toMatch(/\d/);
  });

  test("all three sites that raise the code raise it with that sentence", () => {
    // The state document's own version.
    expect(
      refusalOf(() => parseVaultState(document({ formatVersion: 1 }))),
    ).toEqual(unsupported);

    // A stored profile snapshot's version: valid in every other respect, so
    // the version is the only thing left that can refuse it.
    expect(
      refusalOf(() =>
        parseVaultState(
          document({
            formatVersion: vaultStateFormatVersion,
            profileApprovals: [
              {
                profile: PROFILE,
                projectId,
                root: "/Users/dev/code/project",
                device: "16777232",
                inode: "8429931",
                approvedAt: timestamp,
                snapshotVersion: 99,
                snapshot: {},
              },
            ],
          }),
        ),
      ),
    ).toEqual(unsupported);

    // The sealed envelope's version.
    const key = generateVaultKey();
    const record = seal(key, { vaultId, revision: 1 }, document({}));
    expect(
      refusalOf(() =>
        open(key, { ...record, formatVersion: envelopeFormatVersion + 1 }),
      ),
    ).toEqual(unsupported);
  });

  test("a missing or non-numeric version is still the malformed answer, not this one", () => {
    // The two answers call for different things and must not converge: a
    // damaged document is not a document from another build.
    for (const value of [{}, { formatVersion: "2" }, { formatVersion: null }])
      expect(refusalOf(() => parseVaultState(document(value)))).toEqual({
        code: "vault_state_malformed",
        message:
          "The vault's contents are not a state document this Ward can read.",
      });
  });

  test("no migration and no read-out surface exists (DEC-25)", () => {
    // The command list first, because that is what a user would reach for.
    const names = commands.map((command) => command.name);
    // The positive control: the list was read and is not empty.
    expect(names).toContain("run");
    for (const forbidden of [
      "migrate",
      "recover",
      "upgrade",
      "convert",
      "readout",
    ])
      expect(names).not.toContain(forbidden);

    // And nothing in the domain raises a document from another format: a
    // function that did would be the recovery path by another name.
    expect(Object.keys(vaultState).length).toBeGreaterThan(0);
    expect(
      Object.keys(vaultState).filter((name) =>
        /migrat|recover|raise|upgrade|convert|readout|read-out/i.test(name),
      ),
    ).toEqual([]);
  });
});

describe("a format-1 vault is refused on the paths that act", () => {
  const approver: RegistrationApprover = {
    available: () => true,
    ask: () => "approved",
  };

  function harness() {
    const directory = join(mkdtempSync(join(root, "case-")), ".ward");
    const keychain = new MemoryKeychain();
    const keyProvider = createKeychainKeyProvider({
      service: "opum.ward.format",
      entry: keychain.entry,
      timeoutMs: 2_000,
    });
    const store = createSqliteVaultStore({ directory });
    const options = (cwd: string): RunOptions => ({
      wardDirectory: directory,
      keyProvider,
      approver,
      profileApprover: approver,
      cwd,
    });
    const key = (): Uint8Array => {
      const stored = keychain.items.values().next().value as
        | number[]
        | undefined;
      if (stored === undefined) throw new Error("no stored vault key");
      return new Uint8Array(stored);
    };
    return { store, options, key, keychain };
  }

  function worktree(): string {
    const path = join(root, `repo-${Math.random().toString(36).slice(2)}`);
    mkdirSync(path);
    mkdirSync(join(path, ".git"));
    return path;
  }

  // A checkout registered with this build, whose vault document is then
  // replaced by what the previous build wrote. The envelope is re-sealed by
  // the store, so what is being read is a genuine format-1 state document
  // behind a valid envelope — the exact shape a real pre-change vault has.
  async function formatOneVault() {
    const h = harness();
    const checkout = worktree();
    expect(
      (await runWard(["setup", "--json"], h.options(checkout))).exitCode,
    ).toBe(exitCodes.success);
    expect(
      (await runWard(["init", "--json"], h.options(checkout))).exitCode,
    ).toBe(exitCodes.success);
    // A declared profile, so `ward run` below has nothing to refuse but the
    // vault: the parse happens before the declaration is read.
    const manifestPath = join(checkout, ".ward", "project.json");
    writeFileSync(
      manifestPath,
      `${JSON.stringify({
        schemaVersion: 1,
        projectId,
        profiles: {
          [PROFILE]: {
            adapter: "http",
            method: "GET",
            url: "https://api.example.invalid/status",
            auth: { type: "bearer", secret: "example.token" },
          },
        },
      })}\n`,
    );
    h.store.mutate(h.key(), () => document({ formatVersion: 1 }));
    return { h, checkout };
  }

  const refusalFrom = (stderr: string) => ({
    code: (JSON.parse(stderr) as { code: string }).code,
    message: (JSON.parse(stderr) as { message: string }).message,
  });

  const paths: [label: string, argv: string[]][] = [
    ["ward run", ["run", PROFILE, "--json"]],
    ["ward audit", ["audit", "--json"]],
    ["ward check", ["check", PROFILE, "--json"]],
    ["ward secret list", ["secret", "list", "--json"]],
  ];

  for (const [label, argv] of paths) {
    test(`${label} refuses it with the one sentence`, async () => {
      const { h, checkout } = await formatOneVault();
      const result = await runWard(argv, h.options(checkout));
      expect(result.exitCode).toBe(exitCodes.validation);
      expect(refusalFrom(result.stderr)).toEqual(unsupported);
      expect(result.stdout).toBe("");
    });
  }

  test("ward doctor reports it as unsupported rather than reading it", async () => {
    const { h, checkout } = await formatOneVault();
    const result = await runWard(["doctor", "--json"], h.options(checkout));
    const data = JSON.parse(result.stdout).data as {
      checks: { check: string; code: string }[];
    };
    const schema = data.checks.find((entry) => entry.check === "schema");
    expect(schema?.code).toBe("state_unsupported");
  });

  test("the same vault rewritten as format 2 opens, so the refusal is the version's", async () => {
    const { h, checkout } = await formatOneVault();
    const refused = await runWard(["audit", "--json"], h.options(checkout));
    expect(refusalFrom(refused.stderr)).toEqual(unsupported);

    // The positive control for the whole file: the only change is the version
    // number, and the refusal turns into a report.
    h.store.mutate(h.key(), () =>
      document({ formatVersion: vaultStateFormatVersion, projects: [] }),
    );
    const accepted = await runWard(["audit", "--json"], h.options(checkout));
    expect(accepted.exitCode).toBe(exitCodes.denied);
    // Still refused, but now for the binding it does not have — which is a
    // different answer about the same vault, and is the point.
    expect(refusalFrom(accepted.stderr).code).toBe("project_not_registered");
  });
});
