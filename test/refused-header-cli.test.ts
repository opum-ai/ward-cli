// WCLI-116 (ward-cli#215 review, finding 5): a refused header name reaches
// the user through the real command surface as Ward's canonical constant, and
// no declared byte or value reaches any output.
//
// Two kinds of surface are driven. `profile approve` and `run` let the
// WardError through, so they print the `(refused header: <name>)` suffix.
// `status` and `doctor` catch the refusal in reporting.ts and profiles.ts and
// report an enumerated state ("invalid declaration") instead of a message; a
// state with no free text has no place to carry a name, so those paths are
// pinned to print neither the canonical name nor any declared byte. Synthetic
// names and values only.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type {
  ProfileApprover,
  RegistrationApprover,
} from "../src/application/approvals.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import type {
  Transport,
  TransportOutcome,
  TransportRequest,
} from "../src/application/transport.ts";
import { runWard } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const PROFILE = "example-profile";
const ALIAS = "example-token";
const VALUE = "value-sentinel-9c1e";
const encoder = new TextEncoder();
const root = mkdtempSync(join(tmpdir(), "ward-refused-header-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

class RecordingTransport implements Transport {
  sent = 0;
  async send(_request: TransportRequest): Promise<TransportOutcome> {
    this.sent++;
    return { kind: "response", httpStatus: 200 };
  }
}

const values: SecretValueSource = {
  available: () => true,
  readHidden: () => encoder.encode("synthetic-refused-header-value"),
  readStdin: () => encoder.encode("synthetic-refused-header-value"),
  confirmReplace: () => true,
};
const registration: RegistrationApprover = {
  available: () => true,
  ask: () => "approved",
};
const profileApprover: ProfileApprover = {
  available: () => true,
  ask: () => "approved",
};

let cases = 0;

// A project whose one profile is declared by `overrides` on top of a valid
// bearer declaration. The vault, the secret and the registration are real.
async function world(overrides: Record<string, unknown>) {
  const directory = join(mkdtempSync(join(root, `vault-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: "opum.ward.refused-header",
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const store = createSqliteVaultStore({ directory });
  const transport = new RecordingTransport();
  let ids = 0;
  const checkoutPath = join(root, `repo-${++cases}`);
  mkdirSync(checkoutPath);
  mkdirSync(join(checkoutPath, ".git"));
  const ward = (args: string[]) =>
    runWard([...args, "--json"], {
      wardDirectory: directory,
      keyProvider,
      approver: registration,
      profileApprover,
      secrets: values,
      cwd: checkoutPath,
      now: () => new Date("2026-10-31T00:00:00.000Z"),
      newId: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
      transport,
      machine: () => ({ user: "refused-user", host: "refused-host" }),
    });
  expect((await ward(["setup"])).exitCode).toBe(exitCodes.success);
  expect((await ward(["init"])).exitCode).toBe(exitCodes.success);
  const manifestPath = join(checkoutPath, ".ward", "project.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    profiles?: Record<string, unknown>;
  };
  manifest.profiles = {
    [PROFILE]: {
      adapter: "http",
      method: "GET",
      url: "https://api.example.invalid/status",
      auth: { type: "bearer", secret: ALIAS },
      requestBody: "none",
      output: "status",
      ...overrides,
    },
  };
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  expect((await ward(["secret", "set", ALIAS, "--stdin"])).exitCode).toBe(
    exitCodes.success,
  );
  const key = (): Uint8Array =>
    new Uint8Array(keychain.items.values().next().value as number[]);
  return { ward, transport, store, key };
}

// The refused declarations, each spelled so that the declared bytes differ
// from the canonical constant in case and in `_` against `-`.
const refused: ReadonlyArray<{
  label: string;
  declared: string;
  canonical: string;
  overrides: Record<string, unknown>;
}> = [
  {
    label: "an ordinary header",
    declared: "x-FORWARDED-host",
    canonical: "X-Forwarded-Host",
    overrides: { headers: { "x-FORWARDED-host": VALUE } },
  },
  {
    label: "an ordinary header spelled with underscores",
    declared: "Content_Length",
    canonical: "Content-Length",
    overrides: { headers: { Content_Length: VALUE } },
  },
  {
    label: "the secret header's name",
    declared: "x_ORIGINAL_url",
    canonical: "X-Original-URL",
    overrides: {
      auth: { type: "header", name: "x_ORIGINAL_url", secret: ALIAS },
    },
  },
];

describe("WCLI-116: a refusal prints Ward's canonical name where an error is printed", () => {
  for (const { label, declared, canonical, overrides } of refused)
    for (const command of [
      ["profile", "approve", PROFILE],
      ["run", PROFILE],
    ]) {
      test(`${command[0]} ${label}: the suffix names ${canonical}, never ${declared}`, async () => {
        const w = await world(overrides);
        const result = await w.ward([...command]);
        expect(result.exitCode).not.toBe(exitCodes.success);
        const printed = result.stderr;
        expect(printed).toContain(`(refused header: ${canonical})`);
        expect(printed).not.toContain(declared);
        expect(printed).not.toContain(VALUE);
        expect(result.stdout).not.toContain(declared);
        expect(result.stdout).not.toContain(VALUE);
        expect(w.transport.sent).toBe(0);
      });
    }
});

describe("WCLI-116: the reporting paths report a state, never a header name", () => {
  // The manifest declares the refused name: `profile list` and `check` catch
  // the refusal (profiles.ts) and report the declaration as invalid.
  for (const { label, declared, canonical, overrides } of refused)
    for (const [command, marker] of [
      [["profile", "list"], '"declaration":"invalid"'],
      [["check", PROFILE], '"reasons":["declaration"]'],
    ] as const) {
      test(`${command.join(" ")} with ${label} declared: invalid, neither ${declared} nor ${canonical} printed`, async () => {
        const w = await world(overrides);
        const result = await w.ward([...command]);
        const printed = `${result.stdout}${result.stderr}`;
        expect(printed).toContain(marker);
        expect(printed).not.toContain(declared);
        expect(printed).not.toContain(canonical);
        expect(printed).not.toContain(VALUE);
      });
    }

  // A stored approval whose snapshot declares the refused name: `status` and
  // `doctor` catch the load refusal (reporting.ts) and report the vault state
  // as malformed.
  for (const [command, marker] of [
    [["status"], '"binding":{"status":"unknown"}'],
    [["doctor"], '"code":"state_malformed"'],
  ] as const)
    test(`${command[0]} with a stored snapshot declaring a refused name: malformed, no name printed`, async () => {
      const w = await world({});
      expect((await w.ward(["profile", "approve", PROFILE])).exitCode).toBe(
        exitCodes.success,
      );
      const declared = "x_FORWARDED_host";
      w.store.mutate(w.key(), (plaintext) => {
        const text = new TextDecoder().decode(plaintext);
        const damaged = text.replace(
          '"requestBody":"none"',
          `"headers":{"${declared}":"${VALUE}"},"requestBody":"none"`,
        );
        expect(damaged).not.toBe(text);
        return new TextEncoder().encode(damaged);
      });
      const result = await w.ward([...command]);
      const printed = `${result.stdout}${result.stderr}`;
      expect(printed).toContain(marker);
      expect(printed).not.toContain(declared);
      expect(printed).not.toContain("X-Forwarded-Host");
      expect(printed).not.toContain(VALUE);
    });

  test("a header that is not refused is never printed on any path", async () => {
    const unlisted = "X-Unlisted-Sentinel-55";
    const w = await world({ headers: { [unlisted]: 7 } });
    for (const command of [
      ["profile", "approve", PROFILE],
      ["run", PROFILE],
      ["profile", "list"],
      ["check", PROFILE],
      ["status"],
      ["doctor"],
    ]) {
      const result = await w.ward([...command]);
      const printed = `${result.stdout}${result.stderr}`;
      expect(printed).not.toContain(unlisted);
      expect(printed).not.toContain("refused header");
    }
  });
});
