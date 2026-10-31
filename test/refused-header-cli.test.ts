// WCLI-116 (ward-cli#215 review, finding 5): a refused header name reaches
// the user through the real command surface as Ward's canonical constant, and
// no declared byte or value reaches any output.
//
// Three kinds of surface are driven. `profile approve` and `run` let the
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
import { parseVaultState } from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const PROFILE = "example-profile";
const ALIAS = "example-token";
// A header value the declaration carries and a stored credential value: both
// are synthetic sentinels, and no output of any command may hold either.
const VALUE = "value-sentinel-9c1e";
const SECRET = "synthetic-secret-sentinel-3d7b";
// The vault holds the credential base64-encoded and only `run` decodes it,
// after approval; every refusal path stops earlier, so the form that could
// reach an output is the encoded one. Both forms are measured absent.
const SECRET_STORED = Buffer.from(SECRET).toString("base64");
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
  readHidden: () => encoder.encode(SECRET),
  readStdin: () => encoder.encode(SECRET),
  confirmReplace: () => true,
};
const registration: RegistrationApprover = {
  available: () => true,
  ask: () => "approved",
};

let cases = 0;

// A project whose one profile is declared by `overrides` on top of a valid
// bearer declaration. The vault, the secret and the registration are real, and
// the stored secret is SECRET.
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
  // Runs inside the approval prompt, so a case can change the manifest while
  // the developer is being asked.
  let whileAsking: (() => void) | undefined;
  const profileApprover: ProfileApprover = {
    available: () => true,
    ask: () => {
      whileAsking?.();
      return "approved";
    },
  };
  const checkoutPath = join(root, `repo-${++cases}`);
  mkdirSync(checkoutPath);
  mkdirSync(join(checkoutPath, ".git"));
  const ward = (args: string[], options: { json?: boolean } = {}) =>
    runWard(options.json === false ? args : [...args, "--json"], {
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
  const writeProfile = (profile: Record<string, unknown>) => {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      profiles?: Record<string, unknown>;
    };
    manifest.profiles = { [PROFILE]: profile };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  };
  const valid = {
    adapter: "http",
    method: "GET",
    url: "https://api.example.invalid/status",
    auth: { type: "bearer", secret: ALIAS },
    requestBody: "none",
    output: "status",
  };
  writeProfile({ ...valid, ...overrides });
  expect((await ward(["secret", "set", ALIAS, "--stdin"])).exitCode).toBe(
    exitCodes.success,
  );
  const key = (): Uint8Array =>
    new Uint8Array(keychain.items.values().next().value as number[]);
  // Rewrites the stored approval's text, for the cases that damage the vault.
  const damageVault = (change: (text: string) => string) =>
    store.mutate(key(), (plaintext) => {
      const text = new TextDecoder().decode(plaintext);
      const damaged = change(text);
      expect(damaged).not.toBe(text);
      return new TextEncoder().encode(damaged);
    });
  return {
    ward,
    transport,
    writeProfile,
    valid,
    damageVault,
    approvals: () =>
      parseVaultState(store.read(key()).plaintext).profileApprovals.length,
    onAsk: (fn: () => void) => {
      whileAsking = fn;
    },
  };
}

type Result = { exitCode: number; stdout: string; stderr: string };

// Everything a command printed, with the two sentinels measured absent. Every
// case below goes through this, so no case can pass without having read the
// output: `printed` must be non-empty.
function printedOf(result: Result, ...absent: string[]): string {
  const printed = `${result.stdout}${result.stderr}`;
  expect(printed.length).toBeGreaterThan(0);
  for (const text of [VALUE, SECRET, SECRET_STORED, ...absent])
    expect(printed).not.toContain(text);
  return printed;
}

// The refused declarations, each spelled so that the declared bytes differ
// from the canonical constant in case and in `_` against `-`. VALUE rides on a
// header in every one, including the secret-header case, where it sits on an
// ordinary header beside the refused auth name.
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
      headers: { "X-Trace": VALUE },
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
        printedOf(result, declared);
        expect(result.stderr).toContain(`(refused header: ${canonical})`);
        expect(w.transport.sent).toBe(0);
        expect(w.approvals()).toBe(0);
      });
    }

  // Positive control: in this harness a run that is admitted writes an audit
  // event, so an empty history below means the refusal wrote nothing.
  test("an admitted run writes an audit event in this harness", async () => {
    const w = await world({});
    expect((await w.ward(["profile", "approve", PROFILE])).exitCode).toBe(
      exitCodes.success,
    );
    expect((await w.ward(["run", PROFILE])).exitCode).toBe(exitCodes.success);
    const audit = await w.ward(["audit"]);
    const data = JSON.parse(audit.stdout).data as { events: unknown[] };
    expect(data.events.length).toBeGreaterThan(0);
  });

  // The profile is approved while valid, so the run would reach admission were
  // it not refused; the manifest is then rewritten to a refused name.
  test("a refused run of an approved profile persists nothing: the audit history is empty", async () => {
    const w = await world({});
    expect((await w.ward(["profile", "approve", PROFILE])).exitCode).toBe(
      exitCodes.success,
    );
    w.writeProfile({ ...w.valid, headers: { "x-FORWARDED-host": VALUE } });
    const run = await w.ward(["run", PROFILE]);
    expect(run.exitCode).not.toBe(exitCodes.success);
    expect(run.stderr).toContain("(refused header: X-Forwarded-Host)");
    expect(w.transport.sent).toBe(0);
    const audit = await w.ward(["audit"]);
    expect(audit.exitCode).toBe(exitCodes.success);
    printedOf(audit, "x-FORWARDED-host", "X-Forwarded-Host");
    const data = JSON.parse(audit.stdout).data as { events: unknown[] };
    expect(data.events).toEqual([]);
  });
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
        const printed = printedOf(result, declared, canonical);
        expect(printed).toContain(marker);
      });
    }

  // The same two commands in human text, which `--json` never prints.
  for (const [command, marker] of [
    [["profile", "list"], "invalid declaration"],
    [["check", PROFILE], "the declaration is not one Ward can use"],
  ] as const)
    test(`${command.join(" ")} in text mode prints no refused name`, async () => {
      const w = await world(refused[0]?.overrides ?? {});
      const result = await w.ward([...command], { json: false });
      const printed = printedOf(result, "x-FORWARDED-host", "X-Forwarded-Host");
      expect(printed).toContain(marker);
    });

  // A stored approval whose snapshot declares the refused name. `status` and
  // `doctor` catch the load refusal (reporting.ts) and report the vault state
  // as malformed; `run` and `profile list` let it through, which is the
  // positive control that the refused-header branch, not a plain malformed(),
  // was taken on this very vault.
  describe("a stored snapshot declaring a refused name", () => {
    const declared = "x_FORWARDED_host";
    const damaged = async () => {
      const w = await world({});
      expect((await w.ward(["profile", "approve", PROFILE])).exitCode).toBe(
        exitCodes.success,
      );
      w.damageVault((text) =>
        text.replace(
          '"requestBody":"none"',
          `"headers":{"${declared}":"${VALUE}"},"requestBody":"none"`,
        ),
      );
      return w;
    };

    for (const command of [
      ["run", PROFILE],
      ["profile", "list"],
    ])
      test(`${command.join(" ")} prints the vault_state_malformed suffix naming the canonical constant`, async () => {
        const w = await damaged();
        const result = await w.ward([...command]);
        expect(result.exitCode).not.toBe(exitCodes.success);
        printedOf(result, declared);
        expect(JSON.parse(result.stderr).code).toBe("vault_state_malformed");
        expect(result.stderr).toContain("(refused header: X-Forwarded-Host)");
      });

    for (const [command, marker] of [
      [["status"], '"binding":{"status":"unknown"}'],
      [["doctor"], '"code":"state_malformed"'],
    ] as const)
      test(`${command[0]} reports malformed and prints no name`, async () => {
        const w = await damaged();
        const printed = printedOf(
          await w.ward([...command]),
          declared,
          "X-Forwarded-Host",
        );
        expect(printed).toContain(marker);
      });

    for (const [command, marker] of [
      [["status"], "binding:       unknown"],
      [["doctor"], "schema          fail    state_malformed"],
    ] as const)
      test(`${command[0]} in text mode prints no name`, async () => {
        const w = await damaged();
        const result = await w.ward([...command], { json: false });
        const printed = printedOf(result, declared, "X-Forwarded-Host");
        expect(printed).toContain(marker);
      });
  });

  // profiles.ts stillApproved: the manifest is rewritten to a refused name
  // while the approval prompt is open. The catch returns false and the
  // approval is refused with a fixed message, naming nothing.
  test("a manifest rewritten to a refused name during the prompt is refused without the name", async () => {
    const w = await world({});
    w.onAsk(() =>
      w.writeProfile({
        ...w.valid,
        headers: { "x-FORWARDED-host": VALUE },
      }),
    );
    const result = await w.ward(["profile", "approve", PROFILE]);
    expect(result.exitCode).not.toBe(exitCodes.success);
    expect(JSON.parse(result.stderr).code).toBe("profile_changed");
    printedOf(result, "x-FORWARDED-host", "X-Forwarded-Host");
    expect(w.approvals()).toBe(0);
  });

  // reporting.ts stale-approval report: an approval written under another
  // snapshot version, whose checkout now declares a refused name, is reported
  // inert with a fixed sentence.
  test("a stale approval whose checkout now declares a refused name is reported without the name", async () => {
    const w = await world({});
    expect((await w.ward(["profile", "approve", PROFILE])).exitCode).toBe(
      exitCodes.success,
    );
    expect(w.approvals()).toBe(1);
    w.damageVault((text) =>
      text.replace('"snapshotVersion":3', '"snapshotVersion":2'),
    );
    w.writeProfile({ ...w.valid, headers: { "x-FORWARDED-host": VALUE } });
    const result = await w.ward(["status"]);
    const printed = printedOf(result, "x-FORWARDED-host", "X-Forwarded-Host");
    expect(printed).toContain("declaration of this profile cannot be read");
  });

  test("a header that is not refused is never printed on any path", async () => {
    const unlisted = "X-Unlisted-Sentinel-55";
    const w = await world({ headers: { [unlisted]: 7 } });
    // A marker per command, so a clean answer is told apart from a command
    // that never produced the output being measured.
    for (const [command, marker] of [
      [["profile", "approve", PROFILE], '"code":"profile_invalid"'],
      [["run", PROFILE], '"code":"profile_invalid"'],
      [["profile", "list"], '"declaration":"invalid"'],
      [["check", PROFILE], '"reasons":["declaration"]'],
      [["status"], '"kind":"status.report"'],
      [["doctor"], '"kind":"doctor.report"'],
    ] as const) {
      const printed = printedOf(await w.ward([...command]), unlisted);
      expect(printed).toContain(marker);
      expect(printed).not.toContain("refused header");
    }
  });
});
