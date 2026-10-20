// WCLI-72: a profile approval expires (DEC-217 Q5, docs/adr/0021).
//
// Expiry is an admission rule, like revocation: it is judged inside the
// admission transaction against the time of admission, a refused run sends
// nothing and writes no audit record, and a run admitted before the approval
// ran out may finish. The clock is injected and moved by the case, so no case
// waits and none depends on the machine it runs on.
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
import { locateCheckout } from "../src/adapters/checkout.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createProjectFiles } from "../src/adapters/project-files.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type {
  ProfileApprover,
  RegistrationApprover,
} from "../src/application/approvals.ts";
import { runOperation } from "../src/application/run.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import type {
  Transport,
  TransportOutcome,
  TransportRequest,
} from "../src/application/transport.ts";
import { runWard } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import {
  defaultApprovalTtlMs,
  parseApprovalTtl,
} from "../src/domain/approval-ttl.ts";
import { parseVaultState } from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const PROFILE = "example-profile";
const ALIAS = "example-token";
const T0 = Date.parse("2026-10-20T00:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const encoder = new TextEncoder();
const root = mkdtempSync(join(tmpdir(), "ward-expiry-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

class RecordingTransport implements Transport {
  sent = 0;
  async send(_request: TransportRequest): Promise<TransportOutcome> {
    this.sent++;
    return { kind: "response", httpStatus: 200 };
  }
}

const values: SecretValueSource = {
  available: () => true,
  readHidden: () => encoder.encode("synthetic-expiry-value"),
  readStdin: () => encoder.encode("synthetic-expiry-value"),
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

async function world() {
  const directory = join(mkdtempSync(join(root, `vault-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: "opum.ward.expiry",
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const store = createSqliteVaultStore({ directory });
  const transport = new RecordingTransport();
  let clock = T0;
  let ids = 0;
  const key = (): Uint8Array =>
    new Uint8Array(keychain.items.values().next().value as number[]);
  const state = () => parseVaultState(store.read(key()).plaintext);
  const revision = () => store.header()?.revision as number;
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
      now: () => new Date(clock),
      newId: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
      transport,
      machine: () => ({ user: "expiry-user", host: "expiry-host" }),
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
    },
  };
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  expect((await ward(["secret", "set", ALIAS, "--stdin"])).exitCode).toBe(
    exitCodes.success,
  );
  const approvalOf = () => state().profileApprovals[0];
  return {
    ward,
    state,
    revision,
    transport,
    approvalOf,
    setClock: (ms: number) => {
      clock = ms;
    },
    // The same run, with a clock the case sequences call by call: the first
    // reading is the run's read of the approval, the second is its admission,
    // the third is its completion.
    operate: (readings: number[]) => {
      const identity = locateCheckout(checkoutPath);
      let call = 0;
      return runOperation(
        { profile: PROFILE, actorLabel: undefined, taskLabel: undefined },
        {
          checkout: identity,
          files: createProjectFiles(identity.root),
          store,
          keyProvider,
          transport,
          now: () =>
            new Date(readings[Math.min(call++, readings.length - 1)] as number),
          newId: () =>
            `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
          observeMachine: () => null,
        },
      );
    },
  };
}

describe("the approval lifetime", () => {
  test("the grammar is a whole number and one unit, bounded to 1m through 30d", () => {
    expect(parseApprovalTtl("8h")).toBe(8 * HOUR);
    expect(parseApprovalTtl("1m")).toBe(60_000);
    expect(parseApprovalTtl("30d")).toBe(30 * 24 * HOUR);
    expect(defaultApprovalTtlMs).toBe(24 * HOUR);
    for (const refused of [
      "",
      "0h",
      "31d",
      "721h",
      "30s",
      "1w",
      "24",
      "h",
      "-1h",
      "1.5h",
      "08h",
      " 8h",
      "8h ",
      "8H",
    ])
      expect(parseApprovalTtl(refused)).toBeUndefined();
  });

  test("an approval lasts 24 hours by default and --ttl names another lifetime", async () => {
    const w = await world();
    const approved = await w.ward(["profile", "approve", PROFILE]);
    expect(approved.exitCode).toBe(exitCodes.success);
    const first = w.approvalOf();
    expect(
      Date.parse(first?.expiresAt as string) -
        Date.parse(first?.approvedAt as string),
    ).toBe(24 * HOUR);
    expect(JSON.parse(approved.stdout).data.expiresAt).toBe(first?.expiresAt);
    const short = await w.ward(["profile", "approve", PROFILE, "--ttl", "8h"]);
    expect(short.exitCode).toBe(exitCodes.success);
    const second = w.approvalOf();
    expect(w.state().profileApprovals).toHaveLength(1);
    expect(
      Date.parse(second?.expiresAt as string) -
        Date.parse(second?.approvedAt as string),
    ).toBe(8 * HOUR);
  });

  test("a lifetime outside the grammar is refused before the vault is touched", async () => {
    const w = await world();
    const revision = w.revision();
    for (const ttl of ["0h", "31d", "30s", "1w", "24", "8H"]) {
      const result = await w.ward([
        "profile",
        "approve",
        PROFILE,
        "--ttl",
        ttl,
      ]);
      expect(result.exitCode).toBe(exitCodes.usage);
      expect(errorCode(result.stderr)).toBe("profile_ttl_invalid");
    }
    expect(w.state().profileApprovals).toEqual([]);
    expect(w.revision()).toBe(revision);
    for (const args of [
      ["profile", "revoke", PROFILE, "--ttl", "8h"],
      ["profile", "list", "--ttl", "8h"],
    ]) {
      const result = await w.ward(args);
      expect(result.exitCode).toBe(exitCodes.usage);
      expect(errorCode(result.stderr)).toBe("profile_option_unexpected");
    }
  });
});

describe("an expired approval blocks new admissions", () => {
  test("a run succeeds before expiry and is refused at it and after it, sending and writing nothing", async () => {
    const w = await world();
    expect((await w.ward(["profile", "approve", PROFILE])).exitCode).toBe(
      exitCodes.success,
    );
    const expires = Date.parse(w.approvalOf()?.expiresAt as string);
    w.setClock(expires - 1);
    expect((await w.ward(["run", PROFILE])).exitCode).toBe(exitCodes.success);
    expect(w.transport.sent).toBe(1);
    const audit = w.state().auditRecords.length;
    const revision = w.revision();
    for (const at of [expires, expires + HOUR]) {
      w.setClock(at);
      const refused = await w.ward(["run", PROFILE]);
      expect(refused.exitCode).toBe(exitCodes.denied);
      expect(errorCode(refused.stderr)).toBe("profile_approval_expired");
    }
    expect(w.transport.sent).toBe(1);
    expect(w.state().auditRecords.length).toBe(audit);
    expect(w.revision()).toBe(revision);
  });

  test("list and check report the approval as expired, and approving again renews it", async () => {
    const w = await world();
    expect(
      (await w.ward(["profile", "approve", PROFILE, "--ttl", "1h"])).exitCode,
    ).toBe(exitCodes.success);
    w.setClock(T0 + 2 * HOUR);
    const listed = JSON.parse((await w.ward(["profile", "list"])).stdout).data
      .profiles as { approval: string }[];
    expect(listed[0]?.approval).toBe("expired");
    const checked = await w.ward(["check", PROFILE]);
    expect(checked.exitCode).toBe(exitCodes.validation);
    expect(JSON.parse(checked.stdout).data.profiles[0].reasons).toContain(
      "approval-expired",
    );
    expect((await w.ward(["profile", "approve", PROFILE])).exitCode).toBe(
      exitCodes.success,
    );
    expect(
      JSON.parse((await w.ward(["profile", "list"])).stdout).data.profiles[0]
        .approval,
    ).toBe("approved");
    expect((await w.ward(["run", PROFILE])).exitCode).toBe(exitCodes.success);
  });

  test("an approval that runs out between a run's read and its admission blocks it", async () => {
    const w = await world();
    expect(
      (await w.ward(["profile", "approve", PROFILE, "--ttl", "1h"])).exitCode,
    ).toBe(exitCodes.success);
    const revision = w.revision();
    await expect(
      w.operate([T0 + 30 * 60_000, T0 + 2 * HOUR]),
    ).rejects.toMatchObject({
      code: "profile_approval_expired",
    });
    expect(w.transport.sent).toBe(0);
    expect(w.state().auditRecords).toEqual([]);
    expect(w.revision()).toBe(revision);
  });

  test("a run admitted before expiry finishes, and its completion is recorded after it", async () => {
    const w = await world();
    expect(
      (await w.ward(["profile", "approve", PROFILE, "--ttl", "1h"])).exitCode,
    ).toBe(exitCodes.success);
    const result = (await w.operate([
      T0,
      T0 + 30 * 60_000,
      T0 + 48 * HOUR,
    ])) as unknown as {
      data: { auditRecorded: boolean };
    };
    expect(result.data.auditRecorded).toBe(true);
    expect(w.state().auditRecords.map((record) => record.phase)).toEqual([
      "admission",
      "completion",
    ]);
  });
});

describe("the stored expiry is exact", () => {
  const ids = {
    p: "00000000-0000-4000-8000-0000000000a1",
  };
  const approval = (overrides: Record<string, unknown>) => ({
    profile: PROFILE,
    projectId: ids.p,
    root: "/Users/dev/code/project",
    device: "1",
    inode: "2",
    approvedAt: "2026-10-20T00:00:00.000Z",
    expiresAt: "2026-10-21T00:00:00.000Z",
    snapshotVersion: 1,
    snapshot: {
      adapter: "http",
      method: "GET",
      url: "https://api.example.invalid/status",
      auth: { type: "bearer", secret: ALIAS },
      headers: {},
      requestBody: "none",
      output: "status",
    },
    ...overrides,
  });
  const document = (record: Record<string, unknown>) =>
    encoder.encode(
      JSON.stringify({ formatVersion: 1, profileApprovals: [record] }),
    );

  test("a missing expiry, a malformed one, or one not after approval is a damaged document", () => {
    expect(
      parseVaultState(document(approval({}))).profileApprovals,
    ).toHaveLength(1);
    const missing = approval({});
    delete (missing as Record<string, unknown>).expiresAt;
    expect(() => parseVaultState(document(missing))).toThrow();
    for (const expiresAt of [
      "tomorrow",
      "2026-10-20T00:00:00.000Z",
      "2026-10-19T00:00:00.000Z",
    ])
      expect(() =>
        parseVaultState(document(approval({ expiresAt }))),
      ).toThrow();
    expect(() => parseVaultState(document(approval({ extra: 1 })))).toThrow();
  });
});
