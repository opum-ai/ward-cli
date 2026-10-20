// WCLI-12: exact use-only cross-project grants (spec §7.2, docs/adr/0020,
// gates T12 and T21).
//
// Everything here is synthetic: a temporary vault directory, an in-memory
// keychain, a recording transport and a sentinel that stands in for a
// credential. The transport is what proves a refusal: a refused run is one
// the transport was never asked to send, and the vault's revision and audit
// count are the other two witnesses that nothing was admitted.
//
// The target and the owner are two checkouts of two projects in one vault,
// which is the situation a grant exists for. A refusal case asserts the
// whole-document state before and after rather than the one record it is
// about, so a write that landed somewhere else would still fail it.
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
import { createProjectFiles } from "../src/adapters/project-files.ts";
import { runOperation } from "../src/application/run.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type {
  GrantApprover,
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
import {
  emptyVaultState,
  parseVaultState,
  serializeVaultState,
  type VaultState,
  withRevokedGrant,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const OWNER_VALUE = "synthetic-owner-value-5e2a";
const ROTATED_VALUE = "synthetic-rotated-value-91c7";
const OWNER_ALIAS = "owner-token";
const TARGET_ALIAS = "shared-token";
const PROFILE = "example-profile";
const HOST = "api.example.invalid";
const encoder = new TextEncoder();
const root = mkdtempSync(join(tmpdir(), "ward-grant-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

class RecordingTransport implements Transport {
  readonly sent: { value: string; url: string }[] = [];
  onSend: (() => void) | undefined;
  async send(request: TransportRequest): Promise<TransportOutcome> {
    this.sent.push({
      value: Buffer.from(request.authorization.value)
        .toString()
        .replace(/^Bearer /, ""),
      url: request.url,
    });
    const hook = this.onSend;
    this.onSend = undefined;
    hook?.();
    return { kind: "response", httpStatus: 200 };
  }
}

class Values implements SecretValueSource {
  value = encoder.encode(OWNER_VALUE);
  available = () => true;
  readHidden = () => this.value.slice();
  readStdin = () => this.value.slice();
  confirmReplace = () => true;
}

const registration: RegistrationApprover = {
  available: () => true,
  ask: () => "approved",
};
const profileApprover: ProfileApprover = {
  available: () => true,
  ask: () => "approved",
};

let cases = 0;

// One machine: a vault directory, a keychain and the answers a developer
// would give. Two of them are what a restore needs.
function machine() {
  const directory = join(mkdtempSync(join(root, `vault-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: "opum.ward.grant",
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const transport = new RecordingTransport();
  const values = new Values();
  let grantAnswer: "approved" | "declined" | "unavailable" = "approved";
  const grantApprover: GrantApprover = {
    available: () => grantAnswer !== "unavailable",
    ask: () => grantAnswer,
  };
  let ids = 0;
  const store = createSqliteVaultStore({ directory });
  const key = (): Uint8Array => {
    const stored = keychain.items.values().next().value as number[] | undefined;
    if (stored === undefined) throw new Error("no vault key is stored");
    return new Uint8Array(stored);
  };
  const state = (): VaultState => parseVaultState(store.read(key()).plaintext);
  const revision = (): number => store.header()?.revision as number;

  const ward = (cwd: string, args: string[], json = true) =>
    runWard(json ? [...args, "--json"] : args, {
      wardDirectory: directory,
      keyProvider,
      approver: registration,
      profileApprover,
      grantApprover,
      secrets: values,
      passphrases: {
        available: () => true,
        read: () => encoder.encode("grant-test"),
      },
      cwd,
      now: () => new Date("2026-10-20T00:00:00.000Z"),
      newId: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
      transport,
      machine: () => ({ user: "grant-user", host: "grant-host" }),
    });

  return {
    ward,
    directory,
    keyProvider,
    store,
    key,
    state,
    revision,
    transport,
    values,
    answerGrants: (answer: "approved" | "declined" | "unavailable") => {
      grantAnswer = answer;
    },
  };
}

function worktree(): string {
  const path = join(root, `repo-${++cases}`);
  mkdirSync(path);
  mkdirSync(join(path, ".git"));
  return path;
}

function projectIdOf(checkout: string): string {
  return (
    JSON.parse(
      readFileSync(join(checkout, ".ward", "project.json"), "utf8"),
    ) as {
      projectId: string;
    }
  ).projectId;
}

function declareProfile(checkout: string, secret: string): void {
  const path = join(checkout, ".ward", "project.json");
  const manifest = JSON.parse(readFileSync(path, "utf8")) as {
    profiles?: Record<string, unknown>;
  };
  manifest.profiles = {
    [PROFILE]: {
      adapter: "http",
      method: "GET",
      url: `https://${HOST}/status`,
      auth: { type: "bearer", secret },
      requestBody: "none",
      output: "status",
    },
  };
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
}

// An owner with a secret, a target that has declared a profile naming the
// granted alias, and both registered. No grant exists yet.
async function world() {
  const m = machine();
  const owner = worktree();
  const target = worktree();
  expect((await m.ward(owner, ["setup"])).exitCode).toBe(exitCodes.success);
  expect((await m.ward(owner, ["init"])).exitCode).toBe(exitCodes.success);
  expect((await m.ward(target, ["init"])).exitCode).toBe(exitCodes.success);
  declareProfile(target, TARGET_ALIAS);
  const set = await m.ward(owner, ["secret", "set", OWNER_ALIAS, "--stdin"]);
  expect(set.exitCode).toBe(exitCodes.success);
  const grant = () =>
    m.ward(owner, [
      "secret",
      "grant",
      OWNER_ALIAS,
      "--to",
      projectIdOf(target),
      "--as",
      TARGET_ALIAS,
    ]);
  const approve = () => m.ward(target, ["profile", "approve", PROFILE]);
  const run = () => m.ward(target, ["run", PROFILE]);
  return {
    m,
    owner,
    target,
    ownerId: projectIdOf(owner),
    targetId: projectIdOf(target),
    grant,
    approve,
    run,
  };
}

// The full set-up a working grant needs: granted, and the target's profile
// approved.
async function granted() {
  const w = await world();
  expect((await w.grant()).exitCode).toBe(exitCodes.success);
  expect((await w.approve()).exitCode).toBe(exitCodes.success);
  return w;
}

describe("T12: exact sharing works", () => {
  test("a grant records one owner secret, one target and one alias, and discloses no value", async () => {
    const w = await world();
    const result = await w.grant();
    expect(result.exitCode).toBe(exitCodes.success);
    const state = w.m.state();
    expect(state.sharingGrants).toHaveLength(1);
    const [grant] = state.sharingGrants;
    const secret = state.secrets.find((entry) => entry.alias === OWNER_ALIAS);
    expect(grant).toEqual({
      id: (JSON.parse(result.stdout).data as { grantId: string }).grantId,
      ownerProjectId: w.ownerId,
      ownerSecretId: secret?.id as string,
      targetProjectId: w.targetId,
      targetAlias: TARGET_ALIAS,
      createdAt: "2026-10-20T00:00:00.000Z",
      revokedAt: null,
    });
    // The target sees the alias, marked as granted, and not the owner's alias
    // or record.
    const listRaw = await w.m.ward(w.target, ["secret", "list"]);
    const listed = JSON.parse(listRaw.stdout).data.secrets as {
      alias: string;
      ownership: string;
      updatedAt: string | null;
      revision: number | null;
    }[];
    expect(listed).toEqual([
      {
        alias: TARGET_ALIAS,
        ownership: "granted",
        updatedAt: null,
        revision: null,
      },
    ]);
    const inspected = await w.m.ward(w.target, [
      "secret",
      "inspect",
      TARGET_ALIAS,
    ]);
    expect(inspected.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(inspected.stdout).data.ownership).toBe("granted");
    expect(JSON.parse(inspected.stdout).data.ownerProjectId).toBe(w.ownerId);
    for (const text of [
      result.stdout,
      result.stderr,
      listRaw.stdout,
      inspected.stdout,
    ])
      expect(text).not.toContain(OWNER_VALUE);
    // The owner's own list does not show the grant as an owned secret twice.
    const ownerList = JSON.parse(
      (await w.m.ward(w.owner, ["secret", "list"])).stdout,
    ).data.secrets as { alias: string }[];
    expect(ownerList.map((entry) => entry.alias)).toEqual([OWNER_ALIAS]);
  });

  test("a target run sends the owner's value in the approved header, and an owner update shows on the next run", async () => {
    const w = await granted();
    expect((await w.run()).exitCode).toBe(exitCodes.success);
    expect(w.m.transport.sent.map((sent) => sent.value)).toEqual([OWNER_VALUE]);
    expect(w.m.transport.sent[0]?.url).toBe(`https://${HOST}/status`);
    const ward = w.m;
    ward.values.value = encoder.encode(ROTATED_VALUE);
    expect(
      (await ward.ward(w.owner, ["secret", "set", OWNER_ALIAS, "--stdin"]))
        .exitCode,
    ).toBe(exitCodes.success);
    expect((await w.run()).exitCode).toBe(exitCodes.success);
    expect(w.m.transport.sent.map((sent) => sent.value)).toEqual([
      OWNER_VALUE,
      ROTATED_VALUE,
    ]);
    // The run's audit records name the owner's secret id, and no value.
    const state = w.m.state();
    const secret = state.secrets.find((entry) => entry.alias === OWNER_ALIAS);
    expect(
      state.auditRecords.every((record) => record.secretId === secret?.id),
    ).toBe(true);
    expect(JSON.stringify(state.auditRecords)).not.toContain(ROTATED_VALUE);
  });

  test("a target cannot update, delete, re-grant or revoke a granted alias, and the vault is untouched", async () => {
    const w = await granted();
    const before = JSON.stringify(w.m.state());
    const revision = w.m.revision();
    const attempts: string[][] = [
      ["secret", "set", TARGET_ALIAS, "--stdin"],
      ["secret", "delete", TARGET_ALIAS],
      [
        "secret",
        "grant",
        TARGET_ALIAS,
        "--to",
        w.ownerId,
        "--as",
        "another-alias",
      ],
      ["secret", "revoke", TARGET_ALIAS, "--from", w.ownerId],
    ];
    for (const args of attempts) {
      const result = await w.m.ward(w.target, args);
      expect(result.exitCode).toBe(exitCodes.denied);
      expect(errorCode(result.stderr)).toBe("secret_granted_readonly");
    }
    expect(w.m.revision()).toBe(revision);
    expect(JSON.stringify(w.m.state())).toBe(before);
  });

  test("a grant cannot name a project this vault does not know, the owner itself, a taken alias, or a pair already granted", async () => {
    const w = await world();
    const grant = (to: string, as: string) =>
      w.m.ward(w.owner, [
        "secret",
        "grant",
        OWNER_ALIAS,
        "--to",
        to,
        "--as",
        as,
      ]);
    const revision = w.m.revision();
    const unknown = await grant(
      "00000000-0000-4000-8000-0000000000ff",
      "x-alias",
    );
    expect(errorCode(unknown.stderr)).toBe("grant_target_unknown");
    expect(unknown.exitCode).toBe(exitCodes.notFound);
    const self = await grant(w.ownerId, "x-alias");
    expect(errorCode(self.stderr)).toBe("grant_target_is_owner");
    const invalid = await grant("not-an-id", "x-alias");
    expect(errorCode(invalid.stderr)).toBe("grant_project_invalid");
    // The target already owns the alias: a collision is refused, not shadowed.
    expect(
      (await w.m.ward(w.target, ["secret", "set", TARGET_ALIAS, "--stdin"]))
        .exitCode,
    ).toBe(exitCodes.success);
    const collision = await grant(w.targetId, TARGET_ALIAS);
    expect(errorCode(collision.stderr)).toBe("grant_alias_conflict");
    expect(collision.exitCode).toBe(exitCodes.conflict);
    expect(w.m.state().sharingGrants).toEqual([]);
    expect(w.m.revision()).toBe(revision + 1);
    // One owner secret goes to one target once.
    expect((await grant(w.targetId, "free-alias")).exitCode).toBe(
      exitCodes.success,
    );
    const twice = await grant(w.targetId, "other-free-alias");
    expect(errorCode(twice.stderr)).toBe("grant_exists");
    // And a granted alias cannot be created as an own secret in the target.
    const shadow = await w.m.ward(w.target, [
      "secret",
      "set",
      "free-alias",
      "--stdin",
    ]);
    expect(shadow.exitCode).toBe(exitCodes.denied);
    expect(errorCode(shadow.stderr)).toBe("secret_granted_readonly");
  });

  test("a grant is the developer's act: no terminal and a declined question both leave no record", async () => {
    const w = await world();
    const revision = w.m.revision();
    w.m.answerGrants("unavailable");
    const none = await w.grant();
    expect(none.exitCode).toBe(exitCodes.denied);
    expect(errorCode(none.stderr)).toBe("grant_requires_terminal");
    w.m.answerGrants("declined");
    const declined = await w.grant();
    expect(declined.exitCode).toBe(exitCodes.denied);
    expect(errorCode(declined.stderr)).toBe("grant_declined");
    expect(w.m.state().sharingGrants).toEqual([]);
    expect(w.m.revision()).toBe(revision);
  });

  test("the reports a person reads mark the alias as granted and state the admission-time rule", async () => {
    // `--json` never prints the human text, so this measures it without.
    const w = await world();
    const text = (cwd: string, args: string[]) =>
      runWard(args, {
        wardDirectory: w.m.directory,
        keyProvider: w.m.keyProvider,
        approver: registration,
        profileApprover,
        grantApprover: { available: () => true, ask: () => "approved" },
        secrets: w.m.values,
        cwd,
        now: () => new Date("2026-10-20T00:00:00.000Z"),
      });
    expect((await w.grant()).exitCode).toBe(exitCodes.success);
    const rule =
      "Revocation blocks runs admitted after it. A run admitted before it may finish, and Ward cannot recall a credential already sent.";
    const list = await text(w.target, ["secret", "list"]);
    const inspect = await text(w.target, ["secret", "inspect", TARGET_ALIAS]);
    const revoke = await text(w.owner, [
      "secret",
      "revoke",
      OWNER_ALIAS,
      "--from",
      w.targetId,
    ]);
    expect(list.stdout).toContain(`${TARGET_ALIAS}  (granted, use only)`);
    expect(inspect.stdout).toContain("ownership: granted, use only");
    expect(revoke.stdout).toContain(rule);
    for (const output of [list, inspect, revoke])
      expect(output.stdout + output.stderr).not.toContain(OWNER_VALUE);
  });

  test("grant and revoke take only their own options", async () => {
    const w = await world();
    const code = async (args: string[]) => {
      const result = await w.m.ward(w.owner, args);
      return [result.exitCode, errorCode(result.stderr)];
    };
    expect(
      await code(["secret", "grant", OWNER_ALIAS, "--to", w.targetId]),
    ).toEqual([exitCodes.usage, "missing_required_option"]);
    expect(
      await code([
        "secret",
        "grant",
        OWNER_ALIAS,
        "--to",
        w.targetId,
        "--as",
        "a-b",
        "--from",
        w.targetId,
      ]),
    ).toEqual([exitCodes.usage, "secret_option_unexpected"]);
    expect(await code(["secret", "revoke", OWNER_ALIAS])).toEqual([
      exitCodes.usage,
      "missing_required_option",
    ]);
    expect(
      await code([
        "secret",
        "revoke",
        OWNER_ALIAS,
        "--from",
        w.targetId,
        "--to",
        w.targetId,
      ]),
    ).toEqual([exitCodes.usage, "secret_option_unexpected"]);
    expect(await code(["secret", "list", "--to", w.targetId])).toEqual([
      exitCodes.usage,
      "secret_option_unexpected",
    ]);
  });
});

describe("T12: revocation and owner deletion block new admissions", () => {
  // The witnesses a refused run leaves: the transport was never asked, the
  // vault's revision did not move, and no admission or completion record was
  // written.
  async function expectRefused(
    w: Awaited<ReturnType<typeof granted>>,
    code: string,
  ) {
    const sent = w.m.transport.sent.length;
    const audit = w.m.state().auditRecords.length;
    const revision = w.m.revision();
    const result = await w.run();
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe(code);
    expect(w.m.transport.sent.length).toBe(sent);
    expect(w.m.state().auditRecords.length).toBe(audit);
    expect(w.m.revision()).toBe(revision);
  }

  test("a revoked grant refuses the next run before anything is sent", async () => {
    const w = await granted();
    expect((await w.run()).exitCode).toBe(exitCodes.success);
    const revoked = await w.m.ward(w.owner, [
      "secret",
      "revoke",
      OWNER_ALIAS,
      "--from",
      w.targetId,
    ]);
    expect(revoked.exitCode).toBe(exitCodes.success);
    // The report states the admission-time rule.
    expect(JSON.parse(revoked.stdout).data.revokedAt).toBe(
      "2026-10-20T00:00:00.000Z",
    );
    expect(
      String(JSON.parse(revoked.stdout).data.grantId).length,
    ).toBeGreaterThan(0);
    await expectRefused(w, "grant_revoked");
    const state = w.m.state();
    expect(state.sharingGrants).toHaveLength(1);
    expect(state.sharingGrants[0]?.revokedAt).toBe("2026-10-20T00:00:00.000Z");
    // The target no longer lists it, and revoking twice finds nothing.
    const listed = JSON.parse(
      (await w.m.ward(w.target, ["secret", "list"])).stdout,
    ).data.secrets as unknown[];
    expect(listed).toEqual([]);
    const again = await w.m.ward(w.owner, [
      "secret",
      "revoke",
      OWNER_ALIAS,
      "--from",
      w.targetId,
    ]);
    expect(errorCode(again.stderr)).toBe("grant_not_found");
    expect(again.exitCode).toBe(exitCodes.notFound);
  });

  test("readiness reports a revoked grant as revoked and never advises storing a local secret", async () => {
    const w = await granted();
    const ready = await w.m.ward(w.target, ["check", PROFILE]);
    expect(ready.exitCode).toBe(exitCodes.success);
    const revoked = await w.m.ward(w.owner, [
      "secret",
      "revoke",
      OWNER_ALIAS,
      "--from",
      w.targetId,
    ]);
    expect(revoked.exitCode).toBe(exitCodes.success);
    const json = await w.m.ward(w.target, ["check", PROFILE]);
    expect(json.exitCode).toBe(exitCodes.validation);
    const reasons = JSON.parse(json.stdout).data.profiles[0]
      .reasons as string[];
    expect(reasons).toContain("grant-revoked");
    expect(reasons).not.toContain("secret");
    const listed = JSON.parse(
      (await w.m.ward(w.target, ["profile", "list"])).stdout,
    ).data.profiles as { secret: string }[];
    expect(listed[0]?.secret).toBe("revoked");
    // The text a person reads: it says why, and does not tell them to store a
    // secret, which would block the owner's re-grant.
    const text = await w.m.ward(w.target, ["check", PROFILE], false);
    expect(text.stdout).toContain("revoked");
    expect(text.stdout).not.toContain("ward secret set");
    // And the advice it replaces really is harmful: a local secret under the
    // alias refuses the re-grant.
    expect(
      (await w.m.ward(w.target, ["secret", "set", TARGET_ALIAS, "--stdin"]))
        .exitCode,
    ).toBe(exitCodes.success);
    const regrant = await w.grant();
    expect(regrant.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(regrant.stderr)).toBe("grant_alias_conflict");
  });

  test("deleting the owner secret revokes its grants in the same write, and a re-created alias is not the granted secret", async () => {
    const w = await granted();
    expect(
      (await w.m.ward(w.owner, ["secret", "delete", OWNER_ALIAS])).exitCode,
    ).toBe(exitCodes.success);
    const state = w.m.state();
    expect(
      state.secrets.find((entry) => entry.alias === OWNER_ALIAS),
    ).toBeUndefined();
    expect(state.sharingGrants.every((grant) => grant.revokedAt !== null)).toBe(
      true,
    );
    await expectRefused(w, "grant_revoked");
    // The owner creates a new secret under the same alias: new id, and the
    // old grant does not revive.
    w.m.values.value = encoder.encode(ROTATED_VALUE);
    expect(
      (await w.m.ward(w.owner, ["secret", "set", OWNER_ALIAS, "--stdin"]))
        .exitCode,
    ).toBe(exitCodes.success);
    await expectRefused(w, "grant_revoked");
    expect(w.m.transport.sent).toEqual([]);
  });

  test("a run admitted before revocation finishes, and its completion is recorded", async () => {
    const w = await granted();
    w.m.transport.onSend = () => {
      // The grant is revoked while the request is in flight, from outside the
      // run, the way a second Ward process would revoke it.
      w.m.store.mutate(w.m.key(), (plaintext) => {
        const current = parseVaultState(plaintext);
        const id = current.sharingGrants[0]?.id as string;
        return serializeVaultState(
          withRevokedGrant(current, id, "2026-10-20T00:00:01.000Z"),
        );
      });
    };
    const result = await w.run();
    expect(result.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(result.stdout).data.auditRecorded).toBe(true);
    expect(w.m.state().auditRecords.map((record) => record.phase)).toEqual([
      "admission",
      "completion",
    ]);
    await expectRefused(w, "grant_revoked");
  });

  test("a revocation landing between a run's read and its admission blocks it", async () => {
    const w = await granted();
    const identity = locateCheckout(w.target);
    let revoked = false;
    const racing = {
      header: () => w.m.store.header(),
      create: w.m.store.create.bind(w.m.store),
      read: w.m.store.read.bind(w.m.store),
      mutate: (
        key: Uint8Array,
        change: Parameters<typeof w.m.store.mutate>[1],
      ) => {
        if (!revoked) {
          revoked = true;
          w.m.store.mutate(w.m.key(), (plaintext) => {
            const current = parseVaultState(plaintext);
            return serializeVaultState(
              withRevokedGrant(
                current,
                current.sharingGrants[0]?.id as string,
                "2026-10-20T00:00:01.000Z",
              ),
            );
          });
        }
        return w.m.store.mutate(key, change);
      },
    };
    const sent = w.m.transport.sent.length;
    await expect(
      runOperation(
        { profile: PROFILE, actorLabel: undefined, taskLabel: undefined },
        {
          checkout: identity,
          files: createProjectFiles(identity.root),
          store: racing,
          keyProvider: w.m.keyProvider,
          transport: w.m.transport,
          now: () => new Date("2026-10-20T00:00:02.000Z"),
          newId: () => "00000000-0000-4000-8000-0000000000aa",
          observeMachine: () => null,
        },
      ),
    ).rejects.toMatchObject({ code: "grant_revoked" });
    expect(w.m.transport.sent.length).toBe(sent);
    expect(w.m.state().auditRecords).toEqual([]);
  });

  test("no document with an active grant and no owner secret can be written", async () => {
    // The writer refuses the state the reader would refuse, so a deletion that
    // forgot its grants fails rather than leaving a vault nothing can open.
    const w = await granted();
    const state = w.m.state();
    const withoutOwner: VaultState = {
      ...state,
      secrets: state.secrets.filter((entry) => entry.alias !== OWNER_ALIAS),
    };
    expect(() => serializeVaultState(withoutOwner)).toThrow();
  });
});

describe("the grant record is exact and its relations are enforced", () => {
  const ids = {
    a: "00000000-0000-4000-8000-00000000000a",
    b: "00000000-0000-4000-8000-00000000000b",
    s: "00000000-0000-4000-8000-0000000000e1",
    g: "00000000-0000-4000-8000-0000000000f1",
  };
  const stamp = "2026-10-20T00:00:00.000Z";
  const secret = (id: string, projectId: string, alias: string) => ({
    id,
    projectId,
    alias,
    value: Buffer.from("x").toString("base64"),
    createdAt: stamp,
    updatedAt: stamp,
    revision: 1,
  });
  const grant = {
    id: ids.g,
    ownerProjectId: ids.a,
    ownerSecretId: ids.s,
    targetProjectId: ids.b,
    targetAlias: "shared-token",
    createdAt: stamp,
    revokedAt: null as string | null,
  };
  const document = (overrides: Record<string, unknown> = {}) =>
    encoder.encode(
      JSON.stringify({
        formatVersion: 1,
        projects: [
          { id: ids.a, createdAt: stamp },
          { id: ids.b, createdAt: stamp },
        ],
        localBindings: [],
        secrets: [secret(ids.s, ids.a, "owner-token")],
        profileApprovals: [],
        sharingGrants: [grant],
        auditRecords: [],
        ...overrides,
      }),
    );

  test("a well-formed document round-trips byte for byte", () => {
    const bytes = document();
    expect(
      new TextDecoder().decode(serializeVaultState(parseVaultState(bytes))),
    ).toBe(new TextDecoder().decode(bytes));
    expect(
      parseVaultState(serializeVaultState(emptyVaultState())).sharingGrants,
    ).toEqual([]);
  });

  test("an unknown key, a missing key, a bad id or alias, or an owner target is malformed", () => {
    const refused = (changed: Record<string, unknown>) =>
      expect(() =>
        parseVaultState(
          document({ sharingGrants: [{ ...grant, ...changed }] }),
        ),
      ).toThrow();
    refused({ extra: 1 });
    refused({ revokedAt: undefined });
    refused({ revokedAt: "yesterday" });
    refused({ targetAlias: "Not An Alias" });
    refused({ ownerSecretId: "nope" });
    refused({ targetProjectId: ids.a });
    expect(() =>
      parseVaultState(document({ sharingGrants: "none" })),
    ).toThrow();
  });

  test("an active grant must name an existing owner secret of the owner project", () => {
    expect(() => parseVaultState(document({ secrets: [] }))).toThrow();
    expect(() =>
      parseVaultState(
        document({ secrets: [secret(ids.s, ids.b, "owner-token")] }),
      ),
    ).toThrow();
    // A revoked grant is a tombstone and needs no secret.
    expect(
      parseVaultState(
        document({
          secrets: [],
          sharingGrants: [{ ...grant, revokedAt: stamp }],
        }),
      ).sharingGrants,
    ).toHaveLength(1);
  });

  test("two active grants for one target alias, or one that collides with a target secret, are malformed", () => {
    const second = { ...grant, id: "00000000-0000-4000-8000-0000000000f2" };
    expect(() =>
      parseVaultState(document({ sharingGrants: [grant, second] })),
    ).toThrow();
    expect(() =>
      parseVaultState(
        document({
          secrets: [
            secret(ids.s, ids.a, "owner-token"),
            secret(
              "00000000-0000-4000-8000-0000000000e2",
              ids.b,
              "shared-token",
            ),
          ],
        }),
      ),
    ).toThrow();
  });
});

describe("T21: restore clears grants and approvals", () => {
  test("a restored vault holds no grant or approval, and the target needs both again", async () => {
    const source = await granted();
    // The positive control: the same profile runs before the restore.
    expect((await source.run()).exitCode).toBe(exitCodes.success);
    const file = join(root, `backup-${++cases}.json`);
    expect(
      (await source.m.ward(source.owner, ["backup", "--output", file]))
        .exitCode,
    ).toBe(exitCodes.success);

    const restored = machine();
    const restore = await restored.ward(source.owner, [
      "restore",
      "--input",
      file,
    ]);
    expect(restore.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(restore.stdout).data).toMatchObject({
      bindings: "cleared",
      approvals: "cleared",
      grants: "cleared",
    });
    const state = restored.state();
    expect(state.sharingGrants).toEqual([]);
    expect(state.profileApprovals).toEqual([]);
    expect(state.localBindings).toEqual([]);
    // The secrets and the projects came across.
    expect(state.secrets.map((entry) => entry.alias)).toEqual([OWNER_ALIAS]);

    // Re-registered and re-approved, the target is still refused: the grant
    // is gone, and an approval alone never made the alias resolve.
    expect((await restored.ward(source.target, ["init"])).exitCode).toBe(
      exitCodes.success,
    );
    expect(
      (await restored.ward(source.target, ["profile", "approve", PROFILE]))
        .exitCode,
    ).toBe(exitCodes.success);
    const refused = await restored.ward(source.target, ["run", PROFILE]);
    expect(refused.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(refused.stderr)).toBe("secret_not_found");
    expect(restored.transport.sent).toEqual([]);

    // Only a fresh grant from the re-registered owner makes it run again.
    expect((await restored.ward(source.owner, ["init"])).exitCode).toBe(
      exitCodes.success,
    );
    expect(
      (
        await restored.ward(source.owner, [
          "secret",
          "grant",
          OWNER_ALIAS,
          "--to",
          source.targetId,
          "--as",
          TARGET_ALIAS,
        ])
      ).exitCode,
    ).toBe(exitCodes.success);
    expect(
      (await restored.ward(source.target, ["run", PROFILE])).exitCode,
    ).toBe(exitCodes.success);
    expect(restored.transport.sent.map((sent) => sent.value)).toEqual([
      OWNER_VALUE,
    ]);
  });
});
