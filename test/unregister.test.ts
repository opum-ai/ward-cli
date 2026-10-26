// WCLI-73: `ward unregister` (DEC-217 Q4, docs/adr/0022).
//
// The command withdraws one checkout's access and nothing else, so the cases
// are about the edges of "one": another checkout of the same project keeps its
// binding and its approvals, a checkout that is not registered is refused, and
// the second confirmation decides the approvals independently of the binding.
// Each refusal is measured against the whole serialized document.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  copyFileSync,
  mkdirSync,
  renameSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { locateCheckout } from "../src/adapters/checkout.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type {
  ProfileAnswer,
  ProfileApprover,
  RegistrationApprover,
  UnregisterApprover,
  UnregisterQuestion,
} from "../src/application/approvals.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import type {
  Transport,
  TransportOutcome,
  TransportRequest,
} from "../src/application/transport.ts";
import { runUnregister } from "../src/application/unregister.ts";
import { runWard } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import {
  findProfileApproval,
  parseVaultState,
  serializeVaultState,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const PROFILE = "example-profile";
const ALIAS = "example-token";
const encoder = new TextEncoder();
const root = mkdtempSync(join(tmpdir(), "ward-unregister-"));
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
  readHidden: () => encoder.encode("synthetic-unregister-value"),
  readStdin: () => encoder.encode("synthetic-unregister-value"),
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

// An unregister approver the case scripts: the answers it will give in order,
// and the questions it was actually asked.
function scripted(answers: ProfileAnswer[], available = true) {
  const asked: UnregisterQuestion[] = [];
  const approver: UnregisterApprover = {
    available: () => available,
    ask: (question) => {
      asked.push(question);
      return answers.shift() ?? "declined";
    },
  };
  return { approver, asked };
}

let cases = 0;

async function world() {
  const directory = join(mkdtempSync(join(root, `vault-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: "opum.ward.unregister",
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const store = createSqliteVaultStore({ directory });
  const transport = new RecordingTransport();
  let ids = 0;
  const key = (): Uint8Array =>
    new Uint8Array(keychain.items.values().next().value as number[]);
  const state = () => parseVaultState(store.read(key()).plaintext);
  const revision = () => store.header()?.revision as number;
  const worktree = (): string => {
    const path = join(root, `repo-${++cases}`);
    mkdirSync(path);
    mkdirSync(join(path, ".git"));
    return path;
  };
  const ward = (
    cwd: string,
    args: string[],
    unregisterApprover?: UnregisterApprover,
  ) =>
    runWard([...args, "--json"], {
      wardDirectory: directory,
      keyProvider,
      approver: registration,
      profileApprover,
      ...(unregisterApprover === undefined ? {} : { unregisterApprover }),
      secrets: values,
      cwd,
      now: () => new Date("2026-10-20T00:00:00.000Z"),
      newId: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
      transport,
      machine: () => ({ user: "unregister-user", host: "unregister-host" }),
    });
  const first = worktree();
  expect((await ward(first, ["setup"])).exitCode).toBe(exitCodes.success);
  expect((await ward(first, ["init"])).exitCode).toBe(exitCodes.success);
  const manifestPath = join(first, ".ward", "project.json");
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
  expect(
    (await ward(first, ["secret", "set", ALIAS, "--stdin"])).exitCode,
  ).toBe(exitCodes.success);
  expect((await ward(first, ["profile", "approve", PROFILE])).exitCode).toBe(
    exitCodes.success,
  );
  // A second checkout of the same project, registered and approved on its own.
  const second = worktree();
  mkdirSync(join(second, ".ward"));
  copyFileSync(manifestPath, join(second, ".ward", "project.json"));
  expect((await ward(second, ["init"])).exitCode).toBe(exitCodes.success);
  expect((await ward(second, ["profile", "approve", PROFILE])).exitCode).toBe(
    exitCodes.success,
  );
  return {
    ward,
    state,
    revision,
    transport,
    store,
    key,
    keyProvider,
    first,
    second,
    worktree,
  };
}

describe("ward unregister", () => {
  test("removes this checkout's binding and, on a second yes, its approvals, and touches no other checkout", async () => {
    const w = await world();
    const before = w.state();
    expect(before.localBindings).toHaveLength(2);
    expect(before.profileApprovals).toHaveLength(2);
    const { approver, asked } = scripted(["approved", "approved"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(result.stdout).data).toMatchObject({
      status: "unregistered",
      binding: "removed",
      approvals: "removed",
      approvalsRemoved: 1,
    });
    expect(asked.map((question) => question.kind)).toEqual([
      "binding",
      "approvals",
    ]);
    const after = w.state();
    const firstRoot = locateCheckout(w.first).root;
    expect(after.localBindings.map((binding) => binding.root)).toEqual([
      locateCheckout(w.second).root,
    ]);
    expect(after.profileApprovals.map((approval) => approval.root)).toEqual([
      locateCheckout(w.second).root,
    ]);
    expect(
      after.localBindings.some((binding) => binding.root === firstRoot),
    ).toBe(false);
    // Everything but those two collections is byte-identical.
    expect(
      JSON.stringify({ ...after, localBindings: 0, profileApprovals: 0 }),
    ).toBe(
      JSON.stringify({ ...before, localBindings: 0, profileApprovals: 0 }),
    );
    const refused = await w.ward(w.first, ["run", PROFILE]);
    expect(refused.exitCode).toBe(exitCodes.denied);
    expect(errorCode(refused.stderr)).toBe("project_not_registered");
    expect(w.transport.sent).toBe(0);
    // The other checkout is unaffected and still runs.
    expect((await w.ward(w.second, ["run", PROFILE])).exitCode).toBe(
      exitCodes.success,
    );
  });

  test("declining the second question removes the binding and keeps the approvals, and says so", async () => {
    const w = await world();
    const { approver } = scripted(["approved", "declined"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(result.stdout).data).toMatchObject({
      binding: "removed",
      approvals: "kept",
      approvalsRemoved: 0,
    });
    const state = w.state();
    expect(state.localBindings).toHaveLength(1);
    expect(state.profileApprovals).toHaveLength(2);
    // The report a person reads says what was left behind.
    const w2 = await world();
    const kept = await runUnregister({
      checkout: locateCheckout(w2.first),
      store: w2.store,
      keyProvider: w2.keyProvider,
      approver: scripted(["approved", "declined"]).approver,
    });
    expect(kept.text).toContain("Its profile approvals were kept.");
    expect(kept.text).toContain("Registering this same directory");
  });

  test("declining the first question changes nothing and never asks the second", async () => {
    const w = await world();
    const before = JSON.stringify(w.state());
    const revision = w.revision();
    const { approver, asked } = scripted(["declined", "approved"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(result.stdout).data.status).toBe("declined");
    expect(asked.map((question) => question.kind)).toEqual(["binding"]);
    expect(JSON.stringify(w.state())).toBe(before);
    expect(w.revision()).toBe(revision);
  });

  test("a checkout with no approvals is asked once", async () => {
    const w = await world();
    expect(
      (await w.ward(w.first, ["profile", "revoke", PROFILE], undefined))
        .exitCode,
    ).toBe(exitCodes.success);
    const { approver, asked } = scripted(["approved", "approved"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(result.stdout).data.approvals).toBe("none");
    expect(asked.map((question) => question.kind)).toEqual(["binding"]);
  });

  test("an unregistered checkout is refused and the vault is untouched", async () => {
    const w = await world();
    const before = JSON.stringify(w.state());
    const revision = w.revision();
    const stranger = w.worktree();
    const { approver, asked } = scripted(["approved", "approved"]);
    const result = await w.ward(stranger, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("project_not_registered");
    expect(asked).toEqual([]);
    expect(JSON.stringify(w.state())).toBe(before);
    expect(w.revision()).toBe(revision);
  });

  test("an approval of another project at this identity is neither counted nor removed", async () => {
    const w = await world();
    // Another project's approval recorded at the first checkout's identity.
    const foreign = "00000000-0000-4000-8000-0000000000ff";
    w.store.mutate(w.key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const mine = current.profileApprovals.find(
        (approval) => approval.root === locateCheckout(w.first).root,
      );
      if (mine === undefined) throw new Error("fixture has no approval");
      return serializeVaultState({
        ...current,
        profileApprovals: [
          ...current.profileApprovals,
          { ...mine, projectId: foreign },
        ],
      });
    });
    expect(w.state().profileApprovals).toHaveLength(3);
    const { approver, asked } = scripted(["approved", "approved"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(asked.map((question) => question.approvals)).toEqual([1, 1]);
    expect(JSON.parse(result.stdout).data.approvalsRemoved).toBe(1);
    const kept = w.state().profileApprovals;
    expect(kept).toHaveLength(2);
    expect(kept.some((approval) => approval.projectId === foreign)).toBe(true);
  });

  test("a symlink to the checkout resolves to the physical directory", async () => {
    const w = await world();
    const link = join(root, `link-${++cases}`);
    symlinkSync(w.first, link);
    const result = await w.ward(
      link,
      ["unregister"],
      scripted(["approved", "approved"]).approver,
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(w.state().localBindings.map((binding) => binding.root)).toEqual([
      locateCheckout(w.second).root,
    ]);
  });

  test("a moved checkout and a separate worktree are refused and change nothing", async () => {
    const w = await world();
    const moved = join(root, `moved-${++cases}`);
    renameSync(w.first, moved);
    const before = JSON.stringify(w.state());
    const revision = w.revision();
    const { approver, asked } = scripted(["approved", "approved"]);
    for (const cwd of [moved, w.worktree()]) {
      const result = await w.ward(cwd, ["unregister"], approver);
      expect(result.exitCode).toBe(exitCodes.denied);
      expect(errorCode(result.stderr)).toBe("project_not_registered");
    }
    expect(asked).toEqual([]);
    expect(JSON.stringify(w.state())).toBe(before);
    expect(w.revision()).toBe(revision);
  });

  test("without a terminal it refuses before opening the vault", async () => {
    const w = await world();
    const before = JSON.stringify(w.state());
    const result = await w.ward(
      w.first,
      ["unregister"],
      scripted([], false).approver,
    );
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("unregister_requires_terminal");
    expect(JSON.stringify(w.state())).toBe(before);
    // A terminal that vanishes mid-question did not answer yes either.
    const gone = await w.ward(
      w.first,
      ["unregister"],
      scripted(["unavailable"]).approver,
    );
    expect(errorCode(gone.stderr)).toBe("unregister_requires_terminal");
    expect(JSON.stringify(w.state())).toBe(before);
  });

  test("it needs no manifest", async () => {
    const w = await world();
    rmSync(join(w.first, ".ward", "project.json"));
    const result = await w.ward(
      w.first,
      ["unregister"],
      scripted(["approved", "approved"]).approver,
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(w.state().localBindings).toHaveLength(1);
  });

  test("a binding that disappears between the read and the write removes nothing", async () => {
    const w = await world();
    const identity = locateCheckout(w.first);
    const racing = {
      header: () => w.store.header(),
      create: w.store.create.bind(w.store),
      read: w.store.read.bind(w.store),
      mutate: (
        key: Uint8Array,
        change: Parameters<typeof w.store.mutate>[1],
      ) => {
        // A second Ward process unregisters the same checkout first.
        w.store.mutate(w.key(), (plaintext) => {
          const current = parseVaultState(plaintext);
          return new TextEncoder().encode(
            JSON.stringify({
              ...JSON.parse(new TextDecoder().decode(plaintext)),
              localBindings: JSON.parse(
                new TextDecoder().decode(plaintext),
              ).localBindings.filter(
                (binding: { root: string }) => binding.root !== identity.root,
              ),
              projects: current.projects,
            }),
          );
        });
        return w.store.mutate(key, change);
      },
    };
    await expect(
      runUnregister({
        checkout: identity,
        store: racing,
        keyProvider: w.keyProvider,
        approver: scripted(["approved", "approved"]).approver,
      }),
    ).rejects.toMatchObject({ code: "project_not_registered" });
    expect(w.state().profileApprovals).toHaveLength(2);
  });

  // DEC-246 (a2) clause 3: a version-mismatched approval is authority the
  // developer still has to see. Unregistering the checkout it names removes
  // the binding and the current-version approval, and leaves the stale record
  // in the document — inert, still named by the reports — rather than
  // dropping it silently.
  test("a stale approval is kept inert when its checkout is unregistered", async () => {
    const w = await world();
    const identity = locateCheckout(w.first);
    w.store.mutate(w.key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const mine = current.profileApprovals.find(
        (approval) => approval.root === identity.root,
      );
      if (mine === undefined) throw new Error("fixture has no approval");
      const stored = {
        profile: mine.profile,
        projectId: mine.projectId,
        root: mine.root,
        device: mine.device,
        inode: mine.inode,
        approvedAt: mine.approvedAt,
        expiresAt: mine.expiresAt,
        snapshotVersion: 1,
        snapshot: {
          adapter: "http",
          method: "GET",
          url: "https://api.example.invalid/status",
          auth: { type: "bearer", secret: ALIAS },
          headers: [],
          requestBody: "none",
          output: "status",
        },
      };
      return serializeVaultState({
        ...current,
        profileApprovals: current.profileApprovals.filter(
          (approval) => approval !== mine,
        ),
        staleProfileApprovals: [
          ...current.staleProfileApprovals,
          {
            profile: mine.profile,
            projectId: mine.projectId,
            root: mine.root,
            device: mine.device,
            inode: mine.inode,
            snapshotVersion: 1,
            stored,
          },
        ],
      });
    });
    expect(w.state().staleProfileApprovals).toHaveLength(1);

    const { approver } = scripted(["approved", "approved"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);

    const after = w.state();
    // The binding and this checkout's current-version approval are gone...
    expect(after.localBindings.map((entry) => entry.root)).toEqual([
      locateCheckout(w.second).root,
    ]);
    expect(after.profileApprovals).toHaveLength(1);
    // ...and the stale record is still there, still inert.
    expect(after.staleProfileApprovals).toHaveLength(1);
    expect(after.staleProfileApprovals[0]?.root).toBe(identity.root);
    expect(
      findProfileApproval(
        after,
        identity,
        String(after.staleProfileApprovals[0]?.projectId),
        PROFILE,
      ),
    ).toBe(undefined);
  });
});
