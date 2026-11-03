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
import { createTerminalUnregisterApprover } from "../src/adapters/terminal-consent.ts";
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
  errorCatalog,
  errorEnvelope,
  WardError,
} from "../src/contract/errors.ts";
import {
  findBinding,
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
    expect(kept.text).toContain("Registering this same clone again");
    expect(kept.text).toContain(
      "an approval written by an earlier version never does",
    );
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

  // DEC-255 (a7): a record a 0.1.1 build wrote has no nonce, so it matches
  // nothing; unregister, run in the checkout, clears it and its approvals
  // anyway, because removing a record grants nothing and a user must have a
  // way to clear their own records.
  const makeFirstLegacy = (w: Awaited<ReturnType<typeof world>>) => {
    const firstRoot = locateCheckout(w.first).root;
    w.store.mutate(w.key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const strip = <T extends { root: string; checkoutId?: string }>(
        record: T,
      ): T => {
        if (record.root !== firstRoot) return record;
        const { checkoutId: _dropped, ...rest } = record;
        return rest as T;
      };
      return serializeVaultState({
        ...current,
        localBindings: current.localBindings.map(strip),
        profileApprovals: current.profileApprovals.map(strip),
      });
    });
  };

  test("a legacy binding matches nothing, and unregister clears it with its legacy approvals", async () => {
    const w = await world();
    makeFirstLegacy(w);
    const before = w.state();
    const identity = locateCheckout(w.first);
    expect(identity.checkoutId).toBeDefined();
    // Never matched: the checkout is unregistered as far as authority goes.
    expect(findBinding(before, identity)).toBeUndefined();
    const refused = await w.ward(w.first, ["run", PROFILE]);
    expect(refused.exitCode).toBe(exitCodes.denied);
    expect(errorCode(refused.stderr)).toBe("project_not_registered");
    expect(w.transport.sent).toBe(0);

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
    expect(after.localBindings.map((binding) => binding.root)).toEqual([
      locateCheckout(w.second).root,
    ]);
    expect(after.profileApprovals.map((approval) => approval.root)).toEqual([
      locateCheckout(w.second).root,
    ]);
    // Still no authority afterwards.
    expect((await w.ward(w.first, ["run", PROFILE])).exitCode).toBe(
      exitCodes.denied,
    );
  });

  test("declining leaves a legacy binding and its approvals exactly as they were", async () => {
    const w = await world();
    makeFirstLegacy(w);
    const before = JSON.stringify(w.state());
    const result = await w.ward(
      w.first,
      ["unregister"],
      scripted(["declined"]).approver,
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(result.stdout).data).toMatchObject({
      status: "declined",
    });
    expect(JSON.stringify(w.state())).toBe(before);
  });

  test("a legacy binding beside a current one is cleared with it, and the other checkout is untouched", async () => {
    const w = await world();
    const identity = locateCheckout(w.first);
    // A 0.1.1 record at the same directory, beside this build's.
    w.store.mutate(w.key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const mine = current.localBindings.find(
        (binding) => binding.root === identity.root,
      );
      if (mine === undefined) throw new Error("fixture has no binding");
      const { checkoutId: _dropped, ...legacy } = mine;
      return serializeVaultState({
        ...current,
        localBindings: [...current.localBindings, legacy],
      });
    });
    expect(w.state().localBindings).toHaveLength(3);
    const result = await w.ward(
      w.first,
      ["unregister"],
      scripted(["approved", "approved"]).approver,
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(w.state().localBindings.map((binding) => binding.root)).toEqual([
      locateCheckout(w.second).root,
    ]);
  });

  // The nonce comparisons inside unregister itself (belongsTo and
  // withoutBinding): another clone's records at the same root, device and inode
  // but another nonce are not this checkout's, so they are neither counted nor
  // removed. Dropping either comparison turns this red.
  test("a record at the same directory identity with another nonce is left alone", async () => {
    const w = await world();
    const identity = locateCheckout(w.first);
    const other = "d".repeat(32);
    w.store.mutate(w.key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const mine = current.localBindings.find(
        (binding) => binding.root === identity.root,
      );
      const approval = current.profileApprovals.find(
        (entry) => entry.root === identity.root,
      );
      if (mine === undefined || approval === undefined)
        throw new Error("fixture has no record");
      return serializeVaultState({
        ...current,
        localBindings: [
          ...current.localBindings,
          { ...mine, checkoutId: other },
        ],
        profileApprovals: [
          ...current.profileApprovals,
          { ...approval, checkoutId: other },
        ],
      });
    });
    const result = await w.ward(
      w.first,
      ["unregister"],
      scripted(["approved", "approved"]).approver,
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(JSON.parse(result.stdout).data).toMatchObject({
      binding: "removed",
      approvalsRemoved: 1,
    });
    const after = w.state();
    expect(
      after.localBindings.filter((binding) => binding.root === identity.root),
    ).toEqual([expect.objectContaining({ checkoutId: other })]);
    expect(
      after.profileApprovals.filter((entry) => entry.root === identity.root),
    ).toEqual([expect.objectContaining({ checkoutId: other })]);
  });

  // WCLI-137 (N2): a legacy binding of another project at this directory is not
  // shown, counted or removed; unregister takes one project's records.
  test("a legacy binding and approval of another project at this directory are left alone", async () => {
    const w = await world();
    const identity = locateCheckout(w.first);
    const other = "99999999-9999-4999-8999-999999999999";
    w.store.mutate(w.key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const mine = current.localBindings.find(
        (binding) => binding.root === identity.root,
      );
      const approval = current.profileApprovals.find(
        (entry) => entry.root === identity.root,
      );
      const project = current.projects[0];
      if (mine === undefined || approval === undefined || project === undefined)
        throw new Error("fixture has no record");
      const { checkoutId: _binding, ...legacyBinding } = mine;
      const { checkoutId: _approval, ...legacyApproval } = approval;
      return serializeVaultState({
        ...current,
        projects: [...current.projects, { ...project, id: other }],
        localBindings: [
          ...current.localBindings,
          { ...legacyBinding, projectId: other },
        ],
        profileApprovals: [
          ...current.profileApprovals,
          { ...legacyApproval, projectId: other },
        ],
      });
    });
    const { approver, asked } = scripted(["approved", "approved"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);
    // Shown and counted: this project's one approval, not the other project's.
    expect(asked.map((question) => question.approvals)).toEqual([1, 1]);
    expect(asked.every((question) => question.projectId !== other)).toBe(true);
    expect(JSON.parse(result.stdout).data).toMatchObject({
      approvalsRemoved: 1,
    });
    const after = w.state();
    expect(
      after.localBindings
        .filter((binding) => binding.root === identity.root)
        .map((binding) => binding.projectId),
    ).toEqual([other]);
    expect(
      after.profileApprovals
        .filter((entry) => entry.root === identity.root)
        .map((entry) => entry.projectId),
    ).toEqual([other]);
  });

  // WCLI-137 (opus L2): two legacy bindings of different projects at one
  // directory identity. Unregistering one removes that one only: the other is
  // neither shown nor counted, so it is not removed either (DEC-255 a8).
  test("two legacy bindings at one directory identity: only the shown project's is removed", async () => {
    const w = await world();
    makeFirstLegacy(w);
    const identity = locateCheckout(w.first);
    const other = "88888888-8888-4888-8888-888888888888";
    w.store.mutate(w.key(), (plaintext) => {
      const current = parseVaultState(plaintext);
      const mine = current.localBindings.find(
        (binding) => binding.root === identity.root,
      );
      const project = current.projects[0];
      if (mine === undefined || project === undefined)
        throw new Error("fixture has no record");
      return serializeVaultState({
        ...current,
        projects: [...current.projects, { ...project, id: other }],
        localBindings: [
          ...current.localBindings,
          { ...mine, projectId: other },
        ],
      });
    });
    const shown = w
      .state()
      .localBindings.find((binding) => binding.root === identity.root);
    const { approver, asked } = scripted(["approved", "approved"]);
    const result = await w.ward(w.first, ["unregister"], approver);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(asked[0]?.projectId).toBe(shown?.projectId);
    expect(
      w
        .state()
        .localBindings.filter((binding) => binding.root === identity.root)
        .map((binding) => binding.projectId),
    ).toEqual([other]);
  });

  // WCLI-137 (N3): a record that appears between the question and the write was
  // never shown, so the removal is refused and nothing is removed.
  // DEC-255 (a9): a changed removal set has its own retryable conflict code,
  // with the ruled wording, and project_not_registered stays for no binding.
  test("binding_changed is a conflict with the ruled message and hint", () => {
    expect(errorCatalog.binding_changed.type).toBe("conflict");
    expect(errorEnvelope(new WardError("binding_changed"))).toMatchObject({
      error_type: "conflict",
      code: "binding_changed",
      message:
        "This checkout's registration changed while the command was running, so Ward removed nothing.",
      hint: "Run `ward unregister` again to see what is registered now.",
    });
  });

  test("a binding that appears between the question and the write is not removed unseen", async () => {
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
        // A second Ward process registers a legacy binding of the same project
        // at this directory after the developer has answered.
        w.store.mutate(w.key(), (plaintext) => {
          const current = parseVaultState(plaintext);
          const mine = current.localBindings.find(
            (binding) => binding.root === identity.root,
          );
          if (mine === undefined) throw new Error("fixture has no binding");
          const { checkoutId: _dropped, ...legacy } = mine;
          return serializeVaultState({
            ...current,
            localBindings: [...current.localBindings, legacy],
          });
        });
        return w.store.mutate(key, change);
      },
    };
    const before = w.state().profileApprovals.length;
    await expect(
      runUnregister({
        checkout: identity,
        store: racing,
        keyProvider: w.keyProvider,
        approver: scripted(["approved", "approved"]).approver,
      }),
    ).rejects.toMatchObject({ code: "binding_changed" });
    const after = w.state();
    expect(after.profileApprovals).toHaveLength(before);
    expect(
      after.localBindings.filter((binding) => binding.root === identity.root),
    ).toHaveLength(2);
  });

  // WCLI-137 (N1): the question the developer answers must not promise that a
  // kept approval from an earlier version comes back.
  test("the second question says only this version's approvals revive", () => {
    let written = "";
    const approver = createTerminalUnregisterApprover({
      isInteractive: () => true,
      writePrompt: (text: string) => {
        written += text;
      },
      readAnswer: () => "n",
    });
    approver.ask({
      kind: "approvals",
      projectId: "p",
      root: "/work/repo",
      approvals: 2,
    });
    expect(written).toContain("registering this same clone again");
    expect(written).toContain(
      "an approval written by an earlier version never does",
    );
    expect(written).not.toContain("this same directory");
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
    ).rejects.toMatchObject({ code: "binding_changed" });
    expect(w.state().profileApprovals).toHaveLength(2);
  });

  // DEC-255 (a9): the set can change while the binding stays. A second Ward
  // process withdraws this checkout's approval after the developer answered, so
  // what would be removed is no longer what was shown. Nothing is removed.
  test("an approval that changes between the question and the write is refused as binding_changed", async () => {
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
        w.store.mutate(w.key(), (plaintext) => {
          const current = parseVaultState(plaintext);
          return serializeVaultState({
            ...current,
            profileApprovals: current.profileApprovals.slice(1),
          });
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
    ).rejects.toMatchObject({ code: "binding_changed" });
    const after = w.state();
    expect(after.profileApprovals).toHaveLength(1);
    expect(
      after.localBindings.filter((binding) => binding.root === identity.root),
    ).toHaveLength(1);
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
