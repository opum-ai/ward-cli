// WCLI-7: `ward init` and the project binding (spec §7.1, §11.2).
//
// T10's shapes, one test each: an unknown project, a copied project id, a
// nested repository, a linked worktree, a moved path, and a clone — including
// a directory replaced at the very same path. Every one of them must resolve
// to "unregistered", because the binding names a canonical worktree root and
// that directory's identity, not a project id a repository can carry with it.
//
// T22's file shapes live in the second half: repeated init preserves user
// content and peer blocks, and a malformed marker or an escaping symlink is a
// conflict, never an overwrite. Every case here runs against a temporary
// vault, a memory credential store and a throwaway checkout; nothing touches
// the developer's ~/.ward, real keychain or repositories.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { locateCheckout } from "../src/adapters/checkout.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createProjectFiles } from "../src/adapters/project-files.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type {
  RegistrationAnswer,
  RegistrationApprover,
  RegistrationRequest,
} from "../src/application/approvals.ts";
import { wardBlockBody } from "../src/application/bridges.ts";
import { bindingFor, readCheckout } from "../src/application/project.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { parseVaultState, type VaultState } from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SERVICE = "opum.ward.binding";
const REGISTERED_AT = "2026-09-28T12:00:00.000Z";

const root = mkdtempSync(join(tmpdir(), "ward-binding-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;

// What the terminal would answer, without a terminal.
class FakeTerminal implements RegistrationApprover {
  interactive = true;
  answer: RegistrationAnswer = "approved";
  asks = 0;
  lastRequest: RegistrationRequest | undefined;

  available(): boolean {
    return this.interactive;
  }

  ask(request: RegistrationRequest): RegistrationAnswer {
    this.asks += 1;
    this.lastRequest = request;
    return this.answer;
  }
}

// A directory that looks like a Git worktree to the resolver: `.git` as a
// directory is an ordinary checkout, `.git` as a file is a linked worktree or
// a submodule (spec §7.1). The resolver reads neither.
function worktree(
  name: string,
  git: "directory" | "file" = "directory",
): string {
  const directory = join(root, `${name}-${++cases}`);
  mkdirSync(directory);
  if (git === "directory") mkdirSync(join(directory, ".git"));
  else
    writeFileSync(
      join(directory, ".git"),
      `gitdir: ${directory}/.git/worktrees/x\n`,
    );
  return directory;
}

function manifestPath(checkout: string): string {
  return join(checkout, ".ward", "project.json");
}

function copyManifest(from: string, to: string): void {
  mkdirSync(join(to, ".ward"), { recursive: true });
  writeFileSync(manifestPath(to), readFileSync(manifestPath(from)));
}

function harness() {
  const directory = join(mkdtempSync(join(root, `case-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const keyProvider = createKeychainKeyProvider({
    service: SERVICE,
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const approver = new FakeTerminal();
  const store = createSqliteVaultStore({ directory });

  const options = (
    cwd: string,
    extra: Partial<RunOptions> = {},
  ): RunOptions => ({
    wardDirectory: directory,
    keyProvider,
    approver,
    cwd,
    now: () => new Date(REGISTERED_AT),
    ...extra,
  });

  // The vault's decrypted state, or undefined when setup has not run.
  const state = (): VaultState | undefined => {
    const stored = keychain.items.values().next().value as number[] | undefined;
    if (stored === undefined) return undefined;
    return parseVaultState(store.read(new Uint8Array(stored)).plaintext);
  };

  // The resolution every later command performs: the canonical root of the
  // directory, the manifest Ward finds at that root, and the binding the
  // vault holds for that root and no other.
  const resolve = (cwd: string) => {
    const identity = locateCheckout(cwd);
    const checkout = readCheckout(identity, createProjectFiles(identity.root));
    const current = state();
    return {
      root: identity.root,
      projectId: checkout.manifest?.projectId,
      binding:
        current === undefined ? undefined : bindingFor(current, checkout),
    };
  };

  const setUp = async (cwd: string) => {
    const result = await runWard(["setup", "--json"], options(cwd));
    expect(result.exitCode).toBe(exitCodes.success);
  };

  const init = async (
    cwd: string,
    args: string[] = [],
    extra: Partial<RunOptions> = {},
  ) => await runWard(["init", ...args, "--json"], options(cwd, extra));

  return {
    directory,
    keychain,
    store,
    approver,
    options,
    state,
    resolve,
    setUp,
    init,
  };
}

const json = (output: string) =>
  JSON.parse(output) as {
    kind: string;
    data: {
      projectId: string;
      root: string;
      manifest: string;
      bridges: { target: string; document: string; status: string }[];
      registration: string;
    };
  };

const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

describe("T10: no checkout inherits a binding", () => {
  test("only an approved registration creates one", async () => {
    const h = harness();
    const checkout = worktree("approved");
    await h.setUp(checkout);

    expect(h.resolve(checkout).binding).toBeUndefined();
    const skipped = await h.init(checkout, ["--no-register"]);
    expect(skipped.exitCode).toBe(exitCodes.success);
    expect(json(skipped.stdout).data.registration).toBe("skipped");
    expect(json(skipped.stdout).data.manifest).toBe("created");
    expect(h.resolve(checkout).binding).toBeUndefined();

    h.approver.answer = "declined";
    const declined = await h.init(checkout);
    expect(declined.exitCode).toBe(exitCodes.success);
    expect(json(declined.stdout).data.registration).toBe("declined");
    expect(h.resolve(checkout).binding).toBeUndefined();

    h.approver.answer = "approved";
    const registered = await h.init(checkout);
    expect(registered.exitCode).toBe(exitCodes.success);
    const data = json(registered.stdout).data;
    expect(data.registration).toBe("registered");
    expect(data.manifest).toBe("present");
    expect(data.projectId).toMatch(/^[0-9a-f-]{36}$/);
    expect(data.root).toBe(realpathSync(checkout));
    expect(h.approver.lastRequest?.root).toBe(realpathSync(checkout));

    const state = h.state();
    expect(state?.localBindings).toHaveLength(1);
    const [binding] = state?.localBindings ?? [];
    expect(binding?.projectId).toBe(data.projectId);
    expect(binding?.root).toBe(realpathSync(checkout));
    expect(binding?.registeredAt).toBe(REGISTERED_AT);
    expect(binding?.device).toMatch(/^\d+$/);
    expect(binding?.inode).toMatch(/^\d+$/);
    expect(state?.projects).toEqual([
      { id: data.projectId, createdAt: REGISTERED_AT },
    ]);
    expect(h.resolve(checkout).binding?.projectId).toBe(data.projectId);
  });

  test("a copied manifest brings a project id and no binding", async () => {
    const h = harness();
    const original = worktree("copied-source");
    const copy = worktree("copied-target");
    await h.setUp(original);
    const registered = json((await h.init(original)).stdout).data;

    copyManifest(original, copy);
    const resolved = h.resolve(copy);
    expect(resolved.projectId).toBe(registered.projectId);
    expect(resolved.binding).toBeUndefined();
    expect(h.state()?.localBindings).toHaveLength(1);

    // Declining leaves it that way, and it stays a separate project when the
    // developer does register it.
    h.approver.answer = "declined";
    await h.init(copy);
    expect(h.resolve(copy).binding).toBeUndefined();

    h.approver.answer = "approved";
    await h.init(copy);
    expect(h.resolve(copy).binding?.projectId).toBe(registered.projectId);
    expect(h.resolve(original).binding?.projectId).toBe(registered.projectId);
    expect(h.state()?.localBindings).toHaveLength(2);
    expect(h.state()?.projects).toHaveLength(1);
  });

  test("a manifest naming a project the vault has never seen is unbound", async () => {
    const h = harness();
    const known = worktree("known-project");
    const stranger = worktree("unknown-project");
    await h.setUp(known);
    json((await h.init(known)).stdout);

    mkdirSync(join(stranger, ".ward"), { recursive: true });
    writeFileSync(
      manifestPath(stranger),
      JSON.stringify({ schemaVersion: 1, projectId: randomUUID() }),
    );
    const resolved = h.resolve(stranger);
    expect(resolved.projectId).toBeDefined();
    expect(resolved.binding).toBeUndefined();
    expect(h.state()?.localBindings).toHaveLength(1);
  });

  test("a nested repository is its own root, not its parent's", async () => {
    const h = harness();
    const parent = worktree("nested-parent");
    await h.setUp(parent);
    const registered = json((await h.init(parent)).stdout).data;

    const nested = join(parent, "vendor", "sub");
    mkdirSync(join(nested, ".git"), { recursive: true });
    expect(h.resolve(nested).root).toBe(realpathSync(nested));
    expect(h.resolve(nested).projectId).toBeUndefined();
    expect(h.resolve(nested).binding).toBeUndefined();

    // Even carrying the parent's manifest, the nested root is unregistered.
    copyManifest(parent, nested);
    expect(h.resolve(nested).projectId).toBe(registered.projectId);
    expect(h.resolve(nested).binding).toBeUndefined();
    // And the parent's own binding is untouched.
    expect(h.resolve(parent).binding?.root).toBe(realpathSync(parent));
  });

  test("a linked worktree is a checkout of its own", async () => {
    const h = harness();
    const main = worktree("worktree-main");
    await h.setUp(main);
    const registered = json((await h.init(main)).stdout).data;

    const linked = worktree("worktree-linked", "file");
    copyManifest(main, linked);
    expect(h.resolve(linked).root).toBe(realpathSync(linked));
    expect(h.resolve(linked).binding).toBeUndefined();
    expect(h.resolve(main).binding?.root).toBe(realpathSync(main));

    // An explicitly registered worktree is a second approved root for the
    // same project, not a replacement for the first.
    h.approver.answer = "approved";
    const second = await h.init(linked);
    expect(json(second.stdout).data.registration).toBe("registered");
    expect(h.state()?.localBindings).toHaveLength(2);
    expect(h.state()?.projects).toHaveLength(1);
    expect(h.resolve(linked).binding?.projectId).toBe(registered.projectId);
    expect(h.resolve(main).binding?.root).toBe(realpathSync(main));
  });

  test("moving a checkout ends its binding", async () => {
    const h = harness();
    const before = worktree("moved-before");
    const after = worktree("moved-after");
    await h.setUp(before);
    json((await h.init(before)).stdout);
    const registered = h.resolve(before);
    expect(registered.binding?.root).toBe(realpathSync(before));

    rmSync(after, { recursive: true, force: true });
    renameSync(before, after);
    // The same directory — same device and inode — at a new path.
    expect(h.resolve(after).root).toBe(realpathSync(after));
    expect(h.resolve(after).binding).toBeUndefined();
    expect(h.resolve(after).projectId).toBe(registered.projectId);

    const blocked = await h.init(after, ["--no-register"]);
    expect(blocked.exitCode).toBe(exitCodes.success);
    expect(h.resolve(after).binding).toBeUndefined();
  });

  test("a clone at another path has no binding, even with the manifest", async () => {
    const h = harness();
    const source = worktree("clone-source");
    const clone = worktree("clone-target");
    await h.setUp(source);
    const registered = json((await h.init(source)).stdout).data;

    copyManifest(source, clone);
    expect(h.resolve(clone).projectId).toBe(registered.projectId);
    expect(h.resolve(clone).binding).toBeUndefined();
    expect(h.state()?.localBindings).toHaveLength(1);
  });

  test("a directory replaced at the same path is a new checkout", async () => {
    const h = harness();
    const checkout = worktree("replaced");
    await h.setUp(checkout);
    const registered = json((await h.init(checkout)).stdout).data;
    const manifest = readFileSync(manifestPath(checkout));

    const before = locateCheckout(checkout);
    rmSync(checkout, { recursive: true, force: true });
    mkdirSync(join(checkout, ".git"), { recursive: true });
    mkdirSync(join(checkout, ".ward"));
    writeFileSync(manifestPath(checkout), manifest);
    const after = locateCheckout(checkout);

    // The precondition this case exists for: the path is identical and the
    // directory behind it is not.
    expect(after.root).toBe(before.root);
    expect(after.inode).not.toBe(before.inode);
    expect(h.resolve(checkout).projectId).toBe(registered.projectId);
    expect(h.resolve(checkout).binding).toBeUndefined();
  });

  test("re-registering the same checkout asks nothing and writes nothing", async () => {
    const h = harness();
    const checkout = worktree("repeat");
    await h.setUp(checkout);
    const first = json((await h.init(checkout)).stdout).data;
    const revision = h.store.header()?.revision;
    const asks = h.approver.asks;

    const second = await h.init(checkout);
    expect(second.exitCode).toBe(exitCodes.success);
    expect(json(second.stdout).data.registration).toBe("already-registered");
    expect(json(second.stdout).data.projectId).toBe(first.projectId);
    expect(h.approver.asks).toBe(asks);
    expect(h.store.header()?.revision).toBe(revision);
  });

  test("a checkout registered to another project is a conflict", async () => {
    const h = harness();
    const checkout = worktree("conflict");
    await h.setUp(checkout);
    json((await h.init(checkout)).stdout);
    const before = h.state();

    // Someone replaced the manifest of a registered checkout.
    mkdirSync(join(checkout, ".ward"), { recursive: true });
    writeFileSync(
      manifestPath(checkout),
      JSON.stringify({
        schemaVersion: 1,
        projectId: "8b0d1ff6-6f2f-4d5c-9c33-0f5a0f1c7d21",
      }),
    );
    const result = await h.init(checkout);
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("binding_conflict");
    expect(h.state()).toEqual(before);
    expect(h.approver.asks).toBe(1);
  });

  test("without a terminal, registration is refused before the vault is read", async () => {
    const h = harness();
    const checkout = worktree("headless");
    await h.setUp(checkout);
    h.approver.interactive = false;
    const reads = h.keychain.readAttempts;

    const result = await h.init(checkout);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("binding_requires_terminal");
    // The manifest is still prepared; the credential store is never reached.
    expect(existsSync(manifestPath(checkout))).toBe(true);
    expect(h.keychain.readAttempts).toBe(reads);
    expect(h.approver.asks).toBe(0);
    expect(h.state()?.localBindings).toEqual([]);
  });

  test("without a vault, init prepares the files and names setup", async () => {
    const h = harness();
    const checkout = worktree("unconfigured");

    const result = await h.init(checkout, ["--claude"]);
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(result.stderr)).toBe("vault_not_found");
    expect(existsSync(manifestPath(checkout))).toBe(true);
    expect(readFileSync(join(checkout, "CLAUDE.md"), "utf8")).toContain(
      "<!-- ward:begin -->",
    );
    expect(h.resolve(checkout).binding).toBeUndefined();
  });

  test("--no-register never reaches the vault or the credential store", async () => {
    const h = harness();
    const checkout = worktree("prepare-only");
    await h.setUp(checkout);
    const revision = h.store.header()?.revision;
    const reads = h.keychain.readAttempts;

    const result = await h.init(checkout, [
      "--no-register",
      "--claude",
      "--codex",
    ]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(h.keychain.readAttempts).toBe(reads);
    expect(h.approver.asks).toBe(0);
    expect(h.store.header()?.revision).toBe(revision);
    expect(h.state()?.localBindings).toEqual([]);
  });

  test("outside a Git worktree there is no root to bind", async () => {
    const h = harness();
    const directory = join(root, `nowhere-${++cases}`);
    mkdirSync(directory);
    await h.setUp(directory);

    const result = await h.init(directory);
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(result.stderr)).toBe("worktree_not_found");
    expect(existsSync(join(directory, ".ward"))).toBe(false);
  });

  test("a repository that would hold the user vault is refused", async () => {
    const h = harness();
    const home = mkdtempSync(join(root, `home-${++cases}-`));
    mkdirSync(join(home, ".git"));
    const directory = join(home, ".ward");

    const result = await runWard(["init", "--json"], {
      ...h.options(home),
      wardDirectory: directory,
    });
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("project_path_unsafe");
  });
});

describe("T22: init preserves every file it does not own", () => {
  const peerBlock = [
    "<!-- quest:agent-instructions:begin -->",
    "# Quest agent instructions",
    "<!-- quest:agent-instructions:end -->",
    "",
    "<!-- lore:agents:begin -->",
    "This repo uses lore.",
    "<!-- lore:agents:end -->",
    "",
  ].join("\n");

  test("repeated init keeps user content and peer blocks byte for byte", async () => {
    const h = harness();
    const checkout = worktree("preserve");
    const user = `# Project\n\nUser prose the developer wrote.\n\n${peerBlock}\nSee [docs](./docs).\n`;
    writeFileSync(join(checkout, "CLAUDE.md"), user);

    const first = await h.init(checkout, ["--no-register", "--claude"]);
    expect(first.exitCode).toBe(exitCodes.success);
    const once = readFileSync(join(checkout, "CLAUDE.md"), "utf8");
    expect(once.startsWith(user)).toBe(true);
    expect(once).toContain(peerBlock);
    expect(json(first.stdout).data.bridges).toEqual([
      { target: "claude", document: "CLAUDE.md", status: "updated" },
    ]);

    const second = await h.init(checkout, ["--no-register", "--claude"]);
    expect(json(second.stdout).data.bridges).toEqual([
      { target: "claude", document: "CLAUDE.md", status: "unchanged" },
    ]);
    expect(readFileSync(join(checkout, "CLAUDE.md"), "utf8")).toBe(once);
  });

  test("a stale Ward block is refreshed and nothing else moves", async () => {
    const h = harness();
    const checkout = worktree("stale");
    const before =
      "# Project\n\n<!-- ward:begin -->\nold guidance\n<!-- ward:end -->\n\nAfter.\n";
    writeFileSync(join(checkout, "CLAUDE.md"), before);

    const result = await h.init(checkout, ["--no-register", "--claude"]);
    expect(result.exitCode).toBe(exitCodes.success);
    const after = readFileSync(join(checkout, "CLAUDE.md"), "utf8");
    expect(after).toBe(
      `# Project\n\n<!-- ward:begin -->\n${wardBlockBody}<!-- ward:end -->\n\nAfter.\n`,
    );
    expect(after).not.toContain("old guidance");
  });

  test("both hosts are written, and a file with no block is created holding only it", async () => {
    const h = harness();
    const checkout = worktree("targets");
    const result = await h.init(checkout, [
      "--no-register",
      "--claude",
      "--codex",
    ]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(
      json(result.stdout).data.bridges.map((bridge) => bridge.document),
    ).toEqual(["CLAUDE.md", "AGENTS.md"]);
    for (const name of ["CLAUDE.md", "AGENTS.md"]) {
      const text = readFileSync(join(checkout, name), "utf8");
      expect(text.startsWith("<!-- ward:begin -->")).toBe(true);
      expect(text).toContain("## Credentials: Ward");
      expect(text.trimEnd().endsWith("<!-- ward:end -->")).toBe(true);
    }
  });

  test("malformed markers are a conflict, and the file is untouched", async () => {
    const h = harness();
    for (const [label, text] of [
      ["a begin marker without an end", "<!-- ward:begin -->\nbody\n"],
      [
        "two Ward pairs",
        "<!-- ward:begin -->\na\n<!-- ward:end -->\n<!-- ward:begin -->\nb\n<!-- ward:end -->\n",
      ],
      ["an end before its begin", "<!-- ward:end -->\n<!-- ward:begin -->\n"],
    ] as [string, string][]) {
      const checkout = worktree(`markers-${label.replaceAll(" ", "-")}`);
      writeFileSync(join(checkout, "CLAUDE.md"), text);
      const result = await h.init(checkout, ["--no-register", "--claude"]);
      expect(result.exitCode).toBe(exitCodes.conflict);
      expect(errorCode(result.stderr)).toBe("instructions_markers_conflict");
      expect(readFileSync(join(checkout, "CLAUDE.md"), "utf8")).toBe(text);
    }
  });

  test("a link that leaves the repository is refused, not followed", async () => {
    const h = harness();
    const checkout = worktree("escaping-link");
    const outside = join(root, `outside-${++cases}`);
    mkdirSync(outside);
    const target = join(outside, "CLAUDE.md");
    writeFileSync(target, "# Elsewhere\n");
    symlinkSync(target, join(checkout, "CLAUDE.md"));

    const result = await h.init(checkout, ["--no-register", "--claude"]);
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("project_path_unsafe");
    expect(readFileSync(target, "utf8")).toBe("# Elsewhere\n");
    expect(lstatSync(join(checkout, "CLAUDE.md")).isSymbolicLink()).toBe(true);
  });

  test("a link inside the repository is followed, and the link survives", async () => {
    const h = harness();
    const checkout = worktree("inside-link");
    symlinkSync(join(checkout, "CLAUDE.md"), join(checkout, "AGENTS.md"));

    const result = await h.init(checkout, [
      "--no-register",
      "--claude",
      "--codex",
    ]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(lstatSync(join(checkout, "AGENTS.md")).isSymbolicLink()).toBe(true);
    expect(readFileSync(join(checkout, "CLAUDE.md"), "utf8")).toContain(
      "<!-- ward:begin -->",
    );
  });

  test("a project directory that is a link out of the repository is refused", async () => {
    const h = harness();
    const checkout = worktree("linked-dotward");
    const outside = join(root, `outside-dotward-${++cases}`);
    mkdirSync(outside);
    symlinkSync(outside, join(checkout, ".ward"));

    const result = await h.init(checkout, ["--no-register"]);
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("project_path_unsafe");
    expect(readdirSync(outside)).toEqual([]);
  });

  test("a malformed manifest is refused rather than replaced", async () => {
    const h = harness();
    const checkout = worktree("malformed-manifest");
    mkdirSync(join(checkout, ".ward"));
    const text = '{"schemaVersion":1,"projectId":"not-an-id"}\n';
    writeFileSync(manifestPath(checkout), text);

    const result = await h.init(checkout, ["--no-register"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(errorCode(result.stderr)).toBe("project_manifest_malformed");
    expect(readFileSync(manifestPath(checkout), "utf8")).toBe(text);
  });

  test("a manifest from a newer Ward is refused, not downgraded", async () => {
    const h = harness();
    const checkout = worktree("newer-manifest");
    mkdirSync(join(checkout, ".ward"));
    const text = `${JSON.stringify({
      schemaVersion: 2,
      projectId: "33b05c92-8a6e-4f15-9dcb-65ae5d371123",
      profiles: { deploy: {} },
    })}\n`;
    writeFileSync(manifestPath(checkout), text);

    const result = await h.init(checkout, ["--no-register"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(errorCode(result.stderr)).toBe("project_manifest_unsupported");
    expect(readFileSync(manifestPath(checkout), "utf8")).toBe(text);
  });

  test("an existing manifest keeps its project id across runs", async () => {
    const h = harness();
    const checkout = worktree("stable-id");
    const first = json((await h.init(checkout, ["--no-register"])).stdout).data;
    const text = readFileSync(manifestPath(checkout), "utf8");
    const second = json(
      (await h.init(checkout, ["--no-register"])).stdout,
    ).data;
    expect(second.projectId).toBe(first.projectId);
    expect(second.manifest).toBe("present");
    expect(readFileSync(manifestPath(checkout), "utf8")).toBe(text);
  });
});
