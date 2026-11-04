// WCLI-125 (DEC-255 a2 clause 4, a6; ADR 0026): a checkout is identified by
// (root, device, inode) AND a nonce kept in the clone's own git directory.
// These cases do not depend on the filesystem: a record and a checkout with an
// identical directory identity and different nonces are different checkouts,
// whatever inode the platform hands out.
import "./support/no-real-keychain.ts";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, test } from "bun:test";
import {
  bindCheckoutIdentity,
  locateCheckout,
} from "../src/adapters/checkout.ts";
import { errorEnvelope, WardError } from "../src/contract/errors.ts";
import {
  type CheckoutIdentity,
  emptyVaultState,
  findBinding,
  findProfileApproval,
  parseVaultState,
  registerCheckout,
  serializeVaultState,
  withProfileApproval,
} from "../src/domain/vault-state.ts";
import {
  normalizeProfile,
  profileSnapshotVersion,
} from "../src/domain/profile.ts";

const root = mkdtempSync(join(tmpdir(), "ward-checkout-id-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let cases = 0;

const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
const timestamp = "2026-11-03T00:00:00.000Z";
const NONCE_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NONCE_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const encoder = new TextEncoder();

const base: CheckoutIdentity = {
  root: "/Users/dev/code/project",
  device: "16777232",
  inode: "8429931",
};

function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof WardError) return errorEnvelope(error).code;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("the nonce joins every match", () => {
  const bound = registerCheckout({
    state: emptyVaultState(),
    projectId,
    checkout: { ...base, checkoutId: NONCE_A },
    registeredAt: timestamp,
  });
  const profile = normalizeProfile({
    adapter: "http",
    method: "GET",
    url: "https://api.example.invalid/a",
    auth: { type: "bearer", secret: "example.token" },
    headers: {},
    requestBody: "none",
    output: "status",
  });
  const approved = withProfileApproval(bound, {
    profile: "deploy",
    projectId,
    ...base,
    checkoutId: NONCE_A,
    approvedAt: timestamp,
    expiresAt: "2026-11-04T00:00:00.000Z",
    snapshotVersion: profileSnapshotVersion,
    snapshot: profile,
  });

  test("the same directory identity and the same nonce is the same checkout", () => {
    const same = { ...base, checkoutId: NONCE_A };
    expect(findBinding(approved, same)?.projectId).toBe(projectId);
    expect(
      findProfileApproval(approved, same, projectId, "deploy"),
    ).toBeDefined();
  });

  test("the same root, device and inode with another nonce is a new checkout", () => {
    const reclone = { ...base, checkoutId: NONCE_B };
    expect(findBinding(approved, reclone)).toBeUndefined();
    expect(
      findProfileApproval(approved, reclone, projectId, "deploy"),
    ).toBeUndefined();
  });

  test("a checkout with no nonce matches nothing, and neither does a record with none", () => {
    expect(findBinding(approved, base)).toBeUndefined();
    expect(
      findProfileApproval(approved, base, projectId, "deploy"),
    ).toBeUndefined();
    const legacy = parseVaultState(
      encoder.encode(
        JSON.stringify({
          formatVersion: 1,
          projects: [{ id: projectId, createdAt: timestamp }],
          localBindings: [{ projectId, ...base, registeredAt: timestamp }],
          secrets: [],
          profileApprovals: [],
          sharingGrants: [],
          auditRecords: [],
        }),
      ),
    );
    expect(legacy.localBindings).toHaveLength(1);
    // Both with and without a nonce on the checkout, the legacy record is unbound.
    expect(
      findBinding(legacy, { ...base, checkoutId: NONCE_A }),
    ).toBeUndefined();
    expect(findBinding(legacy, base)).toBeUndefined();
  });
});

// DEC-255 (a7): approving also removes a legacy approval for the same profile at
// the same directory, so the new record replaces it. A removal only: the legacy
// record never matched for authorization, before or after.
describe("approving replaces a legacy approval, and a legacy record never authorizes", () => {
  const snapshot = normalizeProfile({
    adapter: "http",
    method: "GET",
    url: "https://api.example.invalid/a",
    auth: { type: "bearer", secret: "example.token" },
    headers: {},
    requestBody: "none",
    output: "status",
  });
  const record = (
    profile: string,
    overrides: Record<string, unknown> = {},
  ) => ({
    profile,
    projectId,
    ...base,
    approvedAt: timestamp,
    expiresAt: "2026-11-04T00:00:00.000Z",
    snapshotVersion: profileSnapshotVersion,
    snapshot,
    ...overrides,
  });
  const current = { ...base, checkoutId: NONCE_A };
  const stateWith = (...approvals: ReturnType<typeof record>[]) => ({
    ...emptyVaultState(),
    profileApprovals: approvals,
  });

  test("a legacy approval matches no checkout, with or without a nonce", () => {
    const state = stateWith(record("deploy"));
    expect(
      findProfileApproval(state, current, projectId, "deploy"),
    ).toBeUndefined();
    expect(
      findProfileApproval(state, base, projectId, "deploy"),
    ).toBeUndefined();
  });

  test("approving removes the legacy approval for the same profile and directory", () => {
    const replaced = withProfileApproval(
      stateWith(record("deploy")),
      record("deploy", { checkoutId: NONCE_A }) as never,
    );
    expect(replaced.profileApprovals).toHaveLength(1);
    expect(replaced.profileApprovals[0]?.checkoutId).toBe(NONCE_A);
    expect(
      findProfileApproval(replaced, current, projectId, "deploy"),
    ).toBeDefined();
  });

  test("it removes only that: other profiles, other directories and another clone's approval stay", () => {
    const other = record("status-check");
    const elsewhere = record("deploy", { inode: "1" });
    const anotherClone = record("deploy", { checkoutId: NONCE_B });
    // One legacy approval per field the replacement matches on, each differing
    // from the new record in that field alone: dropping any one comparison in
    // isReplacedBy would remove it (WCLI-137 N5).
    const otherProject = record("deploy", {
      projectId: "44b05c92-8a6e-4f15-9dcb-65ae5d371124",
    });
    const otherRoot = record("deploy", { root: "/Users/dev/code/elsewhere" });
    const otherDevice = record("deploy", { device: "16777233" });
    const kept = [
      other,
      elsewhere,
      anotherClone,
      otherProject,
      otherRoot,
      otherDevice,
    ];
    const replaced = withProfileApproval(
      stateWith(record("deploy"), ...kept),
      record("deploy", { checkoutId: NONCE_A }) as never,
    );
    expect(replaced.profileApprovals).toHaveLength(kept.length + 1);
    for (const approval of kept)
      expect(replaced.profileApprovals).toContainEqual(approval);
  });

  test("the removal never grants: with nothing to approve, a legacy record still authorizes nothing", () => {
    const state = stateWith(record("deploy"), record("status-check"));
    for (const profile of ["deploy", "status-check"])
      expect(
        findProfileApproval(state, current, projectId, profile),
      ).toBeUndefined();
    // Approving one profile leaves the other legacy record inert, not live.
    const replaced = withProfileApproval(
      state,
      record("deploy", { checkoutId: NONCE_A }) as never,
    );
    expect(
      findProfileApproval(replaced, current, projectId, "status-check"),
    ).toBeUndefined();
  });
});

describe("two clones at one identical directory identity", () => {
  test("both bindings are kept through serialize and parse, and each matches only its own nonce", () => {
    const once = registerCheckout({
      state: emptyVaultState(),
      projectId,
      checkout: { ...base, checkoutId: NONCE_A },
      registeredAt: timestamp,
    });
    const twice = registerCheckout({
      state: once,
      projectId,
      checkout: { ...base, checkoutId: NONCE_B },
      registeredAt: timestamp,
    });
    const reread = parseVaultState(serializeVaultState(twice));
    expect(reread.localBindings.map((binding) => binding.checkoutId)).toEqual([
      NONCE_A,
      NONCE_B,
    ]);
    expect(findBinding(reread, { ...base, checkoutId: NONCE_A })).toBe(
      reread.localBindings[0],
    );
    expect(findBinding(reread, { ...base, checkoutId: NONCE_B })).toBe(
      reread.localBindings[1],
    );
  });
});

describe("the stored record", () => {
  const document = (binding: Record<string, unknown>) =>
    encoder.encode(
      JSON.stringify({
        formatVersion: 1,
        projects: [{ id: projectId, createdAt: timestamp }],
        localBindings: [binding],
        secrets: [],
        profileApprovals: [],
        sharingGrants: [],
        auditRecords: [],
      }),
    );
  const record = { projectId, ...base, registeredAt: timestamp };

  test("checkoutId is the one optional key: present round-trips, absent is omitted", () => {
    const withId = parseVaultState(
      document({ ...record, checkoutId: NONCE_A }),
    );
    expect(withId.localBindings[0]?.checkoutId).toBe(NONCE_A);
    expect(new TextDecoder().decode(serializeVaultState(withId))).toContain(
      `"checkoutId":"${NONCE_A}"`,
    );
    const without = parseVaultState(document(record));
    expect(without.localBindings[0]?.checkoutId).toBeUndefined();
    expect(
      new TextDecoder().decode(serializeVaultState(without)),
    ).not.toContain("checkoutId");
  });

  test("nothing else is relaxed: an unknown key, a missing key or a bad nonce still refuses the document", () => {
    for (const bad of [
      { ...record, extra: "x" },
      { ...record, checkoutId: "not-a-nonce" },
      { ...record, checkoutId: null },
      { ...record, checkoutId: NONCE_A.toUpperCase() },
      { ...record, checkoutId: NONCE_A, extra: "x" },
    ])
      expect(codeOf(() => parseVaultState(document(bad)))).toBe(
        "vault_state_malformed",
      );
    const { registeredAt: _omitted, ...missing } = record;
    expect(codeOf(() => parseVaultState(document(missing)))).toBe(
      "vault_state_malformed",
    );
  });
});

describe("the nonce file in the git directory", () => {
  const checkout = (name: string): string => {
    const directory = join(root, `${name}-${++cases}`);
    mkdirSync(directory);
    return directory;
  };
  const idFile = (gitDirectory: string) =>
    join(gitDirectory, "ward", "checkout-id");

  test("binding writes a random 128-bit nonce at mode 0600 and keeps it", () => {
    const directory = checkout("ordinary");
    mkdirSync(join(directory, ".git"));
    const located = locateCheckout(directory);
    expect(located.checkoutId).toBeUndefined();

    const bound = bindCheckoutIdentity(located);
    expect(bound.checkoutId).toMatch(/^[0-9a-f]{32}$/);
    const file = idFile(join(directory, ".git"));
    expect(lstatSync(file).mode & 0o777).toBe(0o600);
    expect(readFileSync(file, "utf8")).toBe(`${bound.checkoutId}\n`);
    expect(locateCheckout(directory).checkoutId).toBe(bound.checkoutId);
    expect(bindCheckoutIdentity(located).checkoutId).toBe(bound.checkoutId);

    const other = checkout("ordinary-two");
    mkdirSync(join(other, ".git"));
    expect(bindCheckoutIdentity(locateCheckout(other)).checkoutId).not.toBe(
      bound.checkoutId,
    );
  });

  test("a damaged nonce file reads as unbound, and binding does not overwrite it", () => {
    const directory = checkout("damaged");
    mkdirSync(join(directory, ".git", "ward"), { recursive: true });
    writeFileSync(idFile(join(directory, ".git")), "not a nonce\n");
    expect(locateCheckout(directory).checkoutId).toBeUndefined();
    expect(codeOf(() => bindCheckoutIdentity(locateCheckout(directory)))).toBe(
      "checkout_identity_unavailable",
    );
    expect(readFileSync(idFile(join(directory, ".git")), "utf8")).toBe(
      "not a nonce\n",
    );
  });

  test("a link at the ward directory or at the file is refused, and nothing is written through it", () => {
    const elsewhere = checkout("elsewhere");
    const linkedDirectory = checkout("link-directory");
    mkdirSync(join(linkedDirectory, ".git"));
    symlinkSync(elsewhere, join(linkedDirectory, ".git", "ward"));
    expect(
      codeOf(() => bindCheckoutIdentity(locateCheckout(linkedDirectory))),
    ).toBe("checkout_identity_unavailable");
    expect(() => lstatSync(join(elsewhere, "checkout-id"))).toThrow();

    const linkedFile = checkout("link-file");
    mkdirSync(join(linkedFile, ".git", "ward"), { recursive: true });
    const target = join(elsewhere, "target");
    symlinkSync(target, idFile(join(linkedFile, ".git")));
    expect(codeOf(() => bindCheckoutIdentity(locateCheckout(linkedFile)))).toBe(
      "checkout_identity_unavailable",
    );
    expect(() => lstatSync(target)).toThrow();
    expect(locateCheckout(linkedFile).checkoutId).toBeUndefined();
  });

  describe("a .git file (a linked worktree or a submodule)", () => {
    const withGitFile = (name: string, content: string) => {
      const directory = checkout(name);
      writeFileSync(join(directory, ".git"), content);
      return directory;
    };

    test("an absolute gitdir pointer is followed and each worktree binds separately", () => {
      const gitA = checkout("gitdir-a");
      const gitB = checkout("gitdir-b");
      const a = withGitFile("worktree-a", `gitdir: ${gitA}\n`);
      const b = withGitFile("worktree-b", `gitdir: ${gitB}\n`);
      const boundA = bindCheckoutIdentity(locateCheckout(a));
      const boundB = bindCheckoutIdentity(locateCheckout(b));
      expect(readFileSync(idFile(gitA), "utf8")).toBe(`${boundA.checkoutId}\n`);
      expect(boundA.checkoutId).not.toBe(boundB.checkoutId);
      expect(locateCheckout(a).checkoutId).toBe(boundA.checkoutId);
    });

    test("a relative pointer resolves against the directory holding the .git file", () => {
      const directory = checkout("submodule");
      mkdirSync(join(directory, "modules", "sub"), { recursive: true });
      writeFileSync(join(directory, ".git"), "gitdir: modules/sub\n");
      const bound = bindCheckoutIdentity(locateCheckout(directory));
      expect(
        readFileSync(idFile(join(directory, "modules", "sub")), "utf8"),
      ).toBe(`${bound.checkoutId}\n`);
    });

    test("a malformed, oversized, multi-line or dangling pointer binds nothing", () => {
      const real = checkout("real-gitdir");
      const bad: Array<[string, string]> = [
        ["no-prefix", `${real}\n`],
        ["two-lines", `gitdir: ${real}\nextra\n`],
        ["empty-path", "gitdir: \n"],
        ["oversized", `gitdir: ${real}/${"a".repeat(5000)}\n`],
        ["dangling", `gitdir: ${real}/does-not-exist\n`],
        ["points-at-a-file", `gitdir: ${join(real, "file")}\n`],
      ];
      writeFileSync(join(real, "file"), "x");
      for (const [name, content] of bad) {
        const directory = withGitFile(`bad-${name}`, content);
        expect(locateCheckout(directory).checkoutId).toBeUndefined();
        expect(
          codeOf(() => bindCheckoutIdentity(locateCheckout(directory))),
        ).toBe("checkout_identity_unavailable");
      }
    });

    test("a CRLF line end, no trailing newline, a ../ pointer and a symlinked gitdir are all followed", () => {
      const real = checkout("pointer-real");
      const lineEnds: Array<[string, (name: string) => string]> = [
        ["crlf", () => `gitdir: ${real}\r\n`],
        ["no-newline", () => `gitdir: ${real}`],
      ];
      for (const [name, content] of lineEnds) {
        const directory = withGitFile(`pointer-${name}`, content(name));
        const bound = bindCheckoutIdentity(locateCheckout(directory));
        expect(locateCheckout(directory).checkoutId).toBe(bound.checkoutId);
      }
      // A ../ pointer resolves against the directory holding the .git file.
      const parent = checkout("pointer-parent");
      mkdirSync(join(parent, "gitdirs", "g"), { recursive: true });
      mkdirSync(join(parent, "tree"));
      writeFileSync(join(parent, "tree", ".git"), "gitdir: ../gitdirs/g\n");
      const viaDots = bindCheckoutIdentity(
        locateCheckout(join(parent, "tree")),
      );
      expect(readFileSync(idFile(join(parent, "gitdirs", "g")), "utf8")).toBe(
        `${viaDots.checkoutId}\n`,
      );
      // A pointer at a symlink to a directory is followed to the directory.
      const target = checkout("pointer-link-target");
      const link = join(root, `pointer-link-${++cases}`);
      symlinkSync(target, link);
      const viaLink = bindCheckoutIdentity(
        locateCheckout(withGitFile("pointer-symlinked", `gitdir: ${link}\n`)),
      );
      expect(readFileSync(idFile(target), "utf8")).toBe(
        `${viaLink.checkoutId}\n`,
      );
    });

    // The pointer's control-character guard, alone: a directory that really
    // exists under a name holding a CR is refused by the guard and by nothing
    // else (without it the path would resolve and be followed).
    test("a control character in the pointer binds nothing even when the path exists", () => {
      const parent = checkout("control-parent");
      const named = join(parent, "with\rreturn");
      mkdirSync(named);
      const directory = withGitFile("pointer-control", `gitdir: ${named}\n`);
      expect(lstatSync(named).isDirectory()).toBe(true);
      expect(locateCheckout(directory).checkoutId).toBeUndefined();
      expect(
        codeOf(() => bindCheckoutIdentity(locateCheckout(directory))),
      ).toBe("checkout_identity_unavailable");
      expect(() => lstatSync(join(named, "ward"))).toThrow();
    });

    // The same guard on a line feed inside the path: "gitdir: <dir with LF>\n"
    // is two lines to the guard, and a directory that really has that name is
    // refused by it and by nothing else.
    test("a line feed inside the pointer path binds nothing even when the path exists", () => {
      const parent = checkout("linefeed-parent");
      const named = join(parent, "with\nfeed");
      mkdirSync(named);
      const directory = withGitFile("pointer-linefeed", `gitdir: ${named}\n`);
      expect(lstatSync(named).isDirectory()).toBe(true);
      expect(locateCheckout(directory).checkoutId).toBeUndefined();
      expect(
        codeOf(() => bindCheckoutIdentity(locateCheckout(directory))),
      ).toBe("checkout_identity_unavailable");
      expect(() => lstatSync(join(named, "ward"))).toThrow();
    });

    // A NUL cannot name an existing path, so realpath refuses it on its own and
    // the NUL in the guard is a second line of defence this case cannot isolate;
    // likewise a .git file that is a link is stopped by the lstat file check
    // before the O_NOFOLLOW read. Both are asserted as outcomes, not as the
    // single guard that did the work.
    test("a NUL in the pointer, and a .git file that is itself a link, bind nothing", () => {
      const real = checkout("nul-real");
      const nul = withGitFile("pointer-nul", `gitdir: ${real}\0x\n`);
      expect(codeOf(() => bindCheckoutIdentity(locateCheckout(nul)))).toBe(
        "checkout_identity_unavailable",
      );
      const holder = checkout("git-file-link");
      const file = join(root, `git-file-target-${++cases}`);
      writeFileSync(file, `gitdir: ${real}\n`);
      symlinkSync(file, join(holder, ".git"));
      expect(codeOf(() => bindCheckoutIdentity(locateCheckout(holder)))).toBe(
        "checkout_identity_unavailable",
      );
    });

    test("the GIT_DIR environment variable is never read", () => {
      const decoy = checkout("decoy-gitdir");
      mkdirSync(join(decoy, "ward"));
      writeFileSync(join(decoy, "ward", "checkout-id"), `${NONCE_A}\n`);
      const directory = checkout("env-ordinary");
      mkdirSync(join(directory, ".git"));
      const previous = process.env.GIT_DIR;
      process.env.GIT_DIR = decoy;
      try {
        expect(locateCheckout(directory).checkoutId).toBeUndefined();
        const bound = bindCheckoutIdentity(locateCheckout(directory));
        expect(bound.checkoutId).not.toBe(NONCE_A);
        expect(readFileSync(idFile(join(directory, ".git")), "utf8")).toBe(
          `${bound.checkoutId}\n`,
        );
      } finally {
        if (previous === undefined) delete process.env.GIT_DIR;
        else process.env.GIT_DIR = previous;
      }
    });
  });
});

// WCLI-144: readBoundedFile opens without blocking and refuses what is not a
// regular file, so a FIFO swapped in at the path cannot stall the read. Run in
// a child that is killed at a deadline: a regression is then a failed test, not
// a hung one. The regular-file case is the control that the child reads at all.
describe("readBoundedFile against a path that is not a regular file", () => {
  const modulePath = new URL("../src/adapters/checkout.ts", import.meta.url)
    .pathname;
  const readInChild = async (path: string) => {
    const child = Bun.spawn(
      [
        process.execPath,
        "-e",
        `import { readBoundedFile } from ${JSON.stringify(modulePath)};
         console.log(JSON.stringify(readBoundedFile(process.env.TARGET, 64) ?? null));`,
      ],
      { env: { ...process.env, TARGET: path }, stdout: "pipe", stderr: "pipe" },
    );
    const timer = setTimeout(() => child.kill(), 5000);
    const exitCode = await child.exited;
    clearTimeout(timer);
    return { exitCode, out: (await new Response(child.stdout).text()).trim() };
  };

  test("a regular file is read, as the control", async () => {
    const path = join(mkdtempSync(join(root, "bounded-")), "file");
    writeFileSync(path, "gitdir: elsewhere\n");
    expect(await readInChild(path)).toEqual({
      exitCode: 0,
      out: JSON.stringify("gitdir: elsewhere\n"),
    });
  });

  test("a FIFO with no writer is refused at once, not waited on", async () => {
    const path = join(mkdtempSync(join(root, "bounded-")), "pipe");
    expect(Bun.spawnSync(["mkfifo", path]).exitCode).toBe(0);
    expect(await readInChild(path)).toEqual({ exitCode: 0, out: "null" });
  });
});
