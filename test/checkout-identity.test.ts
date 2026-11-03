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
