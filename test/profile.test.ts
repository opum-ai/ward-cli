// WCLI-9: `ward profile` and `ward check` (spec §9.1-9.2, §8, docs/adr/0003).
//
// T13 is the spine: a changed URL, method, auth alias, header set, body or
// output policy, binding, or an unknown profile field cannot reuse an
// approval. Each case below is one of those changes, asserted through the
// check an agent actually runs, so the gate is measured where it is used
// rather than only inside the normalizer it calls. Alongside it: readiness
// reports a missing binding, value or approval with no network I/O and no
// value in any output, approving and revoking need a terminal that answers,
// and an approval belongs to one binding rather than to a project.
//
// Every case runs against a temporary vault, a memory credential store and
// throwaway checkouts; nothing touches the developer's ~/.ward or a real
// keychain item.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { locateCheckout } from "../src/adapters/checkout.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createProjectFiles } from "../src/adapters/project-files.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type {
  ProfileAnswer,
  ProfileApprover,
  ProfileQuestion,
  RegistrationApprover,
  RegistrationRequest,
} from "../src/application/approvals.ts";
import {
  type CheckOptions,
  profileCheckReasons,
  type ProfileOptions,
  runCheck,
  runProfile,
} from "../src/application/profiles.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { decodeSecretValue } from "../src/domain/secret.ts";
import {
  differingProfileFields,
  normalizeProfile,
  profileLimits,
  profilesMatch,
} from "../src/domain/profile.ts";
import {
  findProfileApproval,
  parseVaultState,
  serializeVaultState,
  type VaultState,
} from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SENTINEL = "sentinel-9f21c0-profile-value";
const SENTINEL_BASE64 = Buffer.from(SENTINEL).toString("base64");
const PROFILE = "example-profile";
const SNAPSHOT = {
  adapter: "http",
  method: "GET",
  url: "https://api.example.invalid/rate_limit",
  auth: { type: "bearer", secret: "example.token" },
  headers: { Accept: "application/json" },
  requestBody: "none",
  output: "status",
} as const;

type Declaration = Record<string, unknown>;

const declaration = (): Declaration =>
  JSON.parse(JSON.stringify(SNAPSHOT)) as Declaration;

const encode = (text: string) => new TextEncoder().encode(text);

const root = mkdtempSync(join(tmpdir(), "ward-profile-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;

function worktree(): string {
  const directory = join(root, `repo-${++cases}`);
  mkdirSync(directory);
  mkdirSync(join(directory, ".git"));
  return directory;
}

// The manifest `ward init` wrote, with one profile declaration replaced or
// added. The project id is never touched: what is being changed is the
// request, not the identity.
function writeDeclaration(
  checkout: string,
  profile: string,
  value: Declaration,
): void {
  const path = join(checkout, ".ward", "project.json");
  const manifest = JSON.parse(readFileSync(path, "utf8")) as {
    profiles?: Record<string, unknown>;
  };
  manifest.profiles = { ...(manifest.profiles ?? {}), [profile]: value };
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
}

// One approver for both questions: the profile port distinguishes its
// questions by `kind`, and registration's request has none. `beforeAnswer`
// is the seam a race runs through — the world moves after the question is
// asked and before the answer is acted on.
class FakeApprover implements RegistrationApprover, ProfileApprover {
  terminal = true;
  answer: ProfileAnswer = "approved";
  readonly questions: ProfileQuestion[] = [];
  beforeAnswer: (() => void) | undefined;

  available(): boolean {
    return this.terminal;
  }

  ask(question: RegistrationRequest | ProfileQuestion): ProfileAnswer {
    if ("kind" in question) {
      this.questions.push(question);
      const hook = this.beforeAnswer;
      this.beforeAnswer = undefined;
      hook?.();
    }
    if (!this.terminal) return "unavailable";
    return this.answer;
  }
}

class FakeValues implements SecretValueSource {
  value = encode(SENTINEL);

  available(): boolean {
    return true;
  }

  readHidden(): Uint8Array {
    return this.value.slice();
  }

  readStdin(): Uint8Array {
    return this.value.slice();
  }

  confirmReplace(): boolean {
    return true;
  }
}

function harness() {
  const directory = join(mkdtempSync(join(root, `vault-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const store = createSqliteVaultStore({ directory });
  const keyProvider = createKeychainKeyProvider({
    service: "opum.ward.profile",
    entry: keychain.entry,
    timeoutMs: 2_000,
  });
  const approver = new FakeApprover();
  const values = new FakeValues();
  const clock = "2026-09-29T00:00:00.000Z";

  const key = (): Uint8Array => {
    const stored = keychain.items.values().next().value as number[] | undefined;
    if (stored === undefined) throw new Error("no vault key is stored");
    return new Uint8Array(stored);
  };

  const state = (): VaultState => parseVaultState(store.read(key()).plaintext);

  const options = (
    cwd: string,
    extra: Partial<RunOptions> = {},
  ): RunOptions => ({
    wardDirectory: directory,
    keyProvider,
    approver,
    profileApprover: approver,
    secrets: values,
    passphrases: {
      available: () => true,
      read: () => encode("profile-test-passphrase"),
    },
    cwd,
    now: () => new Date(clock),
    ...extra,
  });

  const ward = (cwd: string, args: string[]) => runWard(args, options(cwd));

  // A checkout with a vault, registered for a project of its own and
  // declaring one profile.
  const registered = async (
    profiles: Record<string, Declaration> = { [PROFILE]: declaration() },
  ) => {
    const checkout = worktree();
    expect((await ward(checkout, ["setup", "--json"])).exitCode).toBe(
      exitCodes.success,
    );
    expect((await ward(checkout, ["init", "--json"])).exitCode).toBe(
      exitCodes.success,
    );
    for (const [name, value] of Object.entries(profiles))
      writeDeclaration(checkout, name, value);
    return checkout;
  };

  // Everything the profile needs to be runnable: a registered checkout, the
  // credential stored, and the declaration approved. The T13 cases each
  // change one field of this state, so nothing but that change can explain
  // the readiness answer.
  const ready = async () => {
    const checkout = await registered();
    // A second alias is stored as well, so the case that changes the
    // authentication reference still has a credential present and the only
    // thing left to explain its answer is the changed declaration.
    for (const alias of [SNAPSHOT.auth.secret, "other.token"])
      expect(
        (await ward(checkout, ["secret", "set", alias, "--stdin", "--json"]))
          .exitCode,
      ).toBe(exitCodes.success);
    expect(
      (await ward(checkout, ["profile", "approve", PROFILE, "--json"]))
        .exitCode,
    ).toBe(exitCodes.success);
    return checkout;
  };

  const profileOptions = (checkout: string): ProfileOptions => {
    const identity = locateCheckout(checkout);
    return {
      checkout: identity,
      files: createProjectFiles(identity.root),
      store,
      keyProvider,
      approver,
      now: () => new Date(clock),
    };
  };

  const checkOptions = (checkout: string): CheckOptions => {
    const identity = locateCheckout(checkout);
    return {
      checkout: identity,
      files: createProjectFiles(identity.root),
      store,
      keyProvider,
    };
  };

  return {
    directory,
    store,
    approver,
    values,
    key,
    state,
    options,
    ward,
    registered,
    ready,
    profileOptions,
    checkOptions,
  };
}

type Harness = ReturnType<typeof harness>;

const json = (stdout: string) =>
  JSON.parse(stdout) as { kind: string; data: Record<string, unknown> };
const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

interface CheckProfile {
  profile: string;
  ready: boolean;
  reasons: string[];
  differing: string[];
}

function checkedProfile(
  result: { stdout: string },
  profile = PROFILE,
): CheckProfile {
  const data = json(result.stdout).data as { profiles: CheckProfile[] };
  const entry = data.profiles.find((item) => item.profile === profile);
  if (entry === undefined) throw new Error(`no profile ${profile} reported`);
  return entry;
}

function discloses(result: { stdout: string; stderr: string }): boolean {
  return (
    result.stdout.includes(SENTINEL) ||
    result.stderr.includes(SENTINEL) ||
    result.stdout.includes(SENTINEL_BASE64) ||
    result.stderr.includes(SENTINEL_BASE64)
  );
}

describe("the profile declaration", () => {
  test("normalizes to a complete snapshot with sorted headers and defaults", () => {
    const snapshot = normalizeProfile({
      adapter: "http",
      method: "POST",
      url: "https://api.example.invalid/thing",
      auth: { type: "bearer", secret: "example.token" },
      headers: { "X-Zeta": "1", Accept: "application/json" },
    });
    expect(snapshot).toEqual({
      adapter: "http",
      method: "POST",
      url: "https://api.example.invalid/thing",
      auth: { type: "bearer", secret: "example.token" },
      headers: [
        { name: "Accept", value: "application/json" },
        { name: "X-Zeta", value: "1" },
      ],
      requestBody: "none",
      output: "status",
    });
  });

  test("an omitted header set, body and output are the safe defaults", () => {
    const snapshot = normalizeProfile(declaration());
    expect(snapshot.requestBody).toBe("none");
    expect(snapshot.output).toBe("status");
  });

  const refused: [label: string, value: unknown, code: string][] = [
    [
      "an authentication scheme this build does not implement",
      {
        ...(SNAPSHOT as unknown as Declaration),
        auth: { type: "api-key", secret: "example.token" },
      },
      "profile_unsupported",
    ],
    [
      "HTTP Basic",
      {
        ...(SNAPSHOT as unknown as Declaration),
        auth: { type: "basic", secret: "example.token" },
      },
      "profile_unsupported",
    ],
    [
      "an unknown field",
      { ...(SNAPSHOT as unknown as Declaration), retries: 3 },
      "profile_unsupported",
    ],
    [
      "an unknown field inside auth",
      {
        ...(SNAPSHOT as unknown as Declaration),
        auth: { type: "bearer", secret: "example.token", header: "X-Key" },
      },
      "profile_unsupported",
    ],
    [
      "a method this build does not implement",
      { ...(SNAPSHOT as unknown as Declaration), method: "TRACE" },
      "profile_unsupported",
    ],
    [
      "a lowercase method",
      { ...(SNAPSHOT as unknown as Declaration), method: "get" },
      "profile_unsupported",
    ],
    [
      "a plain-HTTP URL",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "http://api.example.invalid/",
      },
      "profile_unsupported",
    ],
    [
      "a body policy this build does not implement",
      { ...(SNAPSHOT as unknown as Declaration), requestBody: "file" },
      "profile_unsupported",
    ],
    [
      "an output policy this build does not implement",
      { ...(SNAPSHOT as unknown as Declaration), output: "body" },
      "profile_unsupported",
    ],
    [
      "a URL with user-info",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "https://user:pass@api.example.invalid/",
      },
      "profile_invalid",
    ],
    [
      "a URL that does not parse",
      { ...(SNAPSHOT as unknown as Declaration), url: "https://" },
      "profile_invalid",
    ],
    [
      "a URL carrying a line break",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "https://api.example.invalid/\r\nHost: evil",
      },
      "profile_invalid",
    ],
    // The settled reading (WCLI-9): an approval pins the normalized
    // operation, so a declaration another parser could read as a different
    // destination is refused rather than canonicalized into one of them.
    [
      "a URL with a backslash in the authority",
      {
        ...(SNAPSHOT as unknown as Declaration),
        // This parser judges the host `api.example.invalid`; a client that
        // treats the backslash as a literal reads the user-info as ending at
        // the `@` and dials `evil.example` instead.
        url: "https://api.example.invalid\\@evil.example/steal",
      },
      "profile_invalid",
    ],
    [
      "a URL with one slash after the scheme",
      {
        ...(SNAPSHOT as unknown as Declaration),
        // Given an authority by this build's parser, refused by its own
        // fetch: the record would describe an operation Ward cannot send.
        url: "https:/api.example.invalid/x",
      },
      "profile_invalid",
    ],
    [
      "a URL with a character the spec spelling does not allow",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "https://api.example.invalid/café",
      },
      "profile_invalid",
    ],
    [
      "a URL with a space",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "https://api.example.invalid/a b",
      },
      "profile_invalid",
    ],
    [
      "a URL with a malformed percent escape",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "https://api.example.invalid/100%zz",
      },
      "profile_invalid",
    ],
    // A path the parser rewrites names a different resource to a client, a
    // server or a filter that reads it the other way, so both spellings are
    // refused rather than silently resolved into `/x` and stored.
    [
      "a URL whose path carries an encoded dot segment",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "https://api.example.invalid/%2e%2e/x",
      },
      "profile_invalid",
    ],
    [
      "a URL whose path carries a literal dot segment",
      {
        ...(SNAPSHOT as unknown as Declaration),
        url: "https://api.example.invalid/a/../x",
      },
      "profile_invalid",
    ],
    [
      "a header value with a line break",
      {
        ...(SNAPSHOT as unknown as Declaration),
        headers: { Accept: "application/json\r\nX-Evil: 1" },
      },
      "profile_invalid",
    ],
    [
      "a header name that is not a token",
      { ...(SNAPSHOT as unknown as Declaration), headers: { "Bad Name": "1" } },
      "profile_invalid",
    ],
    [
      "the same header spelled twice",
      {
        ...(SNAPSHOT as unknown as Declaration),
        headers: { Accept: "a", accept: "b" },
      },
      "profile_invalid",
    ],
    [
      "an Authorization header beside the auth scheme",
      {
        ...(SNAPSHOT as unknown as Declaration),
        headers: { Authorization: "Bearer x" },
      },
      "profile_invalid",
    ],
    [
      "a secret reference that is not an alias",
      {
        ...(SNAPSHOT as unknown as Declaration),
        auth: { type: "bearer", secret: "../etc/passwd" },
      },
      "profile_invalid",
    ],
    [
      "a missing URL",
      {
        adapter: "http",
        method: "GET",
        auth: { type: "bearer", secret: "example.token" },
      },
      "profile_invalid",
    ],
    [
      "not an object at all",
      "GET https://api.example.invalid/",
      "profile_invalid",
    ],
  ];

  for (const [label, value, code] of refused) {
    test(`${label} is refused`, () => {
      let caught: string | undefined;
      try {
        normalizeProfile(value);
      } catch (error) {
        caught = (error as { code?: string }).code;
      }
      expect(caught).toBe(code);
    });
  }

  test("more headers than the bound is refused", () => {
    const headers = Object.fromEntries(
      Array.from(
        { length: profileLimits.maxHeadersPerProfile + 1 },
        (_, index) => [`X-Header-${index}`, "1"],
      ),
    );
    expect(() =>
      normalizeProfile({ ...(SNAPSHOT as unknown as Declaration), headers }),
    ).toThrow();
  });

  // What is stored is the operation Ward would perform, not the bytes the
  // manifest spelled it with (spec §9.2, WCLI-9's settled reading). The
  // prompt shows this string and a later build executes it, so the approval
  // and the request cannot describe two different destinations.
  test("a URL is stored as the canonical form of the operation", () => {
    const stored = (url: string) =>
      normalizeProfile({ ...declaration(), url }).url;
    expect(stored("https://API.Example.INVALID/rate_limit")).toBe(
      "https://api.example.invalid/rate_limit",
    );
    expect(stored("https://api.example.invalid")).toBe(
      "https://api.example.invalid/",
    );
    expect(stored("https://api.example.invalid:443/rate_limit")).toBe(
      "https://api.example.invalid/rate_limit",
    );
    // A URL already in canonical form is stored byte for byte.
    expect(stored(SNAPSHOT.url)).toBe(SNAPSHOT.url);
    // The path, query and fragment survive unchanged: the origin is the only
    // part of a URL a rewrite may touch.
    expect(stored("https://api.example.invalid/a/b?q=1&r=%20#frag")).toBe(
      "https://api.example.invalid/a/b?q=1&r=%20#frag",
    );
    expect(stored("https://api.example.invalid?q=%2e")).toBe(
      "https://api.example.invalid/?q=%2e",
    );
  });

  test("a declaration without a secret value anywhere in it", () => {
    // The snapshot carries an alias, never a value: this is the shape the
    // approval stores and every result reports.
    const snapshot = normalizeProfile(declaration());
    expect(JSON.stringify(snapshot)).not.toContain(SENTINEL);
    expect(snapshot.auth.secret).toBe(SNAPSHOT.auth.secret);
  });
});

describe("T13: a changed declaration cannot reuse an approval", () => {
  // Each mutation is one field of the approved snapshot. The ones that stay
  // a valid declaration must be reported as an out-of-date approval naming
  // the field; the ones that stop being valid at all are refused as a
  // declaration before any approval is consulted.
  const stale: [
    label: string,
    field: string,
    mutate: (value: Declaration) => void,
  ][] = [
    [
      "the URL changed",
      "url",
      (value) => {
        value.url = "https://api.example.invalid/other";
      },
    ],
    [
      "the method changed",
      "method",
      (value) => {
        value.method = "POST";
      },
    ],
    [
      "the authentication alias changed",
      "auth",
      (value) => {
        value.auth = { type: "bearer", secret: "other.token" };
      },
    ],
    [
      "a header value changed",
      "headers",
      (value) => {
        value.headers = { Accept: "text/plain" };
      },
    ],
    [
      "a header was removed",
      "headers",
      (value) => {
        value.headers = {};
      },
    ],
    [
      "a header was added",
      "headers",
      (value) => {
        value.headers = { Accept: "application/json", "X-Trace": "1" };
      },
    ],
    [
      "the body policy changed",
      "requestBody",
      (value) => {
        value.requestBody = "json-stdin";
      },
    ],
  ];

  for (const [label, field, mutate] of stale) {
    test(`${label}`, async () => {
      const h = harness();
      const checkout = await h.ready();

      const changed = declaration();
      mutate(changed);
      writeDeclaration(checkout, PROFILE, changed);

      const result = await h.ward(checkout, ["check", PROFILE, "--json"]);
      expect(result.exitCode).toBe(exitCodes.validation);
      expect(checkedProfile(result)).toMatchObject({
        ready: false,
        reasons: ["approval-stale"],
        differing: [field],
      });
    });
  }

  const invalid: [label: string, mutate: (value: Declaration) => void][] = [
    [
      "the authentication scheme changed to one this build refuses",
      (value) => {
        value.auth = { type: "basic", secret: "example.token" };
      },
    ],
    [
      "the output policy changed",
      (value) => {
        value.output = "body";
      },
    ],
    [
      "the adapter changed",
      (value) => {
        value.adapter = "shell";
      },
    ],
    [
      "an unknown profile field was added",
      (value) => {
        value.followRedirects = true;
      },
    ],
  ];

  for (const [label, mutate] of invalid) {
    test(`${label}`, async () => {
      const h = harness();
      const checkout = await h.ready();

      const changed = declaration();
      mutate(changed);
      writeDeclaration(checkout, PROFILE, changed);

      const result = await h.ward(checkout, ["check", PROFILE, "--json"]);
      expect(result.exitCode).toBe(exitCodes.validation);
      expect(checkedProfile(result).reasons).toContain("declaration");
      // The approval is still stored — what changed is that nothing can
      // match it any more.
      expect(
        findProfileApproval(
          h.state(),
          locateCheckout(checkout),
          json((await h.ward(checkout, ["profile", "list", "--json"])).stdout)
            .data.projectId as string,
          PROFILE,
        ),
      ).toBeDefined();
    });
  }

  test("a change of header order alone is not a change", () => {
    // Headers are normalized into a sorted list, so the two spellings below
    // are the same approved operation. T13 lists what invalidates an
    // approval and ordering is not among it.
    const approved = normalizeProfile({
      ...declaration(),
      headers: { "X-One": "1", Accept: "application/json" },
    });
    const reordered = normalizeProfile({
      ...declaration(),
      headers: { Accept: "application/json", "X-One": "1" },
    });
    expect(profilesMatch(reordered, approved)).toBe(true);
    expect(differingProfileFields(reordered, approved)).toEqual([]);
  });

  test("an omitted optional field is its default, not a change", () => {
    const explicit = normalizeProfile({
      ...declaration(),
      requestBody: "none",
    });
    const implicit = normalizeProfile(declaration());
    expect(profilesMatch(implicit, explicit)).toBe(true);
  });

  test("a respelling of the same URL is not a change, a different destination is", () => {
    // T13 invalidates a changed destination. Host case, a default port and
    // an omitted trailing slash name the same destination — the spec's own
    // framing is the normalized operation — so they are the same approval,
    // and the snapshot records the one canonical form either way.
    const approved = normalizeProfile(declaration());
    const respelled = normalizeProfile({
      ...declaration(),
      url: "https://API.example.invalid:443/rate_limit",
    });
    expect(differingProfileFields(respelled, approved)).toEqual([]);
    const elsewhere = normalizeProfile({
      ...declaration(),
      url: "https://api.example.invalid/RATE_LIMIT",
    });
    expect(differingProfileFields(elsewhere, approved)).toEqual(["url"]);
  });
});

describe("the approval belongs to one binding", () => {
  test("another checkout of the same project has no approval", async () => {
    const h = harness();
    const first = await h.registered();
    expect(
      (await h.ward(first, ["profile", "approve", PROFILE, "--json"])).exitCode,
    ).toBe(exitCodes.success);

    // A second checkout carrying the same committed manifest: the same
    // project, registered in the same vault, and a different binding.
    const second = worktree();
    mkdirSync(join(second, ".ward"));
    writeFileSync(
      join(second, ".ward", "project.json"),
      readFileSync(join(first, ".ward", "project.json")),
    );
    expect((await h.ward(second, ["init", "--json"])).exitCode).toBe(
      exitCodes.success,
    );

    const result = await h.ward(second, ["check", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(checkedProfile(result).reasons).toContain("approval");
  });

  test("an approval is keyed by the directory identity, not the path alone", async () => {
    const h = harness();
    const checkout = await h.registered();
    expect(
      (await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]))
        .exitCode,
    ).toBe(exitCodes.success);

    const identity = locateCheckout(checkout);
    const projectId = json(
      (await h.ward(checkout, ["check", PROFILE, "--json"])).stdout,
    ).data.projectId as string;
    expect(
      findProfileApproval(h.state(), identity, projectId, PROFILE),
    ).toBeDefined();
    // A directory replaced at the same path is a different directory, and
    // the approval does not follow the pathname (spec §7.1, ADR 0005).
    for (const other of [
      { ...identity, inode: "1" },
      { ...identity, device: "1" },
      { ...identity, root: "/tmp/ward-profile-elsewhere" },
    ])
      expect(
        findProfileApproval(h.state(), other, projectId, PROFILE),
      ).toBeUndefined();
  });

  test("a profile approved in a bound checkout reports as unbound elsewhere", async () => {
    const h = harness();
    const checkout = await h.registered();

    // The same directory, with the binding removed from the vault: no
    // authority, so nothing about this project is evaluated.
    const identity = locateCheckout(checkout);
    h.store.mutate(h.key(), (plaintext) => {
      const state = parseVaultState(plaintext);
      return serializeVaultState({ ...state, localBindings: [] });
    });

    const result = await h.ward(checkout, ["check", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(json(result.stdout).data.binding).toBe("missing");
    const entry = checkedProfile(result);
    expect(entry.reasons).toContain("binding");
    expect(entry.reasons).not.toContain("approval");
    expect(entry.reasons).not.toContain("secret");
    expect(identity).toBeDefined();
  });
});

describe("approving and revoking", () => {
  test("approval writes the snapshot the developer answered about", async () => {
    const h = harness();
    const checkout = await h.registered();
    const result = await h.ward(checkout, [
      "profile",
      "approve",
      PROFILE,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(json(result.stdout).kind).toBe("profile.approve");

    const identity = locateCheckout(checkout);
    const stored = h
      .state()
      .profileApprovals.find((approval) => approval.profile === PROFILE);
    expect(stored).toBeDefined();
    expect(stored?.snapshot).toEqual(normalizeProfile(declaration()));
    expect(stored?.root).toBe(identity.root);
    expect(stored?.device).toBe(identity.device);
    expect(stored?.inode).toBe(identity.inode);
    // What was asked is what was stored: one question, carrying the
    // normalized snapshot.
    expect(h.approver.questions).toHaveLength(1);
    expect(h.approver.questions[0]).toMatchObject({ kind: "approve" });
  });

  test("approving twice replaces the approval rather than adding one", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);
    expect(
      h.state().profileApprovals.filter((entry) => entry.profile === PROFILE),
    ).toHaveLength(1);
  });

  test("a terminal that cannot be asked refuses and writes nothing", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.approver.terminal = false;
    const before = h.store.header()?.revision;
    const result = await h.ward(checkout, [
      "profile",
      "approve",
      PROFILE,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("profile_requires_terminal");
    expect(h.state().profileApprovals).toHaveLength(0);
    expect(h.store.header()?.revision).toBe(before);
  });

  test("a declined approval records nothing", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.approver.answer = "declined";
    const result = await h.ward(checkout, [
      "profile",
      "approve",
      PROFILE,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(json(result.stdout).data.status).toBe("declined");
    expect(h.state().profileApprovals).toHaveLength(0);
  });

  test("a terminal that stops answering mid-question is not consent", async () => {
    const h = harness();
    const checkout = await h.registered();
    h.approver.beforeAnswer = () => {
      h.approver.terminal = false;
    };
    const result = await h.ward(checkout, [
      "profile",
      "approve",
      PROFILE,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("profile_requires_terminal");
    expect(h.state().profileApprovals).toHaveLength(0);
  });

  test("a declaration that moves while the question is open is not approved", async () => {
    const h = harness();
    const checkout = await h.registered();
    // The developer's editor saves, or a branch is switched, after the
    // prompt was rendered and before the answer is acted on: the approval
    // would describe an operation nobody reviewed.
    const changed = declaration();
    changed.url = "https://api.example.invalid/other";
    h.approver.beforeAnswer = () =>
      writeDeclaration(checkout, PROFILE, changed);

    const result = await h.ward(checkout, [
      "profile",
      "approve",
      PROFILE,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("profile_changed");
    expect(h.state().profileApprovals).toHaveLength(0);
  });

  test("an unknown profile is a not-found, and a name Ward cannot address is usage", async () => {
    const h = harness();
    const checkout = await h.registered();
    const missing = await h.ward(checkout, [
      "profile",
      "approve",
      "other",
      "--json",
    ]);
    expect(missing.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(missing.stderr)).toBe("profile_not_found");
    const bad = await h.ward(checkout, [
      "profile",
      "approve",
      "Not a name",
      "--json",
    ]);
    expect(bad.exitCode).toBe(exitCodes.usage);
    expect(errorCode(bad.stderr)).toBe("profile_name_invalid");
  });

  test("revocation removes the approval and needs a terminal", async () => {
    const h = harness();
    const checkout = await h.registered();
    const noApproval = await h.ward(checkout, [
      "profile",
      "revoke",
      PROFILE,
      "--json",
    ]);
    expect(noApproval.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(noApproval.stderr)).toBe("profile_not_approved");

    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);
    h.approver.terminal = false;
    const refused = await h.ward(checkout, [
      "profile",
      "revoke",
      PROFILE,
      "--json",
    ]);
    expect(refused.exitCode).toBe(exitCodes.denied);
    expect(h.state().profileApprovals).toHaveLength(1);

    h.approver.terminal = true;
    const revoked = await h.ward(checkout, [
      "profile",
      "revoke",
      PROFILE,
      "--json",
    ]);
    expect(revoked.exitCode).toBe(exitCodes.success);
    expect(json(revoked.stdout).data.status).toBe("revoked");
    expect(h.state().profileApprovals).toHaveLength(0);
  });

  test("a declined revocation leaves the approval in place", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);
    h.approver.answer = "declined";
    const result = await h.ward(checkout, [
      "profile",
      "revoke",
      PROFILE,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(json(result.stdout).data.status).toBe("declined");
    expect(h.state().profileApprovals).toHaveLength(1);
  });

  test("an unregistered checkout cannot approve anything", async () => {
    const h = harness();
    const checkout = worktree();
    expect((await h.ward(checkout, ["setup", "--json"])).exitCode).toBe(
      exitCodes.success,
    );
    await h.ward(checkout, ["init", "--no-register", "--json"]);
    writeDeclaration(checkout, PROFILE, declaration());
    const result = await h.ward(checkout, [
      "profile",
      "approve",
      PROFILE,
      "--json",
    ]);
    expect(result.exitCode).toBe(exitCodes.denied);
    expect(errorCode(result.stderr)).toBe("project_not_registered");
  });
});

describe("ward check", () => {
  test("answers from local state and makes no network request", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);

    // The declaration names a real https destination, which is the point:
    // readiness must be answered without reaching it. Any request from this
    // process fails the case.
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (() => {
      calls += 1;
      throw new Error("readiness must not reach the network");
    }) as unknown as typeof fetch;
    try {
      const result = await h.ward(checkout, ["check", PROFILE, "--json"]);
      expect(calls).toBe(0);
      expect(result.exitCode).toBe(exitCodes.validation);
      expect(checkedProfile(result).reasons).toEqual(["secret"]);
    } finally {
      globalThis.fetch = original;
    }
  });

  test("reports a missing binding without evaluating the project", async () => {
    const h = harness();
    const checkout = worktree();
    await h.ward(checkout, ["setup", "--json"]);
    // --no-register leaves a manifest and no binding: exactly the state an
    // agent meets before a developer has registered the checkout.
    await h.ward(checkout, ["init", "--no-register", "--json"]);
    writeDeclaration(checkout, PROFILE, declaration());

    const result = await h.ward(checkout, ["check", "--json"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    const data = json(result.stdout).data;
    expect(data.binding).toBe("missing");
    expect(data.ready).toBe(false);
    expect(checkedProfile(result).reasons).toEqual(["binding"]);
    expect(result.stderr).toBe("");
  });

  test("is ready once the profile is approved and its credential is stored", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, [
      "secret",
      "set",
      SNAPSHOT.auth.secret,
      "--stdin",
      "--json",
    ]);
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);

    const result = await h.ward(checkout, ["check", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(json(result.stdout).data.ready).toBe(true);
    expect(checkedProfile(result).reasons).toEqual([]);
  });

  test("a readonly report: the vault revision does not move", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);
    const before = h.store.header()?.revision;
    await h.ward(checkout, ["check", PROFILE, "--json"]);
    await h.ward(checkout, ["profile", "list", "--json"]);
    expect(h.store.header()?.revision).toBe(before);
    expect(h.approver.questions).toHaveLength(1);
  });

  test("an unknown profile is a not-found and a bad name is usage", async () => {
    const h = harness();
    const checkout = await h.registered();
    const missing = await h.ward(checkout, ["check", "other", "--json"]);
    expect(missing.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(missing.stderr)).toBe("profile_not_found");
    const bad = await h.ward(checkout, ["check", "Not a name", "--json"]);
    expect(bad.exitCode).toBe(exitCodes.usage);
    expect(errorCode(bad.stderr)).toBe("profile_name_invalid");
  });

  test("a manifest with no profiles is ready and says so", async () => {
    const h = harness();
    const checkout = worktree();
    await h.ward(checkout, ["setup", "--json"]);
    await h.ward(checkout, ["init", "--json"]);
    const result = await h.ward(checkout, ["check", "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(json(result.stdout).data.profiles).toEqual([]);
  });

  test("every reported reason is one of the declared vocabulary", async () => {
    // `profileCheckReasons` is what an agent renders, so a reason outside it
    // is a contract break rather than a new word. Every state a profile can
    // be in is walked here, and each answer must stay inside the list.
    const h = harness();
    const checkout = await h.registered({
      [PROFILE]: declaration(),
      broken: { adapter: "http", method: "GET" },
    });
    const seen = new Set<string>();
    for (const argv of [
      ["check", "--json"],
      ["check", PROFILE, "--json"],
      ["check", "broken", "--json"],
    ]) {
      const result = await h.ward(checkout, argv);
      const data = json(result.stdout).data as { profiles: CheckProfile[] };
      for (const entry of data.profiles)
        for (const reason of entry.reasons) seen.add(reason);
    }
    expect(seen.size).toBeGreaterThan(0);
    for (const reason of seen)
      expect(profileCheckReasons as readonly string[]).toContain(reason);
  });

  test("an unregistered checkout with nothing declared says that, and not that a profile would be refused", async () => {
    const h = harness();
    const checkout = worktree();
    await h.ward(checkout, ["setup", "--json"]);
    await h.ward(checkout, ["init", "--no-register", "--json"]);
    const result = await h.ward(checkout, ["check"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    // The heading has to agree with the line under it: there is no declared
    // profile to refuse, so the binding is the only thing not ready.
    expect(result.stdout).toContain("this checkout is not registered");
    expect(result.stdout).not.toContain("at least one declared profile");
    expect(result.stdout).toContain("No profiles are declared");
  });

  test("an invalid declaration is reported rather than thrown", async () => {
    const h = harness();
    const checkout = await h.registered({
      [PROFILE]: declaration(),
      broken: { adapter: "http", method: "GET" },
    });
    const result = await h.ward(checkout, ["check", "--json"]);
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(checkedProfile(result, "broken").reasons).toContain("declaration");
    // The profile beside it is still answered: one unreadable declaration
    // does not hide the others.
    expect(checkedProfile(result).reasons).toEqual(["approval", "secret"]);
  });
});

describe("non-disclosure", () => {
  test("no profile command prints a value, a URL or a header value", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, [
      "secret",
      "set",
      SNAPSHOT.auth.secret,
      "--stdin",
      "--json",
    ]);
    const outputs = [
      await h.ward(checkout, ["profile", "list"]),
      await h.ward(checkout, ["profile", "list", "--json"]),
      await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]),
      await h.ward(checkout, ["check", "--json"]),
      await h.ward(checkout, ["check", PROFILE]),
      await h.ward(checkout, ["profile", "revoke", PROFILE, "--json"]),
    ];
    for (const result of outputs) {
      expect(discloses(result)).toBe(false);
      expect(result.stdout).not.toContain(SNAPSHOT.url);
      expect(result.stdout).not.toContain("application/json");
    }
  });

  // What this measures is the port's payload, not the rendered prompt: the
  // question carries the operation and no value, and every *result* stays
  // silent about both (the case above walks the results). The rendering
  // itself — escaping, and what a person actually reads — is measured in
  // test/terminal-consent.test.ts, where the prompt is produced.
  test("the approval question carries the operation and no value", async () => {
    const h = harness();
    const checkout = await h.registered();
    const prompt: string[] = [];
    h.approver.beforeAnswer = () => undefined;
    const options = h.profileOptions(checkout);
    const recording = {
      ...options,
      approver: {
        available: () => true,
        ask: (question: ProfileQuestion): ProfileAnswer => {
          prompt.push(JSON.stringify(question));
          return "approved";
        },
      },
    };
    await runProfile({ action: "approve", profile: PROFILE }, recording);
    expect(prompt).toHaveLength(1);
    expect(prompt[0]).toContain(SNAPSHOT.url);
    expect(prompt[0]).not.toContain(SENTINEL);
  });

  test("a stored approval round-trips, and a damaged one is refused", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);
    const state = h.state();
    expect(parseVaultState(serializeVaultState(state))).toEqual(state);

    // A stored snapshot the normalizer would not produce is a damaged
    // document, not an approval with unknown meaning.
    const damaged = serializeVaultState(state);
    const text = new TextDecoder()
      .decode(damaged)
      .replace('"adapter":"http"', '"adapter":"http","followRedirects":true');
    let caught: string | undefined;
    try {
      parseVaultState(new TextEncoder().encode(text));
    } catch (error) {
      caught = (error as { code?: string }).code;
    }
    expect(caught).toBe("vault_state_malformed");
  });
});

describe("the application ports", () => {
  test("check and list answer through the same evaluation", async () => {
    const h = harness();
    const checkout = await h.registered();
    const listed = await runProfile(
      { action: "list", profile: undefined },
      h.profileOptions(checkout),
    );
    const checked = await runCheck(
      { profile: undefined },
      h.checkOptions(checkout),
    );
    expect(listed.kind).toBe("profile.list");
    expect(checked.kind).toBe("check.report");
    const profiles = listed.data.profiles as {
      profile: string;
      declaration: string;
      approval: string;
      secret: string;
    }[];
    expect(profiles).toEqual([
      {
        profile: PROFILE,
        declaration: "valid",
        approval: "missing",
        secret: "missing",
      },
    ]);
  });

  test("the action vocabulary and the name grammar are enforced", async () => {
    const h = harness();
    const checkout = await h.registered();
    const options = h.profileOptions(checkout);
    const codeOf = async (
      run: Promise<unknown>,
    ): Promise<string | undefined> => {
      try {
        await run;
        return undefined;
      } catch (error) {
        return (error as { code?: string }).code;
      }
    };
    expect(
      await codeOf(
        runProfile({ action: "destroy", profile: undefined }, options),
      ),
    ).toBe("profile_action_unknown");
    expect(
      await codeOf(
        runProfile({ action: "approve", profile: undefined }, options),
      ),
    ).toBe("missing_argument");
    expect(
      await codeOf(runProfile({ action: "list", profile: PROFILE }, options)),
    ).toBe("unexpected_argument");
    expect(
      await codeOf(
        runProfile({ action: "revoke", profile: "Not a name" }, options),
      ),
    ).toBe("profile_name_invalid");
    expect(
      await codeOf(
        runProfile({ action: "approve", profile: "other" }, options),
      ),
    ).toBe("profile_not_found");
  });
});

describe("restore clears approvals with the bindings", () => {
  test("a restored vault holds no profile approval", async () => {
    const h = harness();
    const checkout = await h.registered();
    await h.ward(checkout, ["profile", "approve", PROFILE, "--json"]);
    expect(h.state().profileApprovals).toHaveLength(1);

    const backupPath = join(root, `backup-${++cases}.json`);
    expect(
      (await h.ward(checkout, ["backup", "--output", backupPath, "--json"]))
        .exitCode,
    ).toBe(exitCodes.success);

    // A fresh vault directory: restore refuses anything else.
    const restored = join(
      mkdtempSync(join(root, `restore-${cases}-`)),
      ".ward",
    );
    const keychain = new MemoryKeychain();
    const result = await runWard(["restore", "--input", backupPath, "--json"], {
      wardDirectory: restored,
      keyProvider: createKeychainKeyProvider({
        service: "opum.ward.profile.restore",
        entry: keychain.entry,
        timeoutMs: 2_000,
      }),
      // The passphrase the backup was written with: restore opens the file
      // rather than being told a different one.
      passphrases: {
        available: () => true,
        read: () => encode("profile-test-passphrase"),
      },
      cwd: checkout,
    });
    expect(result.exitCode).toBe(exitCodes.success);
    const restoredState = parseVaultState(
      createSqliteVaultStore({ directory: restored }).read(
        new Uint8Array(keychain.items.values().next().value as number[]),
      ).plaintext,
    );
    expect(restoredState.localBindings).toEqual([]);
    expect(restoredState.profileApprovals).toEqual([]);
    expect(restoredState.secrets).toHaveLength(0);
  });
});

describe("checking a profile never reads its value", () => {
  test("a stored sentinel is not disclosed by any readiness answer", async () => {
    // `ready` stores the sentinel credential and approves the profile, so
    // the value really is in the vault while readiness reports only that it
    // is present.
    const h = harness();
    const checkout = await h.ready();
    const result = await h.ward(checkout, ["check", PROFILE, "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(discloses(result)).toBe(false);
    expect(
      discloses(await h.ward(checkout, ["profile", "list", "--json"])),
    ).toBe(false);
    // The assertion that the value is there, read straight out of the vault
    // rather than through any command: without it, "nothing was disclosed"
    // is equally explained by "nothing was stored".
    const stored = h
      .state()
      .secrets.find((entry) => entry.alias === SNAPSHOT.auth.secret);
    expect(stored).toBeDefined();
    expect(decodeSecretValue(stored?.value ?? "")).toEqual(encode(SENTINEL));
  });
});

describe("a profile name from the manifest cannot act on the terminal", () => {
  // A name is a key in a tracked file anyone who can edit the repository can
  // write, and a name this build's grammar refuses is still *reported* —
  // dropping it would hide a declaration. So it reaches the text reports,
  // and it is escaped on the way out for the same reason the approval prompt
  // escapes the operation: a person reads it.
  const hostile = "evil\u001b]0;PWNED\u0007‮name";

  test("list and check escape a name in their text output", async () => {
    const h = harness();
    const checkout = await h.registered({
      [PROFILE]: declaration(),
      [hostile]: declaration(),
    });
    for (const argv of [["profile", "list"], ["check"]]) {
      const result = await h.ward(checkout, argv);
      expect(result.stdout).not.toContain("\u001b");
      expect(result.stdout).not.toContain("\u0007");
      expect(result.stdout).not.toContain("‮");
      expect(result.stdout).toContain("evil\\x1b]0;PWNED\\x07\\u202ename");
    }
  });

  test("the JSON report carries the name as a JSON string, with no raw control byte", async () => {
    const h = harness();
    const checkout = await h.registered({ [hostile]: declaration() });
    const result = await h.ward(checkout, ["check", "--json"]);
    // JSON.stringify escapes the control bytes itself, so the name survives
    // the round trip — the caller that asked by name still finds it — while
    // no raw ESC or BEL reaches stdout. JSON is a machine channel rather
    // than a terminal, so a format character may travel in it unescaped.
    const parsed = json(result.stdout).data as { profiles: CheckProfile[] };
    expect(parsed.profiles[0]?.profile).toBe(hostile);
    expect(result.stdout).not.toContain("\u001b");
    expect(result.stdout).not.toContain("\u0007");
  });
});

describe("the readiness path cannot reach a transport", () => {
  // The case above patches globalThis.fetch, which is one way to make a
  // request and not the only one: a captured fetch reference, node:https and
  // a spawned curl all miss it, and the layer check constrains only relative
  // imports, so `import "node:https"` would pass it. This is the structural
  // half — the whole import closure of the application layer, every file
  // `ward check` could execute, names no transport at all.
  //
  // What it does not claim: that no Ward command ever reaches the network
  // (adapters do I/O, and a later task adds the transport), only that the
  // layer that answers readiness cannot. It is a source scan, so it would
  // not see a transport acquired by a string a program builds at run time.
  const transports = [
    "node:http",
    "node:https",
    "node:net",
    "node:tls",
    "node:dns",
    "node:dgram",
    "node:child_process",
  ];

  async function closureOfEntries(entries: readonly string[]) {
    const read = new Map<string, string>();
    const queue = [...entries];
    while (queue.length > 0) {
      const path = queue.pop() as string;
      if (read.has(path)) continue;
      const source = await Bun.file(path).text();
      read.set(path, source);
      for (const [, target] of source.matchAll(/["'](\.[^"']+)["']/g)) {
        if (target === undefined) continue;
        const resolved = join(dirname(path), target);
        if (await Bun.file(resolved).exists()) queue.push(resolved);
      }
    }
    return read;
  }

  test("no file the application layer imports names a transport", async () => {
    const layer = join(import.meta.dir, "..", "src", "application");
    const entries = readdirSync(layer)
      .filter((name) => name.endsWith(".ts"))
      .map((name) => join(layer, name));
    const read = await closureOfEntries(entries);
    // Positive control: the walk read the layer it describes, and the file
    // the readiness answer comes from is inside the closure.
    expect(read.size).toBeGreaterThanOrEqual(entries.length);
    expect(entries.length).toBeGreaterThan(0);
    const paths = [...read.keys()];
    expect(paths.some((path) => path.endsWith("/profiles.ts"))).toBe(true);
    expect(paths.some((path) => path.endsWith("/domain/profile.ts"))).toBe(
      true,
    );

    const offenders: string[] = [];
    for (const [path, source] of read) {
      for (const specifier of transports)
        if (
          source.includes(`"${specifier}"`) ||
          source.includes(`'${specifier}'`) ||
          source.includes(`\`${specifier}\``)
        )
          offenders.push(`${path}: names ${specifier}`);
      // A bare call, with `//` comments stripped so prose cannot trip it.
      const code = source.replace(/^\s*\/\/.*$/gm, "");
      if (/\bfetch\s*\(/.test(code)) offenders.push(`${path}: calls fetch`);
      if (/\bBun\.(spawn|spawnSync|\$)/.test(code))
        offenders.push(`${path}: spawns a process`);
    }
    expect(offenders).toEqual([]);
  });
});
