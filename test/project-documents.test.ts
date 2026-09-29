// The two documents `ward init` reads and writes, as pure data: the tracked
// project manifest (a claim) and the encrypted vault's state (the authority).
// Both are parsed from bytes a caller can edit — the manifest is committed,
// the state is sealed but written by an earlier Ward — so every field is
// checked here rather than trusted.
import { describe, expect, test } from "bun:test";
import {
  profileLimits,
  profileSnapshotVersion,
} from "../src/domain/profile.ts";
import {
  newProjectManifest,
  parseProjectManifest,
  serializeProjectManifest,
} from "../src/domain/project-manifest.ts";
import type { SecretRecord } from "../src/domain/secret.ts";
import {
  type AuditRecord,
  auditHistoryLimit,
  type CheckoutIdentity,
  emptyVaultState,
  findBinding,
  type ProfileApprovalRecord,
  parseVaultState,
  registerCheckout,
  serializeVaultState,
  vaultStateFormatVersion,
  withAuditRecord,
} from "../src/domain/vault-state.ts";

const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
const timestamp = "2026-09-28T12:00:00.000Z";
const identity: CheckoutIdentity = {
  root: "/Users/dev/code/project",
  device: "16777232",
  inode: "8429931",
};

// A complete, valid stored-secret record; each malformed case below breaks
// exactly one field of it.
const secretRecord = (overrides: Partial<SecretRecord> = {}): SecretRecord => ({
  id: projectId,
  projectId,
  alias: "example-alias",
  value: Buffer.from("value-bytes").toString("base64"),
  createdAt: timestamp,
  updatedAt: timestamp,
  revision: 1,
  ...overrides,
});

// A complete, valid stored approval; each malformed case below breaks
// exactly one field of it. The URL is canonical and within the character set
// the profile normalizer accepts, so the record survives re-normalization.
const snapshot = {
  adapter: "http",
  method: "GET",
  url: "https://api.example.invalid/a%20b?x=1&y=2",
  auth: { type: "bearer", secret: "example.token" },
  headers: [],
  requestBody: "none",
  output: "status",
} as const;

const approvalRecord = (
  overrides: Partial<ProfileApprovalRecord> = {},
): ProfileApprovalRecord => ({
  profile: "example-profile",
  projectId,
  root: identity.root,
  device: identity.device,
  inode: identity.inode,
  approvedAt: timestamp,
  snapshotVersion: profileSnapshotVersion,
  snapshot: { ...snapshot },
  ...overrides,
});

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
}

// A document is written as JSON text, which is what a caller could have
// edited by hand or sealed from an older build.
const stateBytes = (value: unknown) =>
  new TextEncoder().encode(
    typeof value === "string" ? value : JSON.stringify(value),
  );

describe("the vault's state document", () => {
  test("the skeleton setup seals parses as empty collections", () => {
    const state = parseVaultState(
      stateBytes({ formatVersion: vaultStateFormatVersion }),
    );
    expect(state).toEqual({
      formatVersion: vaultStateFormatVersion,
      projects: [],
      localBindings: [],
      secrets: [],
      profileApprovals: [],
      auditRecords: [],
    });
    expect(parseVaultState(serializeVaultState(emptyVaultState()))).toEqual(
      emptyVaultState(),
    );
  });

  test("a registered checkout round-trips byte for byte", () => {
    const state = registerCheckout({
      state: emptyVaultState(),
      projectId,
      checkout: identity,
      registeredAt: timestamp,
    });
    const bytes = serializeVaultState(state);
    expect(parseVaultState(bytes)).toEqual(state);
    expect(new TextDecoder().decode(bytes)).toBe(
      JSON.stringify({
        formatVersion: vaultStateFormatVersion,
        projects: [{ id: projectId, createdAt: timestamp }],
        localBindings: [
          {
            projectId,
            root: identity.root,
            device: identity.device,
            inode: identity.inode,
            registeredAt: timestamp,
          },
        ],
        secrets: [],
        profileApprovals: [],
        auditRecords: [],
      }),
    );
  });

  // The audit events `ward run` writes. They are in this document because
  // they are the one collection an agent's operation adds to, so their shape
  // is part of what a damaged document has to be caught in rather than a
  // detail of the run.
  const auditRecord = (over: Partial<AuditRecord> = {}): AuditRecord => ({
    id: "11111111-1111-4111-8111-111111111111",
    runId: "22222222-2222-4222-8222-222222222222",
    projectId,
    profile: "example-profile",
    secretId: "33333333-3333-4333-8333-333333333333",
    phase: "admission",
    outcome: null,
    at: timestamp,
    machine: { user: "example-user", host: "example-host" },
    actorLabel: null,
    taskLabel: null,
    ...over,
  });

  test("an audit pair round-trips, and the history stays inside its bound", () => {
    const state = {
      ...emptyVaultState(),
      auditRecords: [
        auditRecord(),
        auditRecord({ phase: "completion", outcome: "succeeded" }),
      ],
    };
    expect(parseVaultState(serializeVaultState(state))).toEqual(state);

    let bounded = emptyVaultState();
    for (let index = 0; index < auditHistoryLimit + 1; index++)
      bounded = withAuditRecord(
        bounded,
        auditRecord({
          id: `11111111-1111-4111-8111-${String(index).padStart(12, "0")}`,
        }),
      );
    expect(bounded.auditRecords.length).toBe(auditHistoryLimit);
    // The oldest goes, not the newest: a bound that dropped what just
    // happened would lose the event a reader is most likely to want.
    expect(bounded.auditRecords.at(-1)?.id).toBe(
      `11111111-1111-4111-8111-${String(auditHistoryLimit).padStart(12, "0")}`,
    );
    expect(bounded.auditRecords[0]?.id).toBe(
      `11111111-1111-4111-8111-${String(1).padStart(12, "0")}`,
    );
  });

  test("an audit record carrying an outcome it could not have is malformed", () => {
    const cases: [label: string, value: Record<string, unknown>][] = [
      // An admission is written before there is an outcome.
      [
        "an admission with an outcome",
        { phase: "admission", outcome: "succeeded" },
      ],
      ["an unknown outcome", { phase: "completion", outcome: "probably-fine" }],
      ["an unknown phase", { phase: "delivery", outcome: null }],
      ["a non-UUID secret id", { secretId: "not-a-uuid" }],
      ["a non-profile name", { profile: "../escape" }],
    ];
    for (const [label, over] of cases) {
      const document = {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [{ ...auditRecord(), ...over }],
      };
      expect({
        label,
        throws: (() => {
          try {
            parseVaultState(stateBytes(document));
            return false;
          } catch {
            return true;
          }
        })(),
      }).toEqual({ label, throws: true });
    }
  });

  test("a secret record round-trips byte for byte", () => {
    // Bytes a text encoding would lose, including NUL and a newline.
    const bytes = Uint8Array.from([0x00, 0x0a, 0xff, 0x62]);
    const state = {
      ...emptyVaultState(),
      secrets: [
        secretRecord({
          value: Buffer.from(bytes).toString("base64"),
          revision: 3,
        }),
      ],
    };
    expect(parseVaultState(serializeVaultState(state))).toEqual(state);
  });

  test("an approval record round-trips byte for byte, with its snapshot version", () => {
    const state = {
      ...emptyVaultState(),
      profileApprovals: [
        approvalRecord({
          snapshot: {
            ...snapshot,
            url: "https://api.example.invalid/other?a=1&b=%20",
          },
        }),
      ],
    };
    const bytes = serializeVaultState(state);
    expect(parseVaultState(bytes)).toEqual(state);
    const document = new TextDecoder().decode(bytes);
    expect(document).toContain('"snapshotVersion":1');
    expect(document).toContain('"snapshot":{"adapter":"http"');
  });

  test("a snapshot version this build does not implement is a document from another build", () => {
    // The vault's formatVersion says which build wrote the document; this
    // says which normalizer produced the snapshot inside it. Running this
    // build's rules over a snapshot written under other ones is how an
    // approval comes to mean something the developer never approved, so it
    // is refused rather than re-read.
    expect(
      codeOf(() =>
        parseVaultState(
          stateBytes({
            formatVersion: vaultStateFormatVersion,
            profileApprovals: [approvalRecord({ snapshotVersion: 2 })],
          }),
        ),
      ),
    ).toBe("vault_format_unsupported");
  });

  test("registering twice keeps one project record and two bindings", () => {
    const first = registerCheckout({
      state: emptyVaultState(),
      projectId,
      checkout: identity,
      registeredAt: timestamp,
    });
    const second = registerCheckout({
      state: first,
      projectId,
      checkout: { ...identity, root: `${identity.root}-worktree` },
      registeredAt: timestamp,
    });
    expect(second.projects).toHaveLength(1);
    expect(second.localBindings).toHaveLength(2);
  });

  test("a binding answers for its own directory and no other", () => {
    const state = registerCheckout({
      state: emptyVaultState(),
      projectId,
      checkout: identity,
      registeredAt: timestamp,
    });
    expect(findBinding(state, identity)?.projectId).toBe(projectId);
    // Same path, different directory: a clone or a replaced checkout.
    expect(
      findBinding(state, { ...identity, inode: "8429932" }),
    ).toBeUndefined();
    expect(
      findBinding(state, { ...identity, device: "16777233" }),
    ).toBeUndefined();
    expect(
      findBinding(state, { ...identity, root: "/Users/dev/code" }),
    ).toBeUndefined();
  });

  const malformed: [label: string, value: unknown][] = [
    ["a document that is not JSON", "{"],
    ["a JSON array", []],
    ["a missing format version", { projects: [], localBindings: [] }],
    [
      "a projects value that is not an array",
      { formatVersion: vaultStateFormatVersion, projects: {} },
    ],
    [
      "a binding with a relative root",
      {
        formatVersion: vaultStateFormatVersion,
        localBindings: [
          {
            ...identity,
            root: "Users/dev/code",
            projectId,
            registeredAt: timestamp,
          },
        ],
      },
    ],
    [
      "a binding root with a trailing slash",
      {
        formatVersion: vaultStateFormatVersion,
        localBindings: [
          {
            ...identity,
            root: "/Users/dev/code/project/",
            projectId,
            registeredAt: timestamp,
          },
        ],
      },
    ],
    [
      "a binding root with a parent segment",
      {
        formatVersion: vaultStateFormatVersion,
        localBindings: [
          {
            ...identity,
            root: "/Users/dev/../code",
            projectId,
            registeredAt: timestamp,
          },
        ],
      },
    ],
    [
      "a device with a leading zero",
      {
        formatVersion: vaultStateFormatVersion,
        localBindings: [
          { projectId, ...identity, device: "0167", registeredAt: timestamp },
        ],
      },
    ],
    [
      "a project id that is not an opaque id",
      {
        formatVersion: vaultStateFormatVersion,
        projects: [{ id: "project-1", createdAt: timestamp }],
      },
    ],
    [
      "a timestamp that is not ISO-8601",
      {
        formatVersion: vaultStateFormatVersion,
        projects: [{ id: projectId, createdAt: "yesterday" }],
      },
    ],
    [
      "an unknown collection",
      {
        formatVersion: vaultStateFormatVersion,
        unknownCollection: [],
        localBindings: [],
      },
    ],
    [
      "an approval record with no snapshot version",
      {
        formatVersion: vaultStateFormatVersion,
        profileApprovals: [
          (() => {
            const { snapshotVersion: _omitted, ...rest } = approvalRecord();
            return rest;
          })(),
        ],
      },
    ],
    [
      "an approval whose snapshot the normalizer would not produce",
      {
        formatVersion: vaultStateFormatVersion,
        profileApprovals: [
          approvalRecord({
            snapshot: {
              ...snapshot,
              headers: [],
              followRedirects: true,
            } as unknown as ProfileApprovalRecord["snapshot"],
          }),
        ],
      },
    ],
    [
      "a secret value that is not canonical base64",
      {
        formatVersion: vaultStateFormatVersion,
        secrets: [secretRecord({ value: "AAA" })],
      },
    ],
    [
      "an empty secret value",
      {
        formatVersion: vaultStateFormatVersion,
        secrets: [secretRecord({ value: "" })],
      },
    ],
    [
      "a secret value over the 64 KiB limit",
      {
        formatVersion: vaultStateFormatVersion,
        secrets: [
          secretRecord({
            value: Buffer.from(new Uint8Array(64 * 1024 + 1)).toString(
              "base64",
            ),
          }),
        ],
      },
    ],
    [
      "a secret alias outside the grammar",
      {
        formatVersion: vaultStateFormatVersion,
        secrets: [secretRecord({ alias: "9not-an-alias" })],
      },
    ],
    [
      "a secret revision below one",
      {
        formatVersion: vaultStateFormatVersion,
        secrets: [secretRecord({ revision: 0 })],
      },
    ],
    [
      "a secret record with a field missing",
      {
        formatVersion: vaultStateFormatVersion,
        secrets: [
          {
            id: projectId,
            projectId,
            alias: "example-alias",
            value: Buffer.from("value-bytes").toString("base64"),
            createdAt: timestamp,
            // updatedAt is deliberately absent.
            revision: 1,
          },
        ],
      },
    ],
    [
      "an audit record whose machine is not an object",
      {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [{ ...auditRecord(), machine: "somewhere" }],
      },
    ],
    [
      "an audit record whose machine names an unknown key",
      {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [
          {
            ...auditRecord(),
            machine: {
              user: "example-user",
              host: "example-host",
              role: "dev",
            },
          },
        ],
      },
    ],
    [
      "an audit record whose observed user is empty",
      {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [
          { ...auditRecord(), machine: { user: "", host: "example-host" } },
        ],
      },
    ],
    [
      "an audit record whose observed host carries a control character",
      {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [
          {
            ...auditRecord(),
            machine: { user: "example-user", host: "example\u0000host" },
          },
        ],
      },
    ],
    [
      "an audit record whose observed host is over the bound",
      {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [
          {
            ...auditRecord(),
            machine: { user: "example-user", host: "h".repeat(257) },
          },
        ],
      },
    ],
    [
      "an audit record with an actor label outside the alias grammar",
      {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [{ ...auditRecord(), actorLabel: "9not-a-label" }],
      },
    ],
    [
      "an audit record with a task label that is not a string",
      {
        formatVersion: vaultStateFormatVersion,
        auditRecords: [{ ...auditRecord(), taskLabel: 7 }],
      },
    ],
  ];
  for (const [label, value] of malformed) {
    test(`${label} is refused`, () => {
      expect(codeOf(() => parseVaultState(stateBytes(value)))).toBe(
        "vault_state_malformed",
      );
    });
  }

  // The genuine format-1 fixture, kept verbatim rather than deleted: this is
  // what the previous build actually wrote, down to an audit record carrying
  // exactly the eight keys format 1 had and no machine and no labels. It is
  // here to pin that the version is the gate — the refusal is the version's
  // answer about these bytes, not a reader failing to make sense of them
  // (WCLI-11, DEC-19 B; DEC-25 is why nothing raises it).
  const formatOneDocument = {
    formatVersion: 1,
    projects: [{ id: projectId, createdAt: timestamp }],
    localBindings: [],
    secrets: [],
    profileApprovals: [],
    auditRecords: [
      {
        id: "11111111-1111-4111-8111-111111111111",
        runId: "22222222-2222-4222-8222-222222222222",
        projectId,
        profile: "example-profile",
        secretId: "33333333-3333-4333-8333-333333333333",
        phase: "admission",
        outcome: null,
        at: timestamp,
      },
    ],
  };

  test("a genuine format-1 document is refused by its version, and nothing reads it", () => {
    expect(codeOf(() => parseVaultState(stateBytes(formatOneDocument)))).toBe(
      "vault_format_unsupported",
    );
    // The positive control for "nothing reads it": the same document under the
    // version this build writes is refused for its record instead. Two
    // demonstrably different answers about the same bytes, which is what makes
    // the first one a reading of the version rather than of the contents.
    expect(
      codeOf(() =>
        parseVaultState(
          stateBytes({
            ...formatOneDocument,
            formatVersion: vaultStateFormatVersion,
          }),
        ),
      ),
    ).toBe("vault_state_malformed");
  });

  test("a format version this build does not implement is named as such", () => {
    expect(
      codeOf(() => parseVaultState(stateBytes({ formatVersion: 3 }))),
    ).toBe("vault_format_unsupported");
  });
});

describe("the tracked project manifest", () => {
  test("a new manifest round-trips, with the profiles key this build writes", () => {
    const manifest = newProjectManifest(projectId);
    const text = serializeProjectManifest(manifest);
    expect(text.endsWith("\n")).toBe(true);
    expect(text).toContain('\n  "projectId": "');
    expect(parseProjectManifest(text)).toEqual(manifest);
  });

  test("a manifest carrying declarations writes them back unchanged", () => {
    // Every caller today hands this function a fresh or restored manifest,
    // whose profiles are empty, so a serializer that dropped them would look
    // correct until the first rewrite of a manifest that had any.
    const profiles = {
      deploy: {
        adapter: "http",
        method: "GET",
        url: "https://api.example.invalid/status",
        auth: { type: "bearer", secret: "example.token" },
      },
    };
    const manifest = { ...newProjectManifest(projectId), profiles };
    const text = serializeProjectManifest(manifest);
    expect(text).toContain('"deploy"');
    expect(parseProjectManifest(text)).toEqual(manifest);
  });

  test("a manifest with no profiles key is read as having none", () => {
    const manifest = parseProjectManifest(
      JSON.stringify({ schemaVersion: 1, projectId }),
    );
    expect(manifest.profiles).toEqual({});
  });

  // A declaration inside `profiles` is deliberately NOT in this list: it is
  // carried as written and judged by the profile commands that use it, so one
  // unreadable profile cannot refuse the manifest every other command reads
  // (WCLI-9). These are the faults in the profiles object itself, which is
  // structure rather than content.
  test("a declared profile is carried as the manifest wrote it", () => {
    const declaration = {
      adapter: "http",
      method: "GET",
      url: "https://example.com/status",
      auth: { type: "bearer", secret: "example.token" },
      somethingNewerWardKnows: true,
    };
    const manifest = parseProjectManifest(
      JSON.stringify({
        schemaVersion: 1,
        projectId,
        profiles: { deploy: declaration },
      }),
    );
    expect(manifest.profiles).toEqual({ deploy: declaration });
  });

  const refused: [label: string, text: string, code: string][] = [
    ["not JSON at all", "{", "project_manifest_malformed"],
    [
      "a project id that is not an opaque id",
      JSON.stringify({ schemaVersion: 1, projectId: "../etc" }),
      "project_manifest_malformed",
    ],
    [
      "a version this build does not implement",
      JSON.stringify({ schemaVersion: 2, projectId }),
      "project_manifest_unsupported",
    ],
    [
      "an unknown field",
      JSON.stringify({ schemaVersion: 1, projectId, secret: "x" }),
      "project_manifest_unsupported",
    ],
    [
      "a profiles value that is not an object",
      JSON.stringify({ schemaVersion: 1, projectId, profiles: [] }),
      "project_manifest_malformed",
    ],
    [
      "a profiles value that is an array",
      JSON.stringify({ schemaVersion: 1, projectId, profiles: ["deploy"] }),
      "project_manifest_malformed",
    ],
    [
      "a profile name that is empty",
      JSON.stringify({ schemaVersion: 1, projectId, profiles: { "": {} } }),
      "project_manifest_malformed",
    ],
    [
      "more profiles than the bounded manifest reads",
      JSON.stringify({
        schemaVersion: 1,
        projectId,
        profiles: Object.fromEntries(
          Array.from(
            { length: profileLimits.maxProfilesPerManifest + 1 },
            (_, index) => [`profile-${index}`, {}],
          ),
        ),
      }),
      "project_manifest_malformed",
    ],
  ];
  for (const [label, text, code] of refused) {
    test(`${label} is refused`, () => {
      expect(codeOf(() => parseProjectManifest(text))).toBe(code);
    });
  }
});
