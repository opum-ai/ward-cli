// The two documents `ward init` reads and writes, as pure data: the tracked
// project manifest (a claim) and the encrypted vault's state (the authority).
// Both are parsed from bytes a caller can edit — the manifest is committed,
// the state is sealed but written by an earlier Ward — so every field is
// checked here rather than trusted.
import { describe, expect, test } from "bun:test";
import {
  newProjectManifest,
  parseProjectManifest,
  serializeProjectManifest,
} from "../src/domain/project-manifest.ts";
import type { SecretRecord } from "../src/domain/secret.ts";
import {
  type CheckoutIdentity,
  emptyVaultState,
  findBinding,
  parseVaultState,
  registerCheckout,
  serializeVaultState,
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
    const state = parseVaultState(stateBytes({ formatVersion: 1 }));
    expect(state).toEqual({
      formatVersion: 1,
      projects: [],
      localBindings: [],
      secrets: [],
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
        formatVersion: 1,
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
      }),
    );
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
      { formatVersion: 1, projects: {} },
    ],
    [
      "a binding with a relative root",
      {
        formatVersion: 1,
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
        formatVersion: 1,
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
        formatVersion: 1,
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
        formatVersion: 1,
        localBindings: [
          { projectId, ...identity, device: "0167", registeredAt: timestamp },
        ],
      },
    ],
    [
      "a project id that is not an opaque id",
      {
        formatVersion: 1,
        projects: [{ id: "project-1", createdAt: timestamp }],
      },
    ],
    [
      "a timestamp that is not ISO-8601",
      {
        formatVersion: 1,
        projects: [{ id: projectId, createdAt: "yesterday" }],
      },
    ],
    [
      "an unknown collection",
      { formatVersion: 1, unknownCollection: [], localBindings: [] },
    ],
    [
      "a secret value that is not canonical base64",
      { formatVersion: 1, secrets: [secretRecord({ value: "AAA" })] },
    ],
    [
      "an empty secret value",
      { formatVersion: 1, secrets: [secretRecord({ value: "" })] },
    ],
    [
      "a secret value over the 64 KiB limit",
      {
        formatVersion: 1,
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
      { formatVersion: 1, secrets: [secretRecord({ alias: "9not-an-alias" })] },
    ],
    [
      "a secret revision below one",
      { formatVersion: 1, secrets: [secretRecord({ revision: 0 })] },
    ],
    [
      "a secret record with a field missing",
      {
        formatVersion: 1,
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
  ];
  for (const [label, value] of malformed) {
    test(`${label} is refused`, () => {
      expect(codeOf(() => parseVaultState(stateBytes(value)))).toBe(
        "vault_state_malformed",
      );
    });
  }

  test("a format version this build does not implement is named as such", () => {
    expect(
      codeOf(() => parseVaultState(stateBytes({ formatVersion: 2 }))),
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

  test("a manifest with no profiles key is read as having none", () => {
    const manifest = parseProjectManifest(
      JSON.stringify({ schemaVersion: 1, projectId }),
    );
    expect(manifest.profiles).toEqual({});
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
      "a profile this build does not implement",
      JSON.stringify({ schemaVersion: 1, projectId, profiles: { deploy: {} } }),
      "project_manifest_unsupported",
    ],
  ];
  for (const [label, text, code] of refused) {
    test(`${label} is refused`, () => {
      expect(codeOf(() => parseProjectManifest(text))).toBe(code);
    });
  }
});
