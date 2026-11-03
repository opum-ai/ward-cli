// DEC-246 (a2): a version-mismatched approval is ABSENT for authorisation,
// stays VISIBLE, and is never removed silently — while every other defect in
// a record still refuses the whole document.
//
// One test per clause, each with the counter-case that would pass under the
// opposite behaviour, so a parser that answered "stale" to everything (or
// "refuse" to everything) fails here rather than reading as covered.
import { describe, expect, test } from "bun:test";
import { errorEnvelope, WardError } from "../src/contract/errors.ts";
import { profileSnapshotVersion } from "../src/domain/profile.ts";
import {
  findBinding,
  findProfileApproval,
  parseVaultState,
  serializeVaultState,
  withProfileApproval,
  type ProfileApprovalRecord,
  vaultStateFormatVersion,
} from "../src/domain/vault-state.ts";

const encoder = new TextEncoder();

const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
const root = "/Users/dev/code/project";
const device = "16777232";
const inode = "8429931";
const profile = "release-deploy";
const checkoutId = "0123456789abcdef0123456789abcdef";
const checkout = { root, device, inode, checkoutId };

// The snapshot is written in the shape a document carries (headers as a map,
// which is what the reader normalizes). For the stale record it is
// deliberately a v1-era shape this build never normalizes: the point of the
// version is that these rules must not be run over it.
const snapshot = {
  adapter: "http",
  method: "GET",
  url: "https://api.example.invalid/a%20b?x=1&y=2",
  auth: { type: "bearer", secret: "example.token" },
  headers: {},
  requestBody: "none",
  output: "status",
};

function approval(overrides: Record<string, unknown> = {}) {
  return {
    profile,
    projectId,
    root,
    device,
    inode,
    checkoutId,
    approvedAt: "2026-09-29T00:00:00.000Z",
    expiresAt: "2026-09-30T00:00:00.000Z",
    snapshotVersion: 1,
    snapshot,
    ...overrides,
  };
}

function document(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value));
}

function refusalCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof WardError) return errorEnvelope(error).code;
    throw error;
  }
  throw new Error("expected a refusal, and the call returned instead");
}

const binding = {
  projectId,
  root,
  device,
  inode,
  checkoutId,
  registeredAt: "2026-09-29T00:00:00.000Z",
};

describe("DEC-246 (a2): a version-mismatched approval", () => {
  // Clause 1: it authorises nothing, ever, and the rest of the document still
  // parses and works.
  test("authorises nothing while the rest of the document still parses and works", () => {
    const state = parseVaultState(
      document({
        formatVersion: vaultStateFormatVersion,
        localBindings: [binding],
        profileApprovals: [
          approval(),
          approval({
            profile: "status-check",
            snapshotVersion: profileSnapshotVersion,
          }),
        ],
      }),
    );

    // The stale record moved out of the authorising collection and is kept
    // whole; the current-version record next to it is untouched.
    expect(state.staleProfileApprovals).toHaveLength(1);
    expect(state.staleProfileApprovals[0]?.stored).toEqual(approval());
    expect(state.profileApprovals).toHaveLength(1);

    // It authorises nothing...
    expect(findProfileApproval(state, checkout, projectId, profile)).toBe(
      undefined,
    );
    // ...while the same document still answers for everything else, which is
    // the half that a document-level refusal would have taken down with it.
    expect(
      findProfileApproval(state, checkout, projectId, "status-check"),
    ).toBeDefined();
    expect(findBinding(state, checkout)).toEqual(binding);
  });

  // Clause 3, first half: re-approving the same identity replaces it.
  test("is replaced by re-approving the same profile, and only by that", () => {
    const state = parseVaultState(
      document({
        formatVersion: vaultStateFormatVersion,
        profileApprovals: [approval()],
      }),
    );
    const reapproved: ProfileApprovalRecord = {
      profile,
      projectId,
      root,
      device,
      inode,
      checkoutId,
      approvedAt: "2026-10-26T00:00:00.000Z",
      expiresAt: "2026-10-27T00:00:00.000Z",
      snapshotVersion: profileSnapshotVersion,
      snapshot: snapshot as ProfileApprovalRecord["snapshot"],
    };

    const replaced = withProfileApproval(state, reapproved);
    expect(replaced.staleProfileApprovals).toEqual([]);
    expect(replaced.profileApprovals).toEqual([reapproved]);

    // A re-approval of a different profile replaces nothing: the stale record
    // stays inert rather than being swept out by an unrelated write.
    const other = withProfileApproval(state, {
      ...reapproved,
      profile: "status-check",
    });
    expect(other.staleProfileApprovals).toHaveLength(1);
  });

  // Clause 3, second half: it is never removed silently. A write that is not
  // a re-approval carries it back out exactly as it came in.
  test("survives a rewrite byte for byte and stays inert", () => {
    // Every collection is present, because a write emits them all; the point
    // of this case is that the approval array comes back exactly as it went
    // in, and the empty collections are the serializer's ordinary shape.
    const first = document({
      formatVersion: vaultStateFormatVersion,
      projects: [],
      localBindings: [],
      secrets: [],
      profileApprovals: [approval()],
      sharingGrants: [],
      auditRecords: [],
    });
    const state = parseVaultState(first);
    const written = serializeVaultState(state);

    // Exactly the record that was read, in the document, not a canonical
    // rewrite of it — including the v1 snapshot this build never normalizes.
    expect(JSON.parse(new TextDecoder().decode(written))).toEqual(
      JSON.parse(new TextDecoder().decode(first)),
    );
    const again = parseVaultState(written);
    expect(again.staleProfileApprovals[0]?.stored).toEqual(approval());
    expect(findProfileApproval(again, checkout, projectId, profile)).toBe(
      undefined,
    );
    // And a second write is byte-identical, so a rewrite cannot drift.
    expect(new TextDecoder().decode(serializeVaultState(again))).toBe(
      new TextDecoder().decode(written),
    );
  });

  // Clause 4: only the version gets this treatment. Each counter-case is a
  // record that would be stale by version and must still refuse.
  test("an unknown key, a malformed record or a wrong document version still refuses", () => {
    expect(
      refusalCode(() =>
        parseVaultState(
          document({
            formatVersion: vaultStateFormatVersion,
            profileApprovals: [approval({ futureField: true })],
          }),
        ),
      ),
    ).toBe("vault_state_malformed");
    expect(
      refusalCode(() =>
        parseVaultState(
          document({
            formatVersion: vaultStateFormatVersion,
            profileApprovals: [approval({ root: "relative/path" })],
          }),
        ),
      ),
    ).toBe("vault_state_malformed");
    expect(
      refusalCode(() =>
        parseVaultState(
          document({
            formatVersion: vaultStateFormatVersion,
            profileApprovals: [approval({ approvedAt: "not-a-timestamp" })],
          }),
        ),
      ),
    ).toBe("vault_state_malformed");
    expect(
      refusalCode(() =>
        parseVaultState(
          document({ formatVersion: vaultStateFormatVersion + 1 }),
        ),
      ),
    ).toBe("vault_state_malformed");

    // The positive control: the same record with only its version changed is
    // the one case that parses, which is what makes the refusals about the
    // defect rather than about the version.
    expect(
      parseVaultState(
        document({
          formatVersion: vaultStateFormatVersion,
          profileApprovals: [approval()],
        }),
      ).staleProfileApprovals,
    ).toHaveLength(1);
  });

  // Finding 7 (rv331): leniency is for a version another build could have
  // written, and no build writes 0, -1 or 1.5. Those are damaged records, so
  // they refuse the document rather than becoming a stale record that would
  // print "snapshot version 1.5" at a developer as if it meant something.
  test("a version that is not a positive integer is malformed, not stale", () => {
    for (const damaged of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(
        refusalCode(() =>
          parseVaultState(
            document({
              formatVersion: vaultStateFormatVersion,
              profileApprovals: [approval({ snapshotVersion: damaged })],
            }),
          ),
        ),
      ).toBe("vault_state_malformed");
    }
    // The positive control on the same axis: one above the build's own
    // version is another build's, and still takes the stale answer.
    expect(
      parseVaultState(
        document({
          formatVersion: vaultStateFormatVersion,
          profileApprovals: [
            approval({ snapshotVersion: profileSnapshotVersion + 1 }),
          ],
        }),
      ).staleProfileApprovals,
    ).toHaveLength(1);
  });

  // A stale approval bound to a checkout path that no longer exists is still
  // named, which is what lets an operator sitting see it after a worktree is
  // gone rather than dead-ending at a refusal.
  test("is kept for a checkout whose directory no longer exists", () => {
    const gone = "/Users/dev/code/deleted-worktree";
    const state = parseVaultState(
      document({
        formatVersion: vaultStateFormatVersion,
        profileApprovals: [approval({ root: gone })],
      }),
    );
    expect(state.staleProfileApprovals).toEqual([
      expect.objectContaining({ profile, root: gone, snapshotVersion: 1 }),
    ]);
    expect(
      findProfileApproval(
        state,
        { root: gone, device, inode },
        projectId,
        profile,
      ),
    ).toBe(undefined);
  });
});
