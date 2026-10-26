// DEC-38: the two sites that still refuse a document from another build, and
// the one that no longer does.
//
// Ward has a single state document format. A document whose shape is not this
// build's is refused by the reader in domain/vault-state.ts, which compares
// every record's key set exactly and answers `vault_state_malformed` — the
// same answer every other invalid field in that document gets. The version
// number is one of those fields rather than a gate, so this file no longer
// covers it: a version this build did not write being malformed is asserted
// below as the positive control for the removal, rather than in a case of its
// own.
//
// What remained after DEC-38 was `vault_format_unsupported`, at two sites that
// are not the state document's format. DEC-246 (a2) removed one of them: a
// stored profile approval whose version names another build is now absent for
// authorisation rather than a refusal, and `test/stale-approval.test.ts`
// measures that instead. What is left here is the sealed envelope's header,
// which is bound as authenticated data and is genuinely the outer container's
// format.
//
// One code, one sentence. The wording is deliberately the same at
// each and says a different build wrote this without naming which version was
// found or expected, because with no recovery path there is nothing a reader
// could do with either number. It is written out here rather than read back
// from the catalog — an assertion that read the catalog would pass on any
// wording at all, which is the failure it exists to catch.
//
// Nothing here touches the developer's machine: no vault, no keychain, no
// temporary store. The envelope case seals its own record in memory.
import { describe, expect, test } from "bun:test";
import { errorEnvelope, WardError } from "../src/contract/errors.ts";
import {
  formatVersion as envelopeFormatVersion,
  generateVaultKey,
  open,
  seal,
} from "../src/domain/envelope.ts";
import {
  parseVaultState,
  vaultStateFormatVersion,
} from "../src/domain/vault-state.ts";

// The sentence DEC-30 A fixed, written out verbatim rather than imported: the
// point of this assertion is that the shipped text is this text.
const DEC_30 =
  "This vault was written by a different version of Ward, and this build cannot read it. Ward did not change it.";

const encoder = new TextEncoder();

const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
const vaultId = "44b05c92-8a6e-4f15-9dcb-65ae5d371456";
const timestamp = "2026-09-29T00:00:00.000Z";
const PROFILE = "example-profile";

const document = (value: unknown) => encoder.encode(JSON.stringify(value));

// The refusal a call raises, as the caller sees it: the code and the exact
// text the error envelope would print.
function refusalOf(run: () => unknown): { code: string; message: string } {
  try {
    run();
  } catch (error) {
    if (error instanceof WardError) {
      const envelope = errorEnvelope(error);
      return { code: envelope.code, message: envelope.message };
    }
    throw error;
  }
  throw new Error("expected a refusal, and the call returned instead");
}

const unsupported = { code: "vault_format_unsupported", message: DEC_30 };

describe("the refusal that remains, and the one that is gone", () => {
  test("the catalog carries the DEC-30 sentence, with no hint and no version numbers", () => {
    expect(errorEnvelope(new WardError("vault_format_unsupported"))).toEqual({
      error_type: "validation",
      code: "vault_format_unsupported",
      message: DEC_30,
      principal: null,
    });
    // No hint key at all, which is what DEC-25 left: a hint would name a
    // recovery the build does not have. DEC-38 leaves that rule standing at
    // the two sites below rather than revisiting it — it removed the state
    // document's use of this code, not the code.
    expect(
      Object.hasOwn(
        errorEnvelope(new WardError("vault_format_unsupported")),
        "hint",
      ),
    ).toBe(false);
    // And nothing numeric, so no reader can take a found or expected version
    // out of the sentence and act on it.
    expect(DEC_30).not.toMatch(/\d/);
  });

  test("the envelope's version raises the code with that sentence", () => {
    // DEC-246 (a2): the approval site this test used to drive is gone — a
    // stored approval from another build parses as an inert record now. The
    // envelope's header is the site that remains, and it still refuses.
    const key = generateVaultKey();
    const record = seal(key, { vaultId, revision: 1 }, document({}));
    expect(
      refusalOf(() =>
        open(key, { ...record, formatVersion: envelopeFormatVersion + 1 }),
      ),
    ).toEqual(unsupported);
  });

  // The positive control for the removal above. The state document's version
  // was the third site that raised this code; it now reaches the ordinary
  // malformed answer, which is what every other invalid field in that
  // document already gets. Without this case the file would assert an absence
  // and say nothing about what replaced it.
  test("the state document's version is no longer one of those sites", () => {
    expect(
      refusalOf(() =>
        parseVaultState(
          document({ formatVersion: vaultStateFormatVersion + 1 }),
        ),
      ),
    ).toEqual({
      code: "vault_state_malformed",
      message:
        "The vault's contents are not a state document this Ward can read.",
    });
  });

  // F6 (rv330), as DEC-246 (a2) now rules it: a dev-era approval carries the
  // literal version 1, and it authorises nothing rather than refusing the
  // document. The exhaustive clause proofs are in test/stale-approval.test.ts;
  // this case stays here because the file's subject is what does and does not
  // refuse, and this record no longer does. The snapshot is the v1-era shape
  // and is never normalized, which is the point of the version.
  test("an approval whose literal snapshotVersion is 1 is inert, not a refusal", () => {
    const state = parseVaultState(
      document({
        formatVersion: vaultStateFormatVersion,
        profileApprovals: [
          {
            profile: PROFILE,
            projectId,
            root: "/Users/dev/code/project",
            device: "16777232",
            inode: "8429931",
            approvedAt: timestamp,
            expiresAt: "2026-09-30T00:00:00.000Z",
            snapshotVersion: 1,
            snapshot: {
              adapter: "http",
              method: "GET",
              url: "https://api.example.invalid/status",
              auth: { type: "bearer", secret: "example.token" },
              headers: [],
              requestBody: "none",
              output: "status",
            },
          },
        ],
      }),
    );
    expect(state.profileApprovals).toEqual([]);
    expect(state.staleProfileApprovals).toHaveLength(1);
  });
});
