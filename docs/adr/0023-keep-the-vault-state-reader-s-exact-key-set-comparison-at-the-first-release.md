---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Keep the vault state reader's exact key-set comparison at the first release
tags:
  - release
  - vault-format
summary: "At 0.1.0 the state document reader keeps its exact key-set comparison: an authority record never silently drops an unknown field, and a format change costs a version bump (DEC-246 D1)."
generated:
  by: lore/0.14.1
  at: 2026-10-26T17:19:12.495Z
---

# Keep the vault state reader's exact key-set comparison at the first release

## Status

Accepted, 2026-10-26, under **DEC-246 (D1, ruled A)**, recorded by opum-doc at
2026-10-26T17:12:38Z under the design delegation, and carried here from its
relay: "keep the exact key-set comparison. An authority record never silently
drops an unknown field, and the version bump plus migration is the intended
price." The record binds, not this document's copy of it; the decision's text
is DEC-246 in opum-doc. It answers the question
[ADR 0010](0010-refuse-a-vault-state-document-from-another-format.md) deferred
to the first release and the [release runbook](../runbooks/cutting-a-ward-release.md)
carries as its step 5 (DEC-38, WCLI-63, WCLI-82).

## Context

The state document's reader compares each record's key set against an exact
expected list. Before the first release that cost nothing: the format was not a
compatibility contract and nobody held a vault this build did not write. At
Ward 0.1.0 it becomes one, because a released build is now what a developer's
vault is written by.

The question ADR 0010 left for this moment is whether the reader keeps the
exact comparison or is relaxed to tolerate keys it does not know. ADR 0010 set
the relaxed arm aside deliberately, and the reason was about authority: the
document holds bindings, approvals and grants, which decide access. A reader
that drops an unknown field on a record that decides access has silently
changed what the record means, and a later write of that record then persists
the loss.

## Decision

**The exact key-set comparison stays at 0.1.0.** `parseVaultState` still
refuses a record whose keys are not exactly the set this build writes, naming it
as a damaged record, and no record type gains tolerance for unknown keys.

## Consequences

- **A field added to the document after 0.1.0 is a breaking change to the
  format.** A newer build refuses a 0.1.0 vault and an older build refuses a
  newer one. That is the price, and it is accepted: the change that adds the
  field must carry its own answer (a format version raised and a migration, or a
  decision that a refusal is acceptable) rather than discover the wall at a
  developer's desk.
- **There is no migration in 0.1.0.** The release does not read a dev-era
  approval either: `profileSnapshotVersion` is 2 from this release
  ([ADR 0018](0018-profilesnapshotversion-bumps-at-the-first-release.md)), so a
  profile approval a pre-release build wrote is held inert — it authorises
  nothing, `ward status` and `ward doctor` name it with its checkout and
  snapshot version, and the developer approves the profile again to replace it
  (DEC-246 a2). The install runbook says so.
- **The arm not taken stays available to revisit.** Tolerating unknown keys on
  records that do not decide access is not decided here and would need its own
  record; this ADR does not forbid it, it declines it on authority records.
- Nothing in `src/` changes for this decision. The reader already behaves this
  way; what is new is that the behaviour is now a recorded commitment rather than
  an unsettled one.

## Amendment, 2026-11-07 (DEC-262 a3, WCLI-149)

A sign key's optional `kind` key uses this price: see [ADR 0027](0027-an-ed25519-sign-operation-sign-keys-are-a-kind-of-secret-record-never-exported.md).
