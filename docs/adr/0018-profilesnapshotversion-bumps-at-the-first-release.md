---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: profileSnapshotVersion bumps at the first release
tags:
  - release
  - profiles
summary: profileSnapshotVersion stays 1 while Ward is unreleased; the first release bumps it and updates the comment, with the obligation carried by the release runbook and the WCLI-15 record (DEC-50).
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:14:05.000Z
---

# profileSnapshotVersion bumps at the first release

## Status

Accepted. Answered first-party by the operator through opum-doc on
2026-09-29 as **DEC-50**, relayed by opum-agent (ODOC-OP-2026-09-29-18), and
recorded under WCLI-38, which was filed for exactly this decision and now
carries its recording. The operator's answer was the packet's recommended
option, in their own selection label:

> Bump at first release (Recommended)

opum-doc's premise, labelled as opum-doc's and not the operator's words: the
option is consistent with the operator's standing ruling that Ward is
pre-release, and the bump refuses dev-era snapshots rather than migrating
them. Both halves are what this record decides.

## Context

`src/domain/profile.ts` holds `profileSnapshotVersion` at 1 with a written
rule: the constant is bumped in the same change that alters what
`normalizeProfile` accepts, because a stored profile approval records the
version it was written under and a later build must not read a
differently-interpreted record as an approval the developer gave. The rule
carried a written exception - it stays 1 while the accepted set is still being
settled, because no released build has written a snapshot yet.

WCLI-10 narrowed the accepted set and did not bump, correctly: a narrowing can
only refuse more, so a snapshot it newly rejects fails closed at parse. That
reasoning is a fact about unreleased data, and it expires the moment a release
writes snapshots: from then on a stored record outlives the rules that wrote
it, and the version is the only thing that stops a later build reading it
under rules it was not written for. The obligation lived only in the source
comment above the constant; a comment is not read by whoever cuts the
release, which is what WCLI-38 was filed to fix (WCLI-10 review round 3).

The refusal a mismatch produces already exists and is unchanged by this
decision: a stored profile approval whose `snapshotVersion` differs raises
`vault_format_unsupported` - "written by a different version of Ward, and this
build cannot read it; Ward did not change it".

## Decision

1. **The constant stays 1 while Ward is unreleased.** No dev-era snapshot
   exists that a released build could misread, and the comment above the
   constant is updated to state this decision and where the release-time
   obligation lives, rather than leaving the reasoning in the comment alone.
2. **The commit that cuts the first release bumps the constant and updates
   the comment**, so the released build refuses every snapshot written by a
   dev-era build. It is a one-line bump plus its comment, done in the release
   commit itself - not a change to any rule about what a profile may contain.
3. **There is no migration, deliberately.** The version refuses a dev-era
   snapshot; it does not reinterpret it, and no upgrade path reads one under
   the new rules. An approval recorded before the release is re-approved
   rather than assumed, which is the direction that fails safe for a record
   whose meaning is the developer's consent.
4. **The obligation is reachable from the release gate, not from the source
   comment.** It is carried by the release runbook
   ([Cutting a Ward release](../runbooks/cutting-a-ward-release.md)) and by
   the WCLI-15 record, so whoever cuts the release meets it as a checklist
   item without rediscovering this decision.
5. **After the first release the original rule is back in force**: any change
   to what `normalizeProfile` accepts bumps the constant in the same change,
   because from then on there is stored data under the old rules.

## Consequences

- **A released build refuses dev-era snapshots rather than reading them.** A
  developer who approved profiles during the pre-release period re-approves
  them after upgrading. That is a small, one-time cost, and it is the same
  cost the exception was always heading toward.
- **The first release carries one more gated item.** It is mechanical
  (constant plus comment) and the runbook names it, so it cannot be
  rediscovered after the tag; the alternative - bumping now - would refuse
  snapshots written by the current build's own test runs for no benefit, since
  nothing released has written one.
- **The version number still means what it says**: a build reading a snapshot
  either wrote it under the same rules or refuses it. Nothing in this decision
  weakens that; it schedules when the first bump happens.
