---
# yaml-language-server: $schema=../.lore/schemas/reference.schema.json
type: Reference
title: Ward's security test matrix
tags:
  - security
  - tests
summary: The T-numbered security gates, the test that discharges each, and the recorded result. T12 and T21 are recorded; the rest are filled by WCLI-15.
generated:
  by: lore/0.14.1
  at: 2026-10-20T23:12:28.950Z
---

# Ward's security test matrix

The T-numbered gates of the spec of record (section 14), the test that
discharges each, and the result recorded for it. A row is added when its test
exists; WCLI-15 fills the remainder and records the packaged-binary T26 run.
"Passing" means `bun test` on the named file at the head of the pull request
that added the row, and `bun run check` plus the three required CI contexts on
the merge SHA.

| Gate | What it proves | Test | Recorded result |
|---|---|---|---|
| T12 | Exact sharing works; the target cannot edit, delete or re-grant; an owner update is visible to the next use; revoke and owner delete block new admissions | `test/grant.test.ts`, the `T12: exact sharing works` and `T12: revocation and owner deletion block new admissions` groups, and `the grant record is exact and its relations are enforced` | Passing, WCLI-12 |
| T21 | A restore leaves no grant or approval active, with a positive control that the same profile runs before it | `test/grant.test.ts`, `T21: restore clears grants and approvals` | Passing, WCLI-12 |

## How T12 is measured

A refusal is measured by three witnesses and not by the exit code alone: the
recording transport was never asked to send, the vault revision did not move,
and the audit count did not change. A target-side write is measured by the
whole serialized document before and after. The admission race is measured by
a store that revokes the grant between the run's read and its admission write.
The check itself was mutated: making the active-grant lookup ignore
revocation turned exactly the revocation, in-flight and race cases red.

## How T21 is measured

The restored vault is read directly and holds no grant and no approval. After
re-registering and re-approving the target, the run is still refused, because
the grant is gone; only a fresh grant from the re-registered owner makes it run.
