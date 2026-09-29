---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Stale test roots are reclaimed by an explicit command, never a sweep
tags:
  - tests
  - tooling
summary: Test runs reclaim their own roots in teardown; stale residue from killed runs is reclaimed by the deliberate bun run clean:temp, never by anything a test run does (DEC-49).
generated:
  by: lore/0.11.0
  at: 2026-09-29T16:55:04.651Z
---

# Stale test roots are reclaimed by an explicit command, never a sweep

## Status

Accepted. Answered first-party by the operator through opum-doc on
2026-09-29 as **DEC-49**, relayed by opum-agent (ODOC-OP-2026-09-29-18), and
recorded under WCLI-46, which carries the work. The operator's answer was the
packet's recommended option, in their own selection label:

> Explicit clean command (Recommended)

The option the repository's own packet asked about, as that packet's record
keeps it: **A**, "ship an explicit `bun run clean:temp` that a person or CI
runs deliberately and never let a test run delete directories it did not
create"; or **B**, the literal sweep in the test helper, which reclaims
residue automatically and means every test run deletes age-filtered
directories it did not create.

## Context

`ward-*` roots accumulate in a shared TMPDIR whenever a test run is killed - a
CI cancellation, a crash fixture, a timeout - because the packaged build root
held two compiled binaries (about 122 MB per run) and removal waited on the
process reaching its exit handlers, which a killed run never does. Found by
the remote-mgmt fleet session on 2026-09-29 while diagnosing a machine running
out of disk: 146 `ward-packaged-*` directories, 17.1 GiB, all created within a
day, at a steady 8-14 per hour. The teardown half is already fixed and
measured (PR #120, `test/support/temp-root.ts`): a root is removed in the
importing file's own `afterAll`, a full run leaves nothing of its own, and the
same measurement found two leakers no criterion had named.

What remained was the residue: roots earlier killed runs had left behind, and
what a test run should do about them. A sweep at the start of every run means
recursively deleting age-filtered directories out of a shared TMPDIR -
directories the running process did not create. The permission layer refused
exactly that capability the first time the test helper exercised it, and the
refusal was carried as evidence rather than routed around. Two measurements
fix the shape of the problem:

- An age filter cannot tell residue from a live run. Read-only measurement by
  opum-doc at about 16:45Z, 2026-09-29: 869 `ward-*` directories in one
  TMPDIR, 711 of them older than two hours (18.9 GiB) - and 158 under two
  hours, which is exactly the window in which a long-lived run is still
  working.
- The residue is real and bounded. This repository's own dry run of the
  command below, 2026-09-29: 70,529 entries scanned, 869 `ward-*` directories,
  724 older than 120 minutes.

## Decision

1. **A test run never deletes a directory it did not create.** Cleanup inside
   a run is teardown-scoped only: `test/support/temp-root.ts` removes the root
   it made, in the importing file's `afterAll`, and nothing sweeps.
2. **Stale residue is reclaimed by an explicit command**:
   `bun run clean:temp`, which runs `scripts/clean-temp.mjs`. It removes
   direct children of `os.tmpdir()` named `ward-*` that are real directories
   (a symlink is neither followed nor removed) whose own modification time is
   older than the threshold - 120 minutes by default, moved with
   `--older-than-minutes <n>`. `--dry-run` reports what it would remove and
   removes nothing. It always reports how much it read - entries scanned,
   `ward-*` directories seen, how many were older than the threshold, how many
   were removed and how many bytes were reclaimed - so a scan that found
   nothing and a scan that read nothing cannot print alike.
3. **Nothing invokes it but a person or a deliberate step.** It is not in
   `bun run check`, not in CI, not in any test, and no hook calls it. The one
   place a test runs it is its own test file, pointed at a fixture directory
   through `TMPDIR`/`TEMP`, so even that run can only touch directories that
   test created.

## Consequences

- **Reclamation is deliberate, and that is the point.** The command deletes
  directories it did not create, which is why it is a command a person runs
  rather than a helper a helper invokes: whoever runs it knows whose TMPDIR it
  is. The fleet's manual two-hour sweeps on other machines are this same
  operation performed by hand.
- **The age filter stays a heuristic, and is documented as one.** Of the 869
  directories measured, 158 were under two hours old; most are live runs, and
  some may be residue from a run that died young. The default is deliberately
  conservative, and `--older-than-minutes` exists for a person who has looked
  and decided otherwise.
- **WCLI-46's second criterion is amended, with its original wording kept.**
  It read "Cleanup does not depend on process exit: e.g. removal in
  afterAll/test teardown, plus a start-of-run sweep of stale
  `ward-packaged-*` dirs older than a few hours." The sweep half is replaced
  by this command, and the amendment is recorded on the task and here rather
  than checked against an unimplemented clause.
- **The refusal is recorded as the reason, not as an obstacle.** A test helper
  is not the place to acquire a destructive capability over a shared
  directory, and the capability does not become safer by being automatic.
