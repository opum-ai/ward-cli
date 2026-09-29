---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Cutting a Ward release
tags:
  - release
  - qualification
summary: "The obligations a Ward release must discharge beyond the code: the profileSnapshotVersion bump (DEC-50), version agreement, T24's smoke (DEC-45), and the marketplace condition (T25)."
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:14:07.413Z
---

# Cutting a Ward release

## Purpose

This is where a Ward release's recorded obligations live, so that whoever cuts
one meets them as a checklist instead of rediscovering them late. Each item
below is a decision recorded elsewhere and already accepted; this runbook
carries the act, not the reasoning.

It is not the whole release process: the lifecycle (branch, pull request,
integration on `dev`, fast-forward promotion to `main`) is the fleet's and
lives in the SDLC skill. What follows is the set of things that must be true
of the release commit and the release act itself, gathered from the decisions
that named a release-time obligation.

## Prerequisites

- `dev` is green (`bun run check`, and the CI contexts on the promoted SHA)
  and every item below has been read once before the release commit is
  prepared.
- Spec §14's gate list is open beside this runbook; the release is gated on
  every mandatory P0 gate passing on macOS (WCLI-1).

## Steps

1. **Bump `profileSnapshotVersion`.** In the release commit, change the
   constant in `src/domain/profile.ts` from 1 and update the comment above it.
   The released build must refuse every snapshot a dev-era build wrote; there
   is deliberately no migration ([ADR 0018](../adr/0018-profilesnapshotversion-bumps-at-the-first-release.md),
   DEC-50). This is the item WCLI-38 exists for.
2. **Make the plugin and CLI versions agree.** `package.json` and
   `.claude-plugin/plugin.json` carry the same version, and
   `test/plugin-manifest.test.ts` fails when they disagree; bump both in the
   same commit. `0.0.0` is the pre-release placeholder, and the plugin version
   must track the CLI version per the peer (lore-cli) pattern.
3. **Run T24's manual Codex smoke** exactly as
   [Release smoke: T24's manual half](release-smoke-t24-s-manual-half.md)
   describes, and record its result with the release's other gate results.
   Failures there are findings about the artifacts or the skill, not about the
   smoke.
4. **Do not publish a marketplace entry before the artifact exists.** The
   public `opum-marketplace` entry is the later phase: it must validate against
   the index and resolve to the released artifact at an immutable reference
   (spec §11.3, test matrix T25). The private-marketplace half is opum-fleet's.
5. **Record the gate results** where the release's results live - WCLI-15's
   `docs/security-tests.md` maps every gate to a test and a recorded result -
   including this runbook's items, so the next release reads one list.

## Rollback

Nothing here touches a developer's machine or an existing vault: a release
that fails a gate is held back and re-cut, and no step above is destructive.

One case deserves its own sentence because it is not visible until later: a
release that shipped with `profileSnapshotVersion` unbumped cannot be repaired
by a second bump in the next release. Fix it forward - treat the next release
as the bump that should have happened, say so in its notes, and never edit a
stored snapshot to fit.
