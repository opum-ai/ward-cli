---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: A local skill file is drift, and only an exact copy is force-removable
tags:
  - agents
  - security
summary: A local skill file at either host's path is drift that fails --check, and --force removes one only when its bytes exactly match the packaged skill (DEC-47).
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:05:00.000Z
---

# A local skill file is drift, and only an exact copy is force-removable

## Status

Accepted. Answered first-party by the operator through opum-doc on
2026-09-29 as **DEC-47**, relayed by opum-agent (ODOC-OP-2026-09-29-17), and
recorded under WCLI-14, which carries the work. The operator's answer was the
packet's recommended option, in their own selection label:

> Report it as drift (Recommended)

The option the repository's own packet described, as that packet's record
keeps it: report a found copy as drift, and let `--force` remove a
byte-identical copy the way `quest agents` does.

## Context

ADR 0011 left this open too: a checkout that installed the skill by hand
before the plugin arrangement, or someone who copies one in, has a duplicate
no Ward command mentioned. Spec §11.2 warns against exactly that duplicate
copy. The peer rule being mirrored is `quest agents`': under a workspace whose
skill ships from a plugin, a present `.claude/skills/quest/SKILL.md` is
`orphaned` - present when it should not be - reported as drift by `--check`
(exit 6); `--force` removes it **only when its bytes exactly match what the
CLI itself would generate**, and a hand-edited file is never removed, force
or not.

Ward differs from quest in one way that shapes the implementation: quest's CLI
carries its skill text and writes it, while Ward writes no skill file at all
(DEC-44). The only content Ward can call its own is the packaged skill,
`skills/ward/SKILL.md`, which the plugin ships.

## Decision

1. **Both host paths are judged, per target**: `.claude/skills/ward/SKILL.md`
   for `--target claude` and `.agents/skills/ward/SKILL.md` for
   `--target codex`, the paths spec §11.2 names. Absence is the healthy state
   and the check says so by naming the path it looked at - a reader can see
   which question was answered.
2. **A present file is drift.** `ward agents --check` reports it and exits 6,
   the same exit a stale or malformed block gets, and regardless of
   `--require-installed`: it is a contradiction, not a configuration a caller
   may decline to have.
3. **`--update-instructions` reports it and removes nothing by default.**
   `--force` removes it only when its bytes are exactly the packaged skill's.
   A differing file - hand-edited, or simply not the file the plugin ships -
   is reported and left alone; Ward never deletes a file it cannot identify.
   The comparison is against the skill embedded at build time from
   `skills/ward/SKILL.md` (a text import in `src/adapters/skill-content.ts`),
   so "exact" always means the copy cut from the same commit as the running
   CLI.
4. **`--force` is refused on `--check`** rather than ignored, the way
   `--require-installed` is refused on the writing form.
5. **The result carries the state in `--json`**: the document, `state` of
   `absent` or `present`, and whether a present file `matchesPackaged`, so a
   caller can tell "drift an automatic repair can clear" from "drift a person
   must resolve" without parsing prose.

## Consequences

- **Ward's binary now carries the skill text** (about 6 KB) purely to judge
  identity. That is the one new asset in the build, it is public guidance,
  and it cannot drift from the plugin's copy because both are cut from the
  same commit.
- **A hand-edited copy is reported forever until a person deletes it.** That
  is the deliberate half of the peer rule: `--force` is not a bulk delete,
  and a file whose bytes Ward cannot vouch for is not Ward's to remove.
- **The spec is corrected where it described this**: §8's `ward agents` rows
  and §11.2's local-skill paragraph gain the DEC-47 behavior, dated, beside
  their DEC-44 corrections.
- **ADR 0011's "neither command touches a skill file" is refined rather than
  repealed**: judging and reporting a file is not touching it, and removal
  remains confined to an exact copy under an explicit `--force`.
