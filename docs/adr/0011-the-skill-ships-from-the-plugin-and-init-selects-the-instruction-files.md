---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: The skill ships from the plugin, and init selects the instruction files
tags:
  - agents
  - distribution
summary: "Ward writes no local skill file: the skill comes from the marketplace plugin, and ward init's multiselect is how a checkout chooses which instruction files carry Ward's block (DEC-44)."
generated:
  by: lore/0.11.0
  at: 2026-09-29T16:21:10.428Z
---

# The skill ships from the plugin, and init selects the instruction files

## Status

Accepted. Answered first-party by the operator through opum-doc on
2026-09-29 as **DEC-44**, relayed by opum-agent (ODOC-OP-2026-09-29-16), and
recorded under WCLI-14, which carries the bridge and packaging work. The
operator's own words:

> it should mirror how lore and quest do it. Skills should be installed from
> the marketplace as a pluging. The 'ward init' should update the CLAUDE.md
> and AGENTS.md only with a multiselect option

Two details those words leave open are recorded here as open rather than
settled locally, and are with the operator: whether the peers' stored
selection is mirrored as a value Ward keeps (their `skill_source`), and what
the bridge commands do about a local skill file somebody already has. Until
they are answered this document states what the words do decide, and Ward
writes or removes no skill file at all.

## Context

Spec §8's row for `ward agents --update-instructions` says it adds "only
Ward-owned blocks **and selected local skill files**", and spec §11.2 names
two local skill paths — `.claude/skills/ward/SKILL.md` for a Claude bridge
"explicitly selected" and `.agents/skills/ward/SKILL.md` for Codex — while
warning against installing a duplicate copy when the marketplace plugin
already supplies the skill. Nothing said how that selection was expressed,
which is why `ward agents` shipped the block half only (WCLI-14, PR #118) and
the skill half was left untouched rather than invented.

The two peer CLIs answer it the same way: a `skill_source` value in their own
workspace configuration (`repo` | `plugin` | `none`, default `repo` in
`.quest/workspace.toml` and `.lore/config.toml`), with the skill file written
only under `repo`. Ward has no workspace configuration; its tracked document
is `.ward/project.json`, so adopting that shape would change a committed
document's schema — a contract change, not an implementation detail. The
question therefore went to the operator rather than being decided here.

Ward's own repository is already a consumer of the peer arrangement: both
`.quest/workspace.toml` and `.lore/config.toml` here carry
`skill_source = "plugin"`, so no local lore or quest skill exists in this
checkout.

## Decision

1. **The skill ships from the marketplace plugin, and Ward generates no local
   skill file.** Neither `.claude/skills/ward/SKILL.md` nor
   `.agents/skills/ward/SKILL.md` is written, refreshed or required by any
   Ward command. The packaged skill is `skills/ward/SKILL.md` in this
   repository, shipped by the `opum-ward` plugin; that is the one artifact,
   and spec §11.3's warning about a second copy is satisfied by there being
   no second copy to drift.
2. **`ward init` is where a checkout chooses its instruction files**, and it
   updates `CLAUDE.md` and `AGENTS.md` only — nothing else, and no skill file.
   The choice is a multiselect among those two files rather than a single
   yes/no, which is what "and AGENTS.md" in the operator's sentence asks for:
   a checkout may want one, both, or neither.
3. **`ward agents` continues to manage Ward's block and nothing else.** Its
   `--check` judges the block, and `--update-instructions` writes it; neither
   command writes a skill file. This is what PR #118 landed, and DEC-44
   confirms it rather than changing it.

   **Refined 2026-09-29 (DEC-47, [ADR 0015](0015-a-local-skill-file-is-drift-and-only-an-exact-copy-is-force-removable.md)).**
   Neither command *writes* a skill file, and `--check` now *judges* one found
   at the host's skill path: presence is drift and exits 6, and
   `--update-instructions --force` removes a copy only when its bytes exactly
   match the packaged skill. Reporting a file is not writing it, and removal
   is confined to an exact copy under an explicit `--force`.

## Consequences

- **No schema change.** `.ward/project.json` gains no key, because the
  operator's arrangement needs nothing stored: the source of the skill is not
  a per-checkout choice when the plugin is always the source. That also means
  this decision is cheap to extend — if the operator later wants the peers'
  stored selection, it is an additive key rather than a rewrite.
- **The bridge and the skill can no longer disagree.** A repository's
  instructions and the skill's rules come from two artifacts cut from the same
  tag (spec §11.3), and no generated copy can be left stale by a version bump.
- **`ward init`'s multiselect has to stay agent-safe.** Ward runs inside
  agent sessions, so the selection must degrade when stdin is not a terminal:
  the existing `--claude` and `--codex` flags remain the non-interactive
  equivalent, and a run with no terminal and no flags selects nothing, which
  is today's behaviour. What the prompt itself looks like — a typed
  multi-answer in the style of this CLI's other one-line prompts, or a raw-mode
  checkbox — is with the operator, because it introduces an interaction
  surface the rest of this CLI does not have.
- **A leftover local skill file is a real state this decision does not
  resolve.** A checkout that installed the skill by hand before this
  arrangement, or a user who copies one in, has a duplicate that no Ward
  command will mention. Whether `ward agents --check` should report it as
  drift, and whether `--force` should remove a byte-identical copy the way
  `quest agents --force` does, is with the operator and is deliberately not
  decided here.
