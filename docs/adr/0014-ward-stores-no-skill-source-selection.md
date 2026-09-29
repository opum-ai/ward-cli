---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Ward stores no skill-source selection
tags:
  - agents
  - distribution
summary: Ward keeps no skill-source value anywhere – the opum-ward plugin is always the source, so nothing is stored and no schema changes (DEC-46).
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:05:00.000Z
---

# Ward stores no skill-source selection

## Status

Accepted. Answered first-party by the operator through opum-doc on
2026-09-29 as **DEC-46**, relayed by opum-agent (ODOC-OP-2026-09-29-17), and
recorded under WCLI-14, which carries the work. The operator's answer was the
packet's recommended option, in their own selection label:

> Store nothing (Recommended)

opum-doc told the operator beforehand, labelled as its own finding rather than
the operator's words, that this option mirrors lore and quest's outcome but
not their mechanism. Both facts are true of this decision: Ward ends where
the peers end (the plugin supplies the skill) by a different route (Ward has
nothing to configure).

## Context

[ADR 0011](0011-the-skill-ships-from-the-plugin-and-init-selects-the-instruction-files.md)
settled that the skill ships from the opum-ward plugin and left one question
open: whether Ward mirrors the peers' *stored selection*. In lore and quest
that selection is a `skill_source` value in their own workspace configuration
(`.lore/config.toml`, `.quest/workspace.toml`; `repo` | `plugin` | `none`,
default `repo`), and the skill file is written to `.claude/skills/<name>/` only
under `repo`. Ward has no workspace configuration file, so adopting that shape
meant adding a key to `.ward/project.json` - a committed document whose schema
would then differ between Ward releases. That cost is what made it a question
for the operator rather than an implementation detail.

## Decision

1. **Ward stores nothing.** No `skill_source` key, no flag, no detection
   result is written anywhere: `.ward/project.json`'s schema is unchanged
   from what WCLI-14 shipped before this decision. The skill's source is not
   a per-checkout choice, because there is only ever one source.
2. **The opum-ward plugin is always the source**, exactly as ADR 0011
   decided, and `ward init`'s multiselect selects instruction files only -
   what it writes (`CLAUDE.md`, `AGENTS.md`) is itself the record of the
   choice, and nothing else remembers it.
3. **`ward agents` reads no configuration to do its work.** With nothing
   stored, its behavior is the same in every checkout, including one Ward has
   never seen; that property already held and this decision keeps it.

## Consequences

- **No schema change, and nothing to keep in sync.** A key that recorded
  "the plugin is the source" would have described a constant, and every
  reader of `.ward/project.json` would have had to know when it could be
  absent.
- **The extension path stays open and is a new decision.** If a future
  arrangement makes the source a real per-checkout choice, the key is
  additive and this record says why it is absent today; it does not say it
  can never exist.
- **Divergence from the peers is mechanical, not behavioral.** A user of
  lore, quest and Ward sees the same outcome (the skill comes from the
  plugin); only the peers' mechanism is absent here, and this record is where
  that asymmetry is explained rather than rediscovered.
