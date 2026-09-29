---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Agent profile source coverage
tags:
  - tooling
  - docs
  - agents
summary: A Docs-job check fails when a concept in the bundle is a candidate source for no specialist profile, so a new ADR cannot be silently absent from every evidence set.
status: stable
generated:
  by: lore/0.11.0
  at: 2026-09-29T01:17:29.293Z
---

# Agent profile source coverage

## Status

Accepted. It records how this repository keeps the four `.lore/agents/*.toml`
source lists current as bundle concepts are added, for WCLI-25, from the
measurement taken during the WCLI-24 review (opum-ai/ward-cli#25).

## Context

`lore agent context <profile> --task "<text>"` compiles a task pack, and in
lore's own words it "selects only among the sources that profile lists". A
concept no profile lists therefore cannot reach a specialist through a pack at
all; the only route left is a hand `lore query` and `lore read`. Nothing was
keeping the four lists up with the bundle, and the gap is silent in the one
direction that matters:

- **A concept arriving is silent.** Adding one leaves `lore check --strict` at
  exit 0 with every pack catalog unchanged and no warning. Measured on
  2026-09-28 during the WCLI-24 review with a scratch ADR.
- **A concept leaving is loud.** `lore agent context` exits 6 with
  `.lore/agents/<file>.toml references missing concept <id>`, `lore check
  --strict` exits 6, and `lore agent list` errors.

So the declaration is a one-way contract: it catches a profile naming a concept
that has gone, and says nothing about a concept that has arrived. Three of the
bundle's eight concepts were in no profile when this ADR was written — the three
most recent accepted decisions, `adr/0005`, `adr/0006` and `adr/0007` — and one
of them, `adr/0007`, was accepted by WCLI-26 in the same change whose
independent review was compiled from the `review` profile that did not declare
it.

A second measurement bounds the remedy. A profile's `max_tokens` bounds its
compiled pack, and an over-budget profile is narrowed by task relevance: each
dropped source is catalogued `omitted-by-budget` and the pack reports
`truncated: true` — **at exit 0**. Declaring every concept in every profile
therefore does not overflow a pack; it evicts the least relevant sources from
it. With all seven ADRs declared against `documentation`'s 10 000 tokens, a
neutral task omitted `adr/0002`, `adr/0003` and `adr/0004`. Raising that
budget until nothing was dropped put the pack at 12 363 tokens, and the same
raise would be needed again the next time a concept landed.

## Decision

**A Docs-job check, `scripts/check-lore-agent-sources.mjs`, fails when a concept
in the bundle is a candidate source for no specialist profile, unless the check
records it as a deliberate exclusion with a reason. The check enforces that the
decision is made; the four source lists stay curated by hand.**

- **The invariant is "a candidate for at least one profile", not "a candidate
  for every profile".** Which profile a concept belongs to is a curation
  decision, and the check is deliberately too weak to make it. A concept
  relevant to one specialist is declared once and the check is satisfied.
- **Only the silent direction is covered.** A profile naming a concept that no
  longer exists is already exit 6 in `lore check --strict` and in `lore agent
  context`, so the check does not restate it.
- **The exclusion map is the escape hatch for "none".** An entry needs a
  reason, and every entry is printed on every run, so a concept deliberately
  kept out of every profile is a visible decision rather than an omission that
  looks like one. It is empty today.
- **The check holds no second copy of either list.** Concepts come from
  `lore graph --json` and declared references from `lore agent list|show
  --json`, so there is nothing in it to drift from the bundle or the profiles.
- **It fails rather than passes when it read nothing.** Zero concepts or zero
  profiles is a failure, because a clean-looking answer from no input is
  indistinguishable from a clean bundle, and the empty report is the one that
  would be believed.
- **Budgets are not part of the fix.** Declaring a concept makes it reachable;
  relevance decides whether it arrives. On the `review` profile, a backup task
  includes `adr/0006` and omits `adr/0007`, and a reporting task does the
  reverse — the assembler already narrows a wide candidate set to the task in
  hand, which is what makes a wide candidate set safe.

**Rejected: record an ADR-landing step instead.** A line in this repository's
instructions saying that adding a concept means updating the four source lists.
A convention has nothing watching it at the moment it is forgotten, and the
failure it would prevent is a concept added in good faith by someone who did
not know the convention existed. It also cannot express the exclusion half, so
a concept deliberately unwanted in every profile and a concept nobody
remembered would leave identical artifacts. A required check beats a written
warning where a check is available, and this one is four `lore` reads and a set
comparison.

**Rejected: also fail when a compiled pack is `truncated`.** It is the same
defect one layer down — a source declared and then absent from the pack, at
exit 0 — and it was tempting for exactly that reason. It fails on two counts.
The result depends on the task text handed to `lore agent context`, so the
assertion would need a synthetic task and still could not be stated for all
tasks. And it would forbid the behaviour the assembler is built for: budgets
would have to grow with the bundle, until every profile carries the whole
bundle and the four profiles stop being different evidence sets.

## Consequences

- **Every accepted ADR is now a candidate in all four profiles.** Product
  decisions are what a change must not exceed, and which specialist meets one
  is decided by the task text rather than by the declaration.
- **The profile descriptions no longer enumerate ADR titles.** A description
  listing them has to be edited every time one lands, which is the maintenance
  burden this ADR exists to remove; they name the profile's character instead.
- **ADR 0008 is declared in the `documentation` profile only.** It is a
  repository-process decision rather than a product bound, so it is the one
  concept here that is not a candidate for every specialist. The check accepts
  that deliberately: it asserts reachability, not uniformity.
- **The check runs in the Docs job**, on every pull request and every push to
  `dev`, beside `lore check --strict` and `lore agents --check`.
- **What is not claimed:** that declaring a concept into a profile is the right
  profile for it, that a profile's declared set is well chosen, or that a
  specialist who needs a concept will find it in its pack. The check catches
  the omission that was silent. Curation quality is still a reading, and
  whether a declared source survives the budget is still a question for the
  pack's own `truncated` flag.
