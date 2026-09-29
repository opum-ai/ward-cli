---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Agent profile source coverage
tags:
  - tooling
  - docs
  - agents
summary: A Docs-job check fails when a concept is in no specialist profile's sources, or when a profile's compiled pack drops a source it declares.
status: stable
generated:
  by: lore/0.11.0
  at: 2026-09-29T01:17:29.293Z
---

# Agent profile source coverage

## Status

Accepted. It records how this repository keeps the four `.lore/agents/*.toml`
source lists current as bundle concepts are added, and what a profile's
`max_tokens` must be able to hold. For WCLI-25, from the measurement taken
during the WCLI-24 review (opum-ai/ward-cli#25).

**Amended before landing, on an independent review.** The first version held
that a wide candidate set was safe because the assembler narrows it. The
measurement below refutes that, and the rejected-alternatives list below
records the earlier reading and why it looked right rather than quietly
dropping it.

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
- **A concept leaving is loud.** A profile naming a concept that no longer
  exists fails three commands: `lore agent context` exits 6 with
  `.lore/agents/<file>.toml references missing concept <id>`, `lore check
  --strict` exits 6, and `lore agent list` exits 6.

So the declaration is a one-way contract: it catches a profile naming a concept
that has gone, and says nothing about a concept that has arrived. Three of the
bundle's eight concepts were in no profile when this ADR was written — the three
most recent accepted decisions, `adr/0005`, `adr/0006` and `adr/0007` — and one
of them, `adr/0007`, was accepted by WCLI-26 in the same change whose
independent review was compiled from the `review` profile that did not declare
it.

**A second measurement decides how much a profile may declare, and it is the
one this ADR first got wrong.** A profile's `max_tokens` bounds its compiled
pack, and the assembler drops sources once the declared set exceeds it —
`omitted-by-budget` per source, `truncated: true` on the pack, **at exit 0**.
Measured over four profiles × four task texts, and reproducible with
`lore agent context <profile> --task "<text>" --json`:

- With the profiles as they stood before this change, **16 of 16 packs were
  `truncated: false`**, at 6 428–6 752 tokens of a 10 000–12 000 budget, with
  every declared source fully included.
- Declaring all eight ADRs against those same budgets made **16 of 16 packs
  `truncated: true`**. On `documentation` with the task text `review this
  change` the pack dropped `adr/0002-p0-threat-model-and-non-guarantees`,
  `adr/0004-committed-platform-target` and
  `adr/0006-backup-container-and-restore-authority`. The P0 threat model is
  the document this repository's own review profile exists to enforce.
- With budgets large enough to hold everything, the same four tasks give
  15 256 tokens for `documentation` and 12 106–12 437 for the other three, with
  every source fully included and `truncated: false`. Those totals move with
  the bundle, and `documentation`'s includes this document, so it moves when
  this document is edited.

So a budget too tight for what a profile declares does not merely narrow a pack
by relevance. It removes documents that used to arrive whole, on every pack and
every task, which is the same silent absence this ADR exists to catch — one
layer down, and caused by this change rather than found by it.

**The truncation flag is a function of capacity, not of the task.** With the
declared set fixed and the budget under it, all 16 combinations above truncated
and all 16 did not once the budget held the set; only *which* sources drop
varies with the task text. That is what makes the flag assertable from one
reference task below, and what makes the composition of a pack the part that
must not be asserted.

## Decision

**A Docs-job check, `scripts/check-lore-agent-sources.mjs`, fails when a concept
in the bundle is a candidate source for no specialist profile — unless it is
recorded as a deliberate exclusion with a reason — and when any profile's
compiled pack drops a source that profile declares. Every accepted ADR is a
candidate source in all four profiles, and each profile's `max_tokens` holds
what it declares.**

- **The coverage half asserts "a candidate for at least one profile", not
  "for every profile".** Which profile a concept belongs to stays a curation
  decision, and the check is deliberately too weak to make it.
- **The budget half closes the eviction the first version created.** Each of
  the four profiles now declares every accepted ADR and carries a budget
  measured to hold them: `documentation` 20 000 and the other three 17 000,
  each at least 4 500 tokens above its complete pack, which is more than the
  largest concept in the bundle (3 604). Declaring without that margin is what
  produced the sixteen truncated packs above.
- **It asserts the truncation flag from one reference task, and deliberately
  asserts nothing about a pack's composition.** Truncation is capacity-driven,
  so one task answers the question the assertion asks; which sources drop is
  task-driven, so a per-source assertion would be pinned to a task text that
  has no standing to decide it.
- **The exclusion map is the escape hatch for "none".** An entry needs a
  reason, and every entry is printed on every run, so a concept deliberately
  kept out of every profile is a visible decision rather than an omission that
  looks like one. It is empty today. `LORE_EXCLUSIONS` names a JSON file of
  `id -> reason` so the accept path can be tested with a non-empty map without
  a test editing this file.
- **The check holds no second copy of either list.** Concepts come from
  `lore graph --json` and declared references and pack state from
  `lore agent list|show|context --json`, so there is nothing in it to drift
  from the bundle or the profiles. A declared reference is compared on its
  concept id, so a heading-qualified entry (`id#section`) counts.
- **It fails rather than passes when it read nothing.** Zero concepts or zero
  profiles is a failure, because a clean-looking answer from no input is
  indistinguishable from a clean bundle, and the empty report is the one that
  would be believed.
- **The loud direction is not restated.** A profile naming a concept that no
  longer exists already fails `lore check --strict` and `lore agent context`.
  The check inherits that failure rather than adding a rule for it: the failed
  read reaches it through `lore agent list`, and a failed read here is a
  failed check.

**Rejected: record an ADR-landing step instead.** A line in this repository's
instructions saying that adding a concept means updating the four source lists.
A convention has nothing watching it at the moment it is forgotten, and the
failure it would prevent is a concept added in good faith by someone who did
not know the convention existed. It cannot express the exclusion half either, so
a concept deliberately unwanted in every profile and a concept nobody
remembered would leave identical artifacts. A required check beats a written
warning where a check is available, and this one is a set comparison and five
`lore` reads.

**Rejected: declare narrowly and leave the budgets alone.** The check requires
one profile, so a concept could be declared once, the gate would be satisfied,
and three specialists would still be unable to reach it. That fixes the gate
and not the finding, and the check would then report clean over exactly the
condition it was written to catch.

**Rejected first, then adopted: failing when a pack truncates.** The first
version of this ADR rejected this assertion, on the reasoning that narrowing is
what the assembler is for and that gating on it would force budgets to grow with
the bundle until every profile carried everything. The measurement above refutes
the premise: truncation never occurred at the budgets in force before this
change, so it was not the assembler's steady state here but a regression this
change introduced, and a regression is what a gate is for. The second half of
the reasoning still stands as a cost, accepted deliberately: budgets do grow
with the bundle, and the gate is what makes each growth a decision instead of a
loss. The earlier reasoning is recorded rather than replaced because it is
plausible, and the next reader will have it.

## Consequences

- **Every accepted ADR is a candidate in all four profiles**, and each
  profile's budget holds its declared set. Packs are therefore larger than
  they were — 12.1–15.3k of a 17–20k budget, from 6.4–6.8k of 10–12k. That is
  the trade: a profile that declares N binding decisions needs a budget that
  holds N, and the alternative measured above is dropping them.
- **The budget is a growth trigger rather than a ceiling that silently
  bites.** The next concept to land evicts nothing; when the margin is finally
  exhausted the Docs job says so, and raising the budget or curating the
  declaration becomes a decision someone makes rather than a loss nobody sees.
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
  specialist who needs a concept will find it in its pack. The check catches a
  concept in no profile and a declared source that does not arrive. Curation
  quality is still a reading.
