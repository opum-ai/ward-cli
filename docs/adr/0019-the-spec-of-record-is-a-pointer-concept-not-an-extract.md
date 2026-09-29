---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: The spec of record is a pointer concept, not an extract
tags:
  - spec
  - agents
summary: WARD_MVP_AGENT_SPEC.md enters the bundle as one Reference concept naming the file and its two cited sections, copying none of its text, declared in review and verification (DEC-51).
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:22:55.000Z
---

# The spec of record is a pointer concept, not an extract

## Status

Accepted. Answered first-party by the operator through opum-doc on
2026-09-29 as **DEC-51**, relayed by opum-agent (ODOC-OP-2026-09-29-18), and
recorded under WCLI-30, which was filed by the WCLI-8 review for this gap.
The operator's answer was the packet's recommended option, in their own
selection label:

> Pointer entry (Recommended)

The packet's own wording, verified in opum-agent's tracker by ref
(`.quest/planning.json`, DEC-51 option A): "one Reference concept that names
the file as the source of record, names the two sections specialists actually
cite (the gate table and the CLI contract), copies none of their text, and is
declared in the review and verification profiles."

One follow-up question - whether the concept should also name a third section
- was answered the same day as **DEC-56** (relayed by opum-agent,
ODOC-OP-2026-09-29-21, 18:00:08Z), again as the recommended option, in the
operator's own selection label:

> Keep the two (Recommended)

Sections 8 and 14 only, exactly as DEC-51 approved; the concept is unchanged,
and decision 5 below records the answer.

## Context

`WARD_MVP_AGENT_SPEC.md` is the v0.1 implementation brief and the source of
the release gates T01-T26. It sits at the repository root, not under `docs/`,
so it is not a bundle concept and no specialist profile can declare it - and a
pack selects only among the sources its profile lists.

The gap was measured twice, independently. The WCLI-8 review and the WCLI-9
review each reported that their compiled pack could not cite the spec, and
each grounded its spec claims on the dispatcher's brief instead - material no
later reader can check against a source. WCLI-8's review named the sections it
had to read directly: §6.2, §7.1 and §8. WCLI-30's record also names §14.

Measured before this change, re-read rather than remembered:

- A review pack for a change of this kind carried 11 sources (the declared
  ADRs plus `index`), 17,653 of its 20,000-token budget, `truncated: false`,
  and named no spec section because it cannot.
- ADR 0008's own budget measurement, re-read for this record: when it was
  taken, 16 of 16 packs compiled at 6,428-6,752 tokens of a 10,000-12,000
  budget with nothing dropped, and declaring the whole bundle against those
  budgets truncated 16 of 16. That is why a wide addition has a measured cost
  here rather than an assumed one.

## Decision

1. **One Reference concept, a pointer and not an extract**:
   [`reference/ward-s-spec-of-record-the-cli-contract-and-the-release-gates`](../reference/ward-s-spec-of-record-the-cli-contract-and-the-release-gates.md).
   It names `WARD_MVP_AGENT_SPEC.md` at the repository root as the source of
   record and the two sections specialists actually cite, by the file's own
   headings: **section 8, "CLI contract"** and **section 14, "Acceptance
   tests: release gates"** (the gate table). It copies no text from the spec,
   and it says the headings are the authority if numbering ever moves.
2. **Declared in the `review` and `verification` profiles** - the two whose
   specialists make claims the spec governs - so a pack can cite it and the
   check that every concept is a profile source keeps it that way.
3. **The spec file stays the one copy of normative text.** A second copy in
   the bundle is the drift hazard the peers' skill arrangements already
   taught this repository to avoid, and the extract alternative was rejected
   for that reason plus its measured cost: sections 8 and 14 are several
   times the pack headroom, so an extract would either raise budgets again or
   drop sources, which ADR 0008's check fails on.
4. **Demonstrated, not assumed**: with the concept declared, the review pack
   compiles it into its catalog (12 sources, 18,244 of 20,000 tokens,
   `truncated: false`), the verification pack does too (13 sources, 17,460 of
   20,000, `truncated: false`; its budget rose 17,000 to 20,000 in this
   change, the only budget that needed it), and
   `scripts/check-lore-agent-sources.mjs` exits 0 with 22 concepts, none
   uncovered and no pack truncated.
5. **The question of a third section was asked and answered: the pointer
   keeps the two.** The packet named two sections, and the repository's own
   measurements show a third being read directly (§6.2 in both WCLI-8's
   record and WCLI-30's, §7.1 in WCLI-8's), so widening the concept was put
   to the operator rather than decided here. The answer, first-party as
   **DEC-56**, was the recommended option in the operator's own label:
   "Keep the two (Recommended)". The concept names sections 8 and 14 only,
   exactly as DEC-51 approved. A specialist grounding a section 6.2 or 7.1
   claim still cites this concept, because it names the whole file as the
   source of record and tells the reader to cite the section they read.

## Consequences

- **A specialist has a real concept id to cite**, which is the whole repair:
  a review's spec claims stop resting on a brief that cannot be checked later.
- **The pointer costs about 200 tokens in each of two packs**, both within
  their budgets with room; nothing else changed for either profile.
- **The pointer can go stale in one way - numbering** - and the concept says
  what to trust when it does (the headings in the file itself). It carries no
  text that can drift, because it carries none at all.
- **The third-section question is closed (DEC-56).** Reopening it is a new
  decision rather than a re-litigation of this record; the concept, the two
  profiles and their packs stay as they are.
