---
# yaml-language-server: $schema=../../.lore/schemas/reference.schema.json
type: Reference
title: "Ward's spec of record: the CLI contract and the release gates"
tags:
  - spec
  - pointer
summary: A pointer to WARD_MVP_AGENT_SPEC.md at the repository root - the source of record for the CLI contract (section 8) and the release gates (section 14) - carrying no copy of its text (DEC-51).
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:19:42.536Z
---

# Ward's spec of record: the CLI contract and the release gates

## Details

The source of record for Ward's v0.1 contract is **`WARD_MVP_AGENT_SPEC.md` at
the repository root**. It is not a bundle concept - it sits outside `docs/` -
so this document is the concept a specialist profile can declare and a
specialist can cite. It is a pointer, not an extract: no text from the spec is
copied here, and none should be. Read the file itself, by ref
(`git show origin/dev:WARD_MVP_AGENT_SPEC.md` or the working tree), and cite
the section you read.

The two sections specialists actually cite, under the headings the file uses:

- **Section 8, "CLI contract"** - the command table every review of a command's
  surface is measured against, and the source of the exit-code and
  no-secret-in-output rules those rows carry.
- **Section 14, "Acceptance tests: release gates"** - the gate table (T01-T26)
  that names what a release claim is measured by; the runbooks and the
  release runbook reference its rows by those gate ids.

Section numbers name the file's own headings, and the headings are the
authority if a numbering edit ever moves one.

## Provenance

Recorded 2026-09-29 as the operator's answer to WCLI-30 (DEC-51, ADR 0019).
The gap this closes was measured twice, independently: the WCLI-8 independent
review and the WCLI-9 independent review each reported that their context pack
could not cite the spec, so each grounded its spec claims on the dispatcher's
brief - text no later reader can check against a source. WCLI-8's review named
the sections it read directly (6.2, 7.1, 8); WCLI-30's record also names 14.
This concept names the two the packet proposed and the operator approved. The
question of widening it to a third section was asked and answered on
2026-09-29 (DEC-56, recorded in ADR 0019): it stays two.
