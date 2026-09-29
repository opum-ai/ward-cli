---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: T24's Codex half is qualified by the artifacts plus a documented manual smoke
tags:
  - agents
  - qualification
summary: The agent contract is proved by the bridge artifacts and ward agents --check for both hosts, and Codex's half by a documented manual smoke run at each release rather than an automated one (DEC-45).
generated:
  by: lore/0.11.0
  at: 2026-09-29T16:21:25.114Z
---

# T24's Codex half is qualified by the artifacts plus a documented manual smoke

## Status

Accepted. Answered first-party by the operator through opum-doc on
2026-09-29 as **DEC-45**, relayed by opum-agent (ODOC-OP-2026-09-29-16), and
recorded under WCLI-14. The operator chose the option written as "Artifacts +
manual smoke", which is the one this document records.

## Context

Release gate T24 reads "Claude/Codex can discover guidance and perform
check/run using synthetic data without requesting values or self-approval"
(spec §14). Its Claude half is already qualified by the eval suite WCLI-50
landed: `evals/` holds adversarial cases run through `claude plugin eval` by
`scripts/run-eval.sh`, which the repository documents as a release gate rather
than a CI job, because it bills API tokens. A structural check over the same
suite runs in CI.

Its Codex half has no such harness, and none exists anywhere in the fleet: the
fleet's eval suites are Claude Code harnesses, and Codex is retired as a
runtime this fleet dispatches to. Codex remains a *product* target for Ward
all the same — spec §11.2 names `.agents/skills/ward/SKILL.md` for "current
Codex local discovery" and `ward agents --target codex` writes and judges
`AGENTS.md` — so the gate cannot simply be read down to Claude alone without
saying so.

The question put to the operator was whether P0 must run Codex automatically
to satisfy T24, or whether the artifacts plus a documented manual run
discharge it.

## Decision

1. **The bridge artifacts are the qualifying evidence, for both hosts.** What
   T24 requires of the Codex side is that Codex can discover Ward's guidance
   and perform `check`/`run` without asking for a value or approving itself.
   That is carried by the two artifacts Ward produces for it — the guidance
   block in `AGENTS.md` and the packaged skill — and by
   `ward agents --check --target codex`, which judges the block's presence,
   currency and marker integrity without modifying anything.
2. **Codex's behavioural half is a documented manual smoke run at each
   release**, not an automated job. It is written down in the release
   procedure with the synthetic-data setup it needs, and its outcome is
   recorded with the release's other gate results. It is deliberately not in
   CI: the fleet has no Codex harness, and inventing one for a retired runtime
   would add a machine nobody maintains to a gate that only needs to be
   discharged honestly at release time.
3. **The Claude half is unchanged** and stays where WCLI-50 put it: the eval
   suite and its ablation run, as a release gate rather than a required check.

## Consequences

- **T24 is dischargeable at release time rather than on every push.** The
  manual smoke's evidence is a recorded result in the release's gate record,
  which is where spec §14 already asks for results to be kept
  (`docs/security-tests.md` maps each gate to a test and a result).
- **The manual step is the weak half, and it is named as such.** An automated
  check cannot be skipped by a busy release; a documented one can. That cost
  is accepted here rather than hidden, and it is bounded by the artifacts
  half, which *is* automated and runs in CI on every change to the bridge.
- **If a Codex harness ever exists in the fleet**, moving the smoke from
  documented to automated is an improvement to this decision rather than a
  reversal of it: the artifact half and the manual result would both stay.
