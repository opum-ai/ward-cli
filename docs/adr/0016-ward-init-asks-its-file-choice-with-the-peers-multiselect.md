---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: ward init asks its file choice with the peers' multiselect
tags:
  - cli
  - agents
summary: On a terminal, with no target flag and no --json, ward init asks which instruction files to write with @clack/prompts on stderr; everywhere else it writes exactly what its flags name (DEC-48, DEC-52).
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:05:00.000Z
---

# ward init asks its file choice with the peers' multiselect

## Status

Accepted. Two first-party operator answers, both relayed by opum-agent and
recorded under WCLI-14, which carries the work.

**DEC-48** (ODOC-OP-2026-09-29-17), in the operator's own words, neither of
the packet's options as written:

> check lore-cli and quest-cli and use the same pattern

**DEC-52** (ODOC-OP-2026-09-29-19), the repository's follow-up question about
the terminal contract, answered as the recommended option:

> lore's shape (Recommended)

## Context

ADR 0011 left the interaction shape open: a typed multi-answer in this CLI's
existing one-line prompt idiom, or a raw-mode checkbox. DEC-48 answered it by
pointing at the peers, so their implementations were read by ref before
anything was built (quest-cli `dev` 5f47120, lore-cli `dev` 524a2f3):

- Both ask the question with **`@clack/prompts`**, in the same words -
  "Select instruction files to write (space toggles, enter accepts)" - with
  `required: false`, nothing pre-checked, and an empty selection legal.
  lore-cli's own comment names the shared pattern as "same library
  (@clack/prompts), same wording, same required:false/empty-selection-legal
  semantics, same cancel handling".
- Their stream contracts **differ**. quest-cli passes no streams to clack (so
  its prompt renders on clack's default stdout) and gates on `stdoutIsTty &&
  stdinIsTty`; lore-cli passes explicit input/output with **stderr** as the
  output and gates on `stdin && stderr` being TTYs, its ADR 0017 recording
  why: a prompt on a redirected stream is a prompt nobody can answer.
- Ward's own prompt contract (spec §7.1/§4.3, `src/adapters/terminal-consent.ts`)
  gates on `process.stdin.isTTY` alone and writes to `/dev/tty` when it can,
  else stderr - and never stdout, which is the machine-readable channel.
  quest's shape is therefore excluded outright for Ward, and the remaining
  choice between lore's and Ward's own was put back to the operator as an
  A/B under the orchestrator's instruction not to decide it locally.

## Decision

1. **The question is the peers'**: `@clack/prompts`' multiselect, message
   "Select instruction files to write (space toggles, enter accepts)",
   options `CLAUDE.md — Claude Code` and `AGENTS.md — Codex, Cursor, Zed,
   Warp, Aider, RooCode, OpenCode, pi, and other AGENTS.md-reading tools`
   (lore-cli's labels for the two files Ward supports), nothing pre-checked,
   `required: false`. A bare Enter writes no bridge - an empty selection is a
   decision, and the run says so and prints the flag path.
2. **The gate is DEC-52's, lore's shape**: the prompt is offered only when
   **stdin and stderr are both TTYs**, no `--claude` or `--codex` was given,
   and `--json` was not requested. Anywhere else there is no prompt at all:
   the flags write exactly the files they name, and a run with no flags
   selects nothing - today's non-interactive behavior, unchanged.
3. **The prompt renders on stderr**, never stdout, through clack's explicit
   `output` option; keys come from stdin. Ward's other prompts keep their own
   contract (below) rather than being migrated.
4. **A cancel aborts before anything is written.** Ctrl-C, a stdin that ends
   while the prompt is open, or a terminal that fails mid-prompt all resolve
   to the same answer - no answer - and `ward init` stops with
   `init_cancelled` (usage, exit 2) and a hint naming the flag path. It is
   deliberately not an empty selection: the run does not continue to ask the
   registration question the developer just interrupted, and nothing has been
   written at that point because the question is asked before `initProject`.
5. **The choice is exactly the two files a bridge writes** - no skill file
   (DEC-44), no other target the peers offer that Ward has no block for.

## Consequences

- **One new interaction surface, gated and testable without a terminal.**
  The chooser is a seam on `RunOptions` the way the registration and profile
  approvers already are, so the command's selection and cancel semantics are
  pinned in tests; clack itself is reached only through a small adapter
  (`src/adapters/init-prompt.ts`) whose call site is one line.
- **Ward now has two prompt contracts, deliberately.** The consent and
  approval prompts keep their existing stronger shape (`/dev/tty` when
  available, so a stderr redirect cannot hide an approval; stdin-only gate).
  The wizard's gate is stricter than theirs because its prompt is on stderr
  by DEC-52 - if the wizard's gate were stdin-only, a `ward init 2>log` in a
  terminal would ask a question whose bytes land in the log. The asymmetry is
  recorded here so a later reader does not "fix" one to match the other
  without re-opening the decision.
- **A bare `ward init` on a terminal now asks where it used to print a
  hint.** That discoverability is the point of DEC-44's multiselect; the
  hint and the flags remain for every non-interactive caller.
- **`--json` never prompts**, on or off a terminal, so a machine-readable
  invocation cannot block on a question no consumer can answer.
