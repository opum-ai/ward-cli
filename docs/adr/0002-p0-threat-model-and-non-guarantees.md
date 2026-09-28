---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: P0 threat model and non-guarantees
tags:
  - security
  - threat-model
status: stable
summary: What Ward P0 protects against, and what it explicitly does not.
generated:
  by: lore/0.11.0
  at: 2026-09-28T16:53:26.371Z
---

# P0 threat model and non-guarantees

## Status

Accepted. Ruled by the orchestrator (opum-agent) on 2026-09-28 and recorded in opum-doc as ODOC-312, `docs/adr/record-ward-cli-wcli-3-vault-format-key-custody-and-plugin-name.md` (opum-doc main d6516c5).

## Context

Ward is a local CLI that runs as the developer's OS user, inside repositories that an agent can
edit. Its security claims are deliberately bounded (spec §1, §4). Those bounds have to be written
down before any implementation leans on them, so that no later document, skill or completion
report strengthens them.

## Decision

**P0 protects against accidental disclosure through normal Ward use** (spec §4.1). That covers:

- committed `.env` files and credential-bearing arguments;
- exported credentials, copied CLI output, prompts and agent memory;
- raw HTTP errors and diagnostic logs;
- unencrypted backups;
- unintended cross-project lookup through Ward.

Tampering with the encrypted vault is detected before any plaintext is used. A manifest copied
into another repository does not grant access to the original project's credentials, and a
repository change does not silently widen an approved operation.

**P0 does not protect against** a compromised OS account, root, a hostile runtime or dependency, a
debugger with adequate privileges, access to unlocked keychain material, or arbitrary code
running with the developer's authority (spec §4.2). Project separation is logical, not a boundary
against the same OS user. A project UUID, a path check, an actor label, a TTY check and a prompt
instruction are guardrails, not authentication.

Ward's supported agent-facing commands never intentionally serialize stored values, key
material, secret-derived previews, secret-bearing headers or raw upstream bodies into any output
(spec §4.3). Diagnostics come from a fixed catalogue and never echo their input.

The following are measured instances of the non-guarantees, recorded so that nobody reads them as
defects to fix in P0:

- **The launcher.** The shipped executable ignores the working directory's `bunfig.toml` and
  `.env` (WCLI-16). The inherited `BUN_OPTIONS` and `BUN_BE_BUN` still reach it (WCLI-19), which
  is arbitrary code with equivalent authority.
- **The keychain.** The Keychain ACL is per-build and ad-hoc signed. Developer ID signing, the
  precondition for any ACL claim, is an operator decision held as opum-agent OPAG-672. See
  [vault storage and key custody](0001-vault-storage-and-key-custody.md).

## Consequences

- Ward may not claim any of the following: perfect memory zeroization, swap exclusion, forensic
  deletion, rollback resistance, immutable audit logging, FIPS validation, universal
  prompt-injection resistance, or information-flow noninterference (spec §4.2). Zeroing that the
  code does is best effort and stated as such.
- A later hostile-agent boundary would put the broker outside the agent's OS or sandbox identity,
  behind a narrow authenticated interface. Nothing in P0 is a step toward that boundary that could
  be advertised as partial isolation.
- SECURITY.md and the acceptance-test matrix (WCLI-15) restate these limits. They do not soften or
  extend them.
