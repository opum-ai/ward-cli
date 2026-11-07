---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Profile approval authority
tags:
  - security
  - profiles
  - authority
status: stable
summary: Only the developer approves an HTTPS profile; a manifest is a request, not authority.
generated:
  by: lore/0.11.0
  at: 2026-09-28T16:53:26.463Z
---

# Profile approval authority

## Status

Accepted. This ADR restates decisions spec §2, §4.3, §7.2 and §9.2 already make, and rules nothing new, so it needs no opum-doc record (opum-agent, 2026-09-28).

## Context

An agent drives Ward, but the operation that consumes a credential must be one the developer
chose. Spec §2 (agent access), §4.3 and §9.2 already decide who holds that authority. This ADR
records that position for the implementation tasks (WCLI-9, WCLI-10, WCLI-12) and does not
reopen it.

## Decision

**Only the developer approves an HTTPS profile, grants a secret, or revokes either**, from a
trusted terminal. The agent's skill never runs these commands to approve itself.

- **A manifest is a request, not authority.** `.ward/project.json` is tracked, and anyone who can
  edit the repository can change it. What authorizes execution is the normalized snapshot the
  developer approved, stored in the encrypted vault and bound to the project. The snapshot covers:
  - the adapter;
  - the exact method and URL;
  - the authentication scheme and aliases;
  - the permitted non-secret headers;
  - the body policy and the output policy;
  - the bound project and root.
- **At execution the declared profile must match the snapshot.** Any change to the destination,
  method, authentication references, body policy or output policy invalidates the approval.
  Unknown fields are rejected. There are no runtime overrides of URL, method, authentication or
  output.
- **Grants are exact and use-only.** A grant names one owner secret, one target project and one
  target alias. It confers `use`, never read, update, delete or regrant. No wildcard grants
  exist, and a target-controlled manifest cannot create a grant (spec §7.2).
- **Agents get metadata, readiness checks and execution of approved profiles.** There is no
  plaintext retrieval command.

## Consequences

- An interactive approval gate reduces mistakes. It is not proof of human identity, so no
  command is labelled human-authenticated on the strength of `isatty()` or a declared actor kind
  (spec §4.3).
- A profile that accepts a request body can authorize broad behaviour, so it is never described as
  fine-grained business-action authorization. The default is no body.
- Revocation blocks newly admitted operations only. Ward cannot recall a credential it has already
  sent, and it does not revoke credentials at their provider.

## Amendment, 2026-11-07 (DEC-262 a3, WCLI-149)

A **sign** profile is a second approved operation: see [ADR 0027](0027-an-ed25519-sign-operation-sign-keys-are-a-kind-of-secret-record-never-exported.md).
