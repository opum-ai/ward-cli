---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Cross-project grants are alias-bound, and restore clears them
tags:
  - grants
  - restore
  - security
summary: A sharingGrants record gives one owner secret to one target alias; approvals name the alias only; one transaction checks grant and owner; restore clears all grants and approvals (DEC-217 Q1, Q2).
generated:
  by: lore/0.14.1
  at: 2026-10-20T23:12:25.024Z
---

# Cross-project grants are alias-bound, and restore clears them

## Status

Accepted. Decided by opum-doc as **DEC-217** (ODOC-488), questions Q1 and Q2,
recorded on opum-doc `dev` and read from that record. Implemented under
WCLI-12. This ADR is the component-side record DEC-217 asks for.

## Context

Spec §7.2 requires a grant to reference one owner secret, one target project
and one target alias; to give the target `use` and nothing else; to reject
collisions; to refuse wildcards and target-created grants; to show an owner's
update on the next authorized use; and to block newly admitted operations on
revocation or owner deletion. [ADR 0003](0003-profile-approval-authority.md)
makes a profile approval the authority for one operation, bound to a checkout,
and makes revocation an admission-time rule. [ADR 0006](0006-backup-container-and-restore-authority.md)
recorded the obligation that a restore leave approvals and grants inactive once
grants exist.

## Decision

1. **A grant is one record in a `sharingGrants` collection**: `id`,
   `ownerProjectId`, `ownerSecretId`, `targetProjectId`, `targetAlias`,
   `createdAt` and `revokedAt`. It names the owner secret by id, not by alias,
   so an owner update (which keeps the id) shows on the next use, while
   deleting the secret and creating another under the same alias does not
   revive the grant. `revokedAt` is a timestamp or `null`, never absent, because
   the reader compares key sets exactly. A revoked grant stays as a tombstone;
   a re-grant is a new record. The collection is an authority record: the
   reader keeps its exact key set.
2. **A target's profile approval names the target alias only.** The snapshot is
   unchanged ([ADR 0003](0003-profile-approval-authority.md)); it does not carry
   a grant id, so re-creating a grant does not invalidate an approval the
   developer did not change.
3. **One resolver turns an alias into a secret.** `resolveSecret` returns the
   project's own secret, a granted one, a revoked one or a missing one, and
   `ward run`, its admission transaction and `ward check` all use it.
4. **Admission is one transaction.** Inside the admission write, the grant is
   active, the owner secret exists and is the owner project's, and its id and
   revision are the ones the run read. A revocation or owner deletion that
   landed first refuses the run with `grant_revoked` before anything is sent
   and before any audit record is written.
5. **An admitted run may finish.** Completion does not resolve the alias again:
   it records against the secret id the admission recorded, so a grant revoked
   or an owner secret deleted while a request is in flight cannot turn a sent
   request into an unaccounted one. Ward cannot recall a credential already
   sent, and the reports of `ward secret revoke` and `ward secret grant` say so.
6. **The target cannot change what it was given.** `set`, `delete`, `grant` and
   `revoke` on a granted alias are refused with `secret_granted_readonly`
   (exit 4), before the vault is written. Creating a grant refuses a target
   that already has a secret or grant under the alias (`grant_alias_conflict`),
   a pair already granted (`grant_exists`), the owner as target, and a target
   project this vault has not registered.
7. **Deleting an owner secret revokes its active grants in the same write.**
   The reader and the serializer both refuse a document in which an active
   grant names no existing owner secret, two active grants give one target the
   same alias, or an active grant collides with a secret its target owns, so no
   writer can leave a vault that cannot be opened.
8. **Granting is the developer's act on a terminal.** It asks a question the
   way `profile approve` does, and "no terminal" is never consent
   (`grant_requires_terminal`). Revoking narrows authority and asks nothing,
   like deleting a secret. DEC-217 is silent on the interactive gate; this is
   a choice made here and put to review.
9. **Restore clears every grant and every approval.** Projects and secrets are
   carried, bindings, approvals and grants are not. The developer re-registers,
   re-approves and re-grants. [ADR 0006](0006-backup-container-and-restore-authority.md)'s
   obligation now has its code site, in the projection `runRestore` builds.

## Consequences

Granting extends authority across a logical boundary that is not an OS
boundary ([ADR 0002](0002-p0-threat-model-and-non-guarantees.md)): any process
running as the developer can still run an approved profile. Neither revocation
nor deletion revokes the credential at its provider. The vault format gains
one collection and stays at version 1 (DEC-38). This build reads a document
written before the collection existed, since a missing key is an empty
collection; an older build refuses a newer document, because its top-level key
allowlist does not know the key. The release decisions on format tolerance are Q3 of DEC-217. The T12 and T21 gates
are recorded in the [security test matrix](../security-tests.md).
