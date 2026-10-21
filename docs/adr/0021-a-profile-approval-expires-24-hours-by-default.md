---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: A profile approval expires, 24 hours by default
tags:
  - approvals
  - security
summary: "Every profile approval carries expiresAt: 24 hours by default, --ttl 1m to 30d; admission checks it in the transaction; completion does not (DEC-217 Q5)."
generated:
  by: lore/0.14.1
  at: 2026-10-20T23:24:53.578Z
---

# A profile approval expires, 24 hours by default

## Status

Accepted. Decided by opum-doc as **DEC-217** (ODOC-488), question Q5, read from
the decision record on opum-doc `dev`. Implemented under WCLI-72.

## Context

A profile approval ([ADR 0003](0003-profile-approval-authority.md)) was durable:
once given, any process running as the developer could repeat `ward run` until
`ward profile revoke`. [ADR 0002](0002-p0-threat-model-and-non-guarantees.md)
concedes that process, but an agent session is exactly that process, and an
unattended one could replay an approval indefinitely. The field also has to
exist before the vault format freezes, because after a release it is a
format-compatibility question.

## Decision

1. **Every approval carries `expiresAt`**, a timestamp strictly after
   `approvedAt`. The reader keeps the record's exact key set and refuses a
   missing, malformed or non-later expiry as a damaged document. The format
   version stays 1 (DEC-38). The reader now refuses an approval that lacks
   `expiresAt`, so a vault written by the previous build fails to parse. That
   is allowed before the first release (WCLI-38); the recovery is to
   re-approve, or to restore from a fresh backup.
2. **The default lifetime is 24 hours.** `ward profile approve <name> --ttl <n>
   <unit>` names another, written as one whole number and one unit (`m`, `h`
   or `d`), for example `--ttl 8h`. The bounds are 1 minute to 30 days, a build
   detail chosen here and put to review: a shorter approval could expire before
   the developer's next command, and a longer one is a durable approval under
   another name. Approving again replaces the record and renews the lifetime.
3. **Admission checks it inside the transaction.** `ward run` refuses an
   expired approval with `profile_approval_expired` (exit 4) before anything is
   sent and before any audit record is written, once at the pre-read and again
   in the admission write against the time of admission. The instant of expiry
   is expired.
4. **Completion does not check it.** An operation admitted before the approval
   ran out may finish and records its completion, the same admission-time rule
   [ADR 0020](0020-cross-project-grants-are-alias-bound-and-restore-clears-them.md)
   applies to revocation.
5. **`ward profile list` and `ward check` report an unchanged approval past its
   expiry as `expired`**, with the reason `approval-expired`. A changed
   declaration is still `stale`, whatever the clock says.

## Consequences

A long-running agent must be re-approved by the developer on a terminal when the
lifetime ends. That friction is the point: it bounds replay of a leaked or
forgotten approval. It is not a defence against a hostile process during the
lifetime, and it revokes nothing at the credential's provider.
