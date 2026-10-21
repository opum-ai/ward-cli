---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Restoring a Ward vault from a backup
tags:
  - restore
  - recovery
summary: Restore a Ward backup into an empty vault, then re-register checkouts, re-approve profiles and re-grant shared secrets; restore clears every binding, approval and grant (DEC-217 Q2).
generated:
  by: lore/0.14.1
  at: 2026-10-20T23:35:49.435Z
---

# Restoring a Ward vault from a backup

## Purpose

This is the act of recovering a developer's vault from a backup file made with
`ward backup`, and what the developer must do afterwards. The design is
[ADR 0006](../adr/0006-backup-container-and-restore-authority.md) and
[ADR 0020](../adr/0020-cross-project-grants-are-alias-bound-and-restore-clears-them.md).

**A restore is an authority reset.** It clears every local binding, every
profile approval and every cross-project grant. Projects, secrets and the audit
history come across. Nothing that was approved or shared before the backup was
taken, or since, is live afterwards, so restoring an older backup cannot revive
access that was granted, changed or revoked in the meantime (DEC-217 Q2).

## Prerequisites

- A backup file and its passphrase. The passphrase is entered on a terminal;
  Ward has no recovery for a lost one.
- An empty destination: `ward restore` refuses a vault that already exists. It
  mints a fresh vault key and vault id, so the old credential-store item is not
  needed to open the backup.

## Steps

1. Run `ward restore --input <backup file>` in a terminal. The report states
   that bindings, approvals and grants are cleared.
2. In each repository that should use a project again, run `ward init` and
   confirm the registration.
3. In each of those checkouts, re-approve each profile the checkout runs with
   `ward profile approve <name>`. An approval lasts 24 hours unless approved
   with `--ttl`. A vault or backup written before approvals carried an expiry
   fails to parse because its approvals lack `expiresAt`; before the first
   release the recovery is to re-approve, or to restore from a backup taken by
   the current build.
4. For every secret that one project shared with another, have the owning
   project's developer run `ward secret grant <alias> --to <project-id> --as
   <alias>` again from the owner's checkout. The target's profiles keep naming
   the target alias and need no change.
5. Run `ward check` in each checkout. A profile whose grant is still missing
   reports the credential as missing; one whose grant was revoked reports
   `grant-revoked`.

## Verification

`ward doctor` passes, and `ward check` is ready in each checkout that should
run profiles. Restoring revokes nothing at a credential's provider: a
credential that was exposed before the backup is still exposed, and rotating it
is a separate act.
