---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Status and doctor reporting
tags:
  - cli
  - reporting
  - health
summary: ward status and ward doctor report the state of the current checkout read-only; doctor exits 6 only when a check over something present failed.
status: stable
generated:
  by: lore/0.11.0
  at: 2026-09-29T00:39:33.997Z
---

# Status and doctor reporting

## Status

Accepted. It implements spec §8's `ward status --json` and `ward doctor --json`
rows for WCLI-26 and records the points those rows leave to the
implementation: what each report contains, what a health check's result means,
and which exit carries a failed check.

## Context

Spec §8 gives each command one line. Status is "safe current-project and
backend state; no global inventory or secret previews". Doctor is "read-only
permissions, key-provider, schema, binding, and instruction health", and must
"never dump keys or request headers". Neither line says what the reports
contain, what "absence" means for a health check, or when doctor fails.

Three shapes are easy to get wrong. A report can read almost nothing and still
print a clean result — the failure mode where silence looks like success. A
check that cannot run (no vault, no key, a locked store) can be reported as a
pass, for the same reason. And "no global inventory" can be read down until a
conflict names the project it conflicts with, which is inventory leaving
through a field rather than a list.

## Decision

**Both commands are one read-only observation, two presentations, and the same
exit contract the fleet already uses for a check whose report is the payload:
`ward status` always exits 0 when it can report, `ward doctor` exits 0 or 6,
and the report reaches stdout either way. A check fails only when something
present is wrong or cannot be evaluated; absence is reported, never failed.**

- **Only the current checkout.** Status reports the canonical root, the
  manifest's claim (project id and schema version), the binding state for this
  root (`registered`, `unregistered`, `conflict`, `unknown`), the vault's
  presence, revision and record format version, and the key provider's
  verdict. It never enumerates the vault. A checkout bound to another project
  is reported as a conflict and that project is never named — the report
  carries this checkout's own claim from the tracked manifest, which the
  repository already holds. Tests seed the vault with a second project and a
  second binding carrying sentinels and assert neither can appear in either
  output, with the current project's own id asserted present as the positive
  control. A stale approval is the one place a vault-wide fact reaches a
  report, and it reaches it as a count only: see the bullet below.
- **A stale approval is named only for the current project.** DEC-246 (a3)
  Q1 settles the scope: records of the project this checkout declares are
  named, including records on that project's deleted worktrees, each with its
  checkout, snapshot version and re-approve step; records of any other project
  appear as a bare count, with no id, profile name or path. That is visibility
  where the operator can act, without turning an `admin: false` report that
  the skill tells agents to read into an inventory of the vault. A test seeds
  a second project's stale approval carrying sentinels and asserts it is
  counted and never named, with the current project's record named as the
  positive control.
- **Doctor runs six checks, in a fixed order, and always reports all six:**
  `permissions`, `key_provider`, `schema`, `binding`, `stale_approvals`,
  `instructions`. Each
  carries a stable code. Every check is evaluated independently, so one
  failure never suppresses the others' answers.
- **A check's result is `pass`, `fail` or `skipped`.** `fail` means the
  check's subject is present and wrong, *or* present and cannot be evaluated:
  a blocked check must not read as a healthy one, and a failure that could not
  be measured reports the blocking reason as its code (`key_missing`,
  `vault_insecure`, `state_unreadable`). `skipped` means the subject does not
  exist here — no vault, no manifest, no installed block — and names the
  absence (`vault_absent`, `manifest_absent`, `absent`).
- **Absence is never a failure.** A machine or checkout that was never set up
  has nothing wrong with it; readiness for a profile is `ward check`
  (WCLI-9), not this command. The consequence is deliberately narrow: doctor
  exits 6 only for a condition that is wrong about something present, and a
  skipped check is not evidence of readiness. `ok: true` and exit 0 mean no
  check failed — not that anything is set up; a consumer that needs readiness
  reads the per-check statuses.
- **A stale approval fails only when it can still be cleared.** DEC-246 (a3)
  Q2 settles the second half: `stale_approvals` fails, with
  `reapprove_required`, only for a record whose checkout still resolves to the
  same root, device and inode, and whose profile its manifest still declares —
  that is, one where running the re-approve step there would actually replace
  it. Every other record is reported as inert (legacy arms: ADR 0026), and
  the check passes with the code `inert` rather than exiting 6 forever over a step nothing can perform. A record of another
  project alone gives `other_projects`; no stale records at all gives
  `current`. Removing an inert record is a later task, not this release.
- **The instruction check judges the blocks that exist.** A block whose bytes
  are not what this build writes is `stale`; a block whose markers the writer
  would refuse is `malformed`; both fail. A host with no block at all is
  reported and skipped, because bridge selection is optional and the manifest
  does not record it — judging absence for a named host is
  `ward agents --check` (WCLI-14). The check reuses the writer's own marker
  grammar, so the two cannot drift apart.
- **Read-only by construction.** The module implements both reports with
  `header`, `load`, `read` and project file reads only; it contains no call to
  `mutate`, `create` or a file write. Both commands declare `unlocksVault:
  true` in the manifest because they do read the vault, and neither is marked
  `admin`: an agent may run them. Outside a Git worktree both exit 3 with
  `worktree_not_found`, the same as every project command; `ward manifest` and
  `ward instructions` remain the commands that run anywhere.
- **Nothing secret.** The only vault value either report touches is the key,
  used and zeroed, never rendered. Outputs carry state words, identifiers and
  versions. No transport exists in this build, so no request header can be
  printed; when `ward run` (WCLI-10) lands, that claim must be re-measured
  against it rather than assumed.

## Consequences

- **The vault header now carries the record's format version.** It is in the
  header table already and readable without the key, so a report can name the
  schema it would have to read even when the key is missing; the port change
  is additive and the store's own tests pin the new shape.
- **Nothing either command does can change bytes it controls.** Pinned by
  test: the vault database, the project manifest and both bridge files are
  byte-identical before and after both commands, nothing new appears in the
  vault directory or the checkout, the vault revision is unchanged, and the
  credential store sees no write. One change is outside Ward's control and is
  inherited from the store rather than introduced here: SQLite's mandatory
  open-time recovery of a file left mid-transaction with a hot journal rolls
  that transaction back when the database is opened (ADR 0001), before any
  layout check can read it, and a read cannot decline to cause it.
- **An empty vault file reads as absent, by the store's own contract.** An
  interrupted `ward setup` can leave an empty `ward.db` that reads as no
  vault at all (ADR 0001); status reports the vault as absent and doctor
  skips the vault-dependent checks. Nothing is lost — the store's `create`
  accepts that file — but "absent" must not be read as "nothing is on disk".
- **A locked or unreadable vault is a failure, not a pass.** `vault_busy`
  from a concurrent writer and `vault_store_failed` are reported as failures
  of the checks that needed them, because "could not read" and "read and
  fine" must not share an exit code.
- **A credential store that never answers is bounded the same way the other
  commands bound it** (WCLI-20): the key check reports `unavailable` and the
  process is told to exit explicitly rather than wait on a pending native
  call.
- **What is not claimed:** that doctor proves anything outside its six
  checks; that a skipped check says a checkout is ready; and that a report can
  distinguish *why* a credential store refused (locked, access denied,
  timed out) — the adapter maps those to one verdict by design, so the report
  says `unavailable` and cannot say more.
