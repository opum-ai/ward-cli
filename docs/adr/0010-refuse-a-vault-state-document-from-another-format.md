---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Refuse a vault state document from another format
summary: Move the vault state document to format 2 for the audit field set spec §9.4 requires, and refuse a format-1 document outright — there is no migration and no read-out.
generated:
  by: lore/0.11.0
  at: 2026-09-29T10:28:54.730Z
---

# Refuse a vault state document from another format

## Status

Accepted. Decided by the operator first-party through opum-doc on 2026-09-29,
relayed as R-2026-09-29-03, R-2026-09-29-08 and R-2026-09-29-11, and recorded
in opum-agent's tracker as DEC-19 (option B), DEC-25, DEC-26 (option A) and
DEC-30 (option A). Executed here as WCLI-11.

This is the state document inside the sealed envelope, not the envelope. The
envelope's own version is still 1 and is unchanged
([ADR 0001](0001-vault-storage-and-key-custody.md)); the two numbers are
independent, and only this one moved.

## Context

Spec §9.4 requires each audit event to carry more than format 1 recorded:
"observed OS identity, optional explicitly self-asserted actor/task labels"
alongside the operation, project and profile ids, opaque secret ids, time and
safe outcome code. `src/domain/vault-state.ts` recorded none of the three.

The obstacle is that this document's reader compares each record's key set
against an exact expected list and answers any difference with
`vault_state_malformed`. That check is what makes an event written by a build
with a different vocabulary a damaged record rather than a displayable one, so
adding a field changes what every build can read **in both directions**: an
older build meeting a newer document calls it malformed, and a newer build
meeting an older one does the same.

ward-cli measured this and put two options to the operator, recommending the
other one:

- **A — additive tolerant read, staying at version 1.** The parser would know
  two record shapes and check both; absence would display as "not recorded".
  No vault stops opening. Cost: two shapes to maintain, a mixed vocabulary
  after upgrade, and a version number that does not advertise the change.
- **B — strict, bumping the version to 2.** The cleanest "another build wrote
  this" refusal and one vocabulary ever. Cost, stated in full before the
  decision: **every pre-change vault, secrets included, becomes unreadable,
  with no migration and no read-out path** — possibly including the operator's
  own dogfood vault — and it is the first bump before the first release.

The operator chose B.

One sentence in the decision record is worth naming here because it was
withdrawn rather than amended: the first relay (R-2026-09-29-03) said the
recovery story for existing vaults was part of this work. It was opum-doc's
gloss and the operator did not say it; R-2026-09-29-08 withdrew it, and DEC-25
then confirmed first-party that there is no recovery. **Read the no-recovery
rule as the decision, not as a gap still to be filled.**

## Decision

**`vaultStateFormatVersion` is 2, and the version is the only format gate.**

- A vault document this build writes opens on every path. A format-1 document
  is refused by every command that reads the vault's contents — `ward run`,
  `ward audit`, `ward check` and `ward secret` all answer exit 6 with the
  sentence above, each measured.
- `ward doctor` reports it rather than refusing: its `schema` check fails with
  `state_unsupported`, which is the state document's verdict kept distinct
  from `vault_unsupported` for the envelope.
- **`ward status` does not report it, because it never reads the state
  document.** By [ADR 0007](0007-status-and-doctor-reporting.md) status
  answers from the sealed header alone so that it works without the key, and
  the header is unchanged here — so a format-1 vault reads as `present` with
  the record's format version, and the word `unsupported` appears nowhere in
  the report. A review measured this and it is the correction to an earlier
  version of this document, which claimed status reported it. Filed as WCLI-48
  alongside the printed version number, which has the same root: two format
  versions now exist and the report names one of them.
- **`ward backup` succeeds on a format-1 vault** and that is not yet
  settled either way. `src/application/backup.ts` seals the plaintext without
  parsing it, so the command exits 0 and writes a durable file whose restore
  then refuses with the sentence above — measured: backup 0, restore 6. The
  argument for leaving it: the container stays encrypted, and refusing would
  remove the only way to preserve a vault this build cannot read. The argument
  against: the command's own output invites the reader to treat that file as
  recovery material, and it is not. Filed as WCLI-49, and it is a decision for
  the coordinator rather than one this document should settle quietly.
- A missing or non-numeric `formatVersion` is still `vault_state_malformed`.
  A damaged document and a document from another build call for different
  things and must not converge on one answer.

**Each audit record carries the §9.4 field set.**

- `machine: { user, host }` — what the OS said, observed by Ward and never
  taken from an argument. It is `null` in exactly one case: the OS gave no
  answer Ward can record. `os.userInfo()` throws for a uid with no passwd
  entry, which is ordinary in a container, and Ward will not refuse to run in
  order to insist on a field a platform may not have. `ward audit` prints that
  as `not-recorded`.
- `actorLabel` and `taskLabel` — what the caller asserted through
  `ward run --actor-label` and `--task-label`, each bounded by the alias
  grammar and each `null` when the caller asserted nothing. They are
  correlation metadata: nothing in Ward reads them back, and a labelled run
  with no approval is refused exactly as an unlabelled one is. A label that
  fails the grammar is a usage fault, answered before the vault is opened.

**One refusal code, one sentence, three sites.** The envelope's version, a
stored profile snapshot's version and the state document's version all raise
`vault_format_unsupported`, whose message is now:

> This vault was written by a different version of Ward, and this build cannot
> read it. Ward did not change it.

It carries no hint and no version numbers. A hint would name a recovery this
build does not have, and a found-or-expected pair would invite action there is
none to take.

**No recovery surface exists.** There is no `ward migrate`, no read-out into a
fresh vault, and no domain function that rewrites a document from another
format. The refusal is the whole answer, and `test/vault-format-refusal.test.ts`
asserts that absence beside a positive control, because an absent signal and a
passing one are different facts.

## Consequences

- **A vault written before this change stops opening, and its secrets are lost
  to Ward.** That is the accepted cost of B, not a defect to be repaired. It
  applies equally to the developer's own vault, and it is why the refusal text
  says plainly that Ward did not change anything.
- **The audit history is not carried forward on any path.** A restore is the
  one place records cross a vault boundary
  ([ADR 0006](0006-backup-container-and-restore-authority.md)) and it carries
  whatever the backup's own state document holds, so a format-1 backup file is
  refused on the same terms as the vault it came from. It can still be
  *created* — `ward backup` seals the plaintext without parsing it, so it
  exits 0 on a vault nothing else will read. Whether it should is open, not
  decided here; see the `ward backup` bullet under Decision.
- **Two absences in `ward audit` read differently on purpose.** A missing
  machine is Ward saying it observed no identity; a missing label is the caller
  saying it asserted none. The report prints `not-recorded` for the first and
  `none` for the second, because collapsing them would erase the distinction
  between an observation and an assertion that these fields exist to keep.
- **The fixtures that build vault documents are regenerated for format 2, with
  one genuine format-1 document retained** — verbatim, eight-key audit record
  and all — so the refusal is pinned rather than described. It is in
  `test/project-documents.test.ts`, and its test asserts both answers about the
  same bytes: refused by the version as written, refused for the record when
  only the version is changed. That pairing is what makes the first answer a
  reading of the version rather than of the contents.
- **`--actor-label` and `--task-label` are the first caller-supplied strings
  Ward writes into a record.** They are the reason `ward audit`'s own doc
  comment no longer claims every field is Ward-owned: what still holds, and is
  what matters, is that nothing is free text. A label is at most 64 characters
  of letters, digits, dot, underscore and dash, and the observed identity is
  bounded to printable characters: C0, DEL, the C1 block, the two Unicode line
  separators and every Cf format character are refused, so a name cannot break
  or reverse the line `ward audit` prints it on. The first version of that
  grammar refused only C0 and DEL, and a review measured U+0085, U+2028 and
  U+202E passing it; the constraint and the claim now agree.
