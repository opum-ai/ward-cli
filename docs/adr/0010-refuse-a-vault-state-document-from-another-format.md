---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: One vault state document format
summary: The state document has a single format at version 1, and a document whose shape is not this build's is refused by the reader's exact key-set comparison rather than by a version gate.
generated:
  by: lore/0.11.0
  at: 2026-09-29T10:28:54.730Z
---

# One vault state document format

## Status

Accepted. Rewritten 2026-09-29 under **DEC-38 (option A)**, which the operator
answered first-party through opum-doc as R-2026-09-29-22. This document
replaces an earlier version of itself that recorded DEC-19 (option B), DEC-25
and DEC-26 (option A) and was executed as WCLI-11. DEC-19 B is superseded and
DEC-25 is vacuous; DEC-26's no-hint rule and DEC-30's sentence survive
unchanged at the two sites that still raise the code. Executed as WCLI-51. The
file keeps its name because that name is this record's identifier: other
documents link to it by path, and renaming it would break those links to
change what is at the top of the file anyway.

This is the state document inside the sealed envelope, not the envelope. The
envelope's own version is 1 and was never part of this decision
([ADR 0001](0001-vault-storage-and-key-custody.md)); the two numbers are
independent, and both are 1.

## Context

Spec §9.4 requires each audit event to carry the observed OS identity and the
optional self-asserted actor and task labels. An earlier version of this
document added those three fields and, because the reader below compares each
record's key set against an exact expected list, bumped the document's version
to 2 so that an older build would refuse the document rather than read part of
it. That was DEC-19 B, and its accepted cost was that every vault written
before the change became unreadable, with no migration and no read-out path.

**DEC-38 measured that cost against a fact that removed it.** Before the first
release the on-disk format is not a compatibility contract: no repository and
no person holds a vault this build did not write, and the only vault in
existence held one valueless test value. The bump answered a compatibility
question with nobody on the other side of it.

The measurement that decides the shape was already in the suite. The version
was never what refused those documents: the same reader that compares key sets
exactly refused a genuine format-1 document for its *record* — an eight-key
audit record against the eleven this build writes — even when only its version
number was changed. The version added a name to the refusal, not a protection.

## Decision

**`vaultStateFormatVersion` is 1, and the version is an ordinary field rather
than a format gate.**

- `parseVaultState` validates `formatVersion` the way it validates every other
  field. A value this build did not write is `vault_state_malformed`, and a
  missing or non-numeric value reaches the same answer. There is no
  "document from another build" state distinct from a malformed one, because
  with a single format there is no other build for it to be about.
- **What refuses a document whose shape is not this build's is the reader's
  exact key-set comparison**, which was always doing the work. A record
  carrying a key set this build does not write is a damaged record rather than
  a displayable one, and that rule is unchanged.
- **`vault_format_unsupported` survives at two sites, and neither is this
  format.** The sealed envelope's header
  ([ADR 0001](0001-vault-storage-and-key-custody.md)), where the version is
  bound as authenticated data and is genuinely the outer container's format;
  and a stored profile approval's `snapshotVersion`, which guards an authority
  question — running this build's normalization rules over an approval written
  under different ones is how it comes to mean something the developer never
  approved. DEC-26's no-hint rule and DEC-30's sentence stand unchanged at
  both:

  > This vault was written by a different version of Ward, and this build
  > cannot read it. Ward did not change it.

- **No recovery surface, and none needed.** The earlier version of this
  document recorded DEC-25's no-migration rule as a decision. It is vacuous
  now rather than repealed: there is no second format to migrate from. Ward
  still has no `ward migrate`, no read-out into a fresh vault, and no domain
  function that rewrites a document from another build.
- **`ward doctor` answers two ways, and the difference is the record.** A
  document whose *own* version this build did not write fails the `schema`
  check as `state_malformed`, the answer a damaged document gets. A stored
  profile approval whose `snapshotVersion` this build does not implement fails
  it as `state_unsupported`, because the document parsed and one record inside
  it did not. The second is not a leftover of the version gate: it is the
  retained authority check above reaching the report, and removing that
  handling would make both reports throw out of their read instead of
  answering. A first draft of this rewrite deleted it on the assumption that
  one format made it unreachable, which was false — the code still reaches the
  reporting path from the approval site, and the removal was measured and
  reverted (WCLI-51 review, F1).

## Consequences

- **A vault written by the pre-DEC-38 build stops opening, and is re-created
  rather than raised.** That is what made DEC-19 B's accepted cost go away:
  the only such vault held no credentials and belonged to the developer who
  decided the change. This is not a general statement that vaults are
  disposable — it is true of this repository before its first release, and it
  stops being true at it.
- **The compatibility question is deferred to the first release, not denied.**
  The reader still compares key sets exactly, so the next audit field added
  before release raises the same wall again, and it will be answered there
  with a real shipped format to reason about rather than a hypothetical one.
  The arm DEC-38 left aside — relaxing the reader to tolerate unknown keys —
  is the one to revisit then, and it was left aside deliberately: on authority
  records such as bindings and approvals, an unknown field would be dropped
  silently from something that decides access.
- **`ward status` names the same number as the document it describes.** By
  [ADR 0007](0007-status-and-doctor-reporting.md) status answers from the
  sealed header alone, so it prints the envelope's version. While the state
  document was 2 the report named one of two numbers, and WCLI-48 tracked that
  ambiguity alongside what status should say about a state it cannot read.
  With both numbers at 1 and one format, both halves dissolve, and WCLI-48 is
  closed as moot rather than answered.
- **`ward backup` and `ward restore` are symmetric again.** `runBackup` opens
  and authenticates the envelope before it seals anything, so a vault this
  build cannot read is refused before a backup file exists, rather than
  producing a file that restore then refuses. WCLI-49 tracked that asymmetry
  and is closed as moot. One gap is unchanged and is recorded rather than
  tidied away: a state document that decrypts but whose shape this build does
  not write still backs up, because `runBackup` seals the plaintext without
  parsing it. That is now a defect in the backup path rather than a format
  case, and no task covers it.
- **A denied vault looks different in the two reports, by design.** `ward
  doctor` fails its `schema` check; `ward status` exits 0. The reason that
  suggests itself is wrong, and an earlier version of this document gave it:
  status *does* read the state document — that read is what produces the
  `binding` row. It exits 0 because `bindingStatus` maps a state that is not
  present to `unknown`
  ([ADR 0007](0007-status-and-doctor-reporting.md)), which is the report
  saying it could not judge rather than that it did not look. One format does
  not change that, and it is also why the remedy for a stored approval this
  build cannot read is a report and not a thrown envelope: both reports answer
  whatever the read returned.
