---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: "An Ed25519 sign operation: sign keys are a kind of secret record, never exported"
tags:
  - signing
  - vault-format
  - security
summary: Sign keys are secret records of kind ed25519, never exported, excluded from backup, refused as a credential (DEC-262 a3).
generated:
  by: lore/0.14.1
  at: 2026-11-07T21:39:09.781Z
---

# An Ed25519 sign operation: sign keys are a kind of secret record, never exported

## Status

Accepted, 2026-11-07, under **DEC-262 (a3), (a4), (a5) and (a6)**, ruled by opum-doc as design authority
(not the operator's words) and carried here from its relay. The record binds, not this document's
copy. This change implements (i) storage, (ii) backup exclusion and the `ward key` commands; the sign
profile and `ward sign` follow in a later change under WCLI-149.

## Context

DEC-262 item (2) asks for an Ed25519 sign operation so an unattended daemon can sign with a key
that Ward holds and never returns: `sign(named key, caller-prefixed bytes) -> signature`, plus key
generation inside the store and public-key read-back. Ward is public since 0.1.1, so its vault
formats are a contract (DEC-255 a6), and
[ADR 0023](0023-keep-the-vault-state-reader-s-exact-key-set-comparison-at-the-first-release.md)
keeps the reader's exact key-set comparison, so a field added to a record makes an older build
refuse that vault. Two existing paths release a secret's bytes outside Ward: `ward run` through an
approved HTTPS profile, and the backup container.

## Decision

**(i) A sign key is a `SecretRecord` with a `kind` field that an ordinary secret never carries.**
`kind` is `"ed25519"` and the value is the 32-byte seed. A magic prefix in the value was rejected: it
is ambiguous and fails open on downgrade. `kind` is serialized only when present, so a vault without
a sign key is byte-identical (no migration, no `formatVersion` change). The reader accepts only that
literal and a 32-byte seed. An older build refuses a vault holding one (ADR 0023): the intended
fail-closed price. Custody is the vault's own; there is no second key store.

**A sign key is never a credential.** `run` and `check` refuse an alias naming one
(`sign_key_refused`); `secret set` does not replace it, `secret grant` does not share it, and
`secret delete` removes it.

**(ii) Backup excludes sign keys.** `ward backup` seals the state without them and reports
`excludedSignKeys`, so the developer regenerates and re-enrols each. The container format is
unchanged, so a restore cannot name what a backup left out; the backup does, in its text output and in `--json`, and `ward restore` states in prose that signing keys are never carried and must be regenerated and re-enrolled (DEC-262 a6, which replaces (a3)'s "restore names each excluded alias"). Restore also drops any sign-kind record by kind, so "restore reproduces none" holds by construction.

**(iii) Authority is an approved "sign" profile** (ruled; implemented in the next change): a key alias plus allowed domain
prefixes (one to eight, never empty: an empty list would admit any domain, DEC-262 a5), with bytes
refused unless they begin with one. Ward signs exactly the bytes given; the caller prefixes.

**Two version lines (DEC-262 a4).** HTTP approvals keep their `profileSnapshotVersion` and stay valid;
the sign snapshot has its own first version, and the reader tells the kinds apart by the stored
`adapter`. A later change to one kind's normalizer makes only that kind's approvals stale-inert (ADR
0018, DEC-246 a2). Bumping every approval to a new version was refused: it would force every developer
to re-approve every HTTP profile for no change to HTTP, against the rule that a vault with neither a sign
key nor a sign approval stays as it was.

**(iv) Commands:** `ward key generate <alias>`, `ward key public <alias>`, `ward sign <profile>`.
No result or error carries key material.

## Consequences

- The seed is stored base64 inside the encrypted state document like any secret, and is unsealed
  only inside Ward's own process to sign, then zeroed.
- Because `kind` makes an older build refuse the vault, a downgrade cannot back up or inject the
  seed. A vault the developer never put a sign key in stays usable by every build.
- A sign approval alone does not make an older build refuse a vault: a build whose snapshot
  version differs holds an approval of another version inert (DEC-246 a2). It is the sign key's
  `kind` that refuses. A sign approval left after its key is deleted is held inert by an older
  build, which is fail-safe.
- Tests use synthetic keys and a temporary store only; the RFC 8032 test vector 1 pins the
  signing and public-key derivation.
