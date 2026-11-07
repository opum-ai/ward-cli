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

Accepted in part, 2026-11-07, under **DEC-262 (a3)**, ruled by opum-doc as design authority
(not the operator's words) and carried here from its relay. The record binds, not this
document's copy of it. Part (iii), the sign profile, is **held**: this ADR records it as ruled
and its implementation lands in a later change under WCLI-149, after opum-doc rules on the
snapshot-version question below.

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
unchanged, so a restore cannot name what a backup left out; the backup does.

**(iii) Authority is an approved "sign" profile** (ruled, held): a key alias plus allowed domain
prefixes, with bytes refused unless they begin with one. Ward signs exactly the bytes given; the
caller prefixes. An empty prefix list allows nothing.

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
- Open, awaiting opum-doc: whether the sign profile bumps `profileSnapshotVersion` for everything
  (every existing HTTPS approval would go inert and need re-approval) or is versioned per kind so
  HTTPS approvals stay valid. Until it is ruled, `ward sign` is not implemented.
- Tests use synthetic keys and a temporary store only; the RFC 8032 test vector 1 pins the
  signing and public-key derivation.
