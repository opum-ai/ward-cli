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

Accepted, 2026-11-07, under **DEC-262 (a3), (a4), (a5), (a6) and (a7)**, ruled by opum-doc as design
authority (not the operator's words) and carried here from its relay. The record binds, not this
document's copy. Storage, backup exclusion and the `ward key` commands landed first; the sign profile
and `ward sign` follow in a second change under WCLI-149, and this record covers both.

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

**A sign key is never a credential.** `run` refuses an alias naming one (`sign_key_refused`) before
admission. `check` reports such a profile with the reason `sign-key` (exit 6, no error code), and
`profile list` shows its secret state as `sign-key` (exit 0), rather than failing every other
profile's report. `secret set` does not replace a sign
key, `secret grant` does not share it, and `secret delete` removes it.

**(ii) Backup excludes sign keys.** `ward backup` seals the state without them and reports
`excludedSignKeys`, so the developer regenerates and re-enrols each. The container format is
unchanged, so a restore cannot name what a backup left out; the backup does, in its text output and in `--json`, and `ward restore` states in prose that signing keys are never carried and must be regenerated and re-enrolled (DEC-262 a6, which replaces (a3)'s "restore names each excluded alias"). Restore also drops any sign-kind record by kind, so "restore reproduces none" holds by construction.

**(iii) Authority is an approved "sign" profile:** `{"adapter": "sign", "key": "<alias>",
"prefixes": ["<base64>", ...]}` in the manifest, which needs no manifest-version change (profiles are
normalized where used). One to eight prefixes, each 1 to 64 bytes, as the canonical base64 of its exact
bytes (a prefix can hold a NUL), sorted and de-duplicated. Ward signs exactly the bytes given, and only
if they begin with one of them; the caller does the prefixing. The approval is of that snapshot, from a
trusted terminal, under ADR 0003's rules, and `ward check` and `profile list` report it.

**Two version lines (DEC-262 a4).** HTTP approvals keep their `profileSnapshotVersion` and stay valid;
the sign snapshot has its own `signSnapshotVersion`, 1, and the reader tells them apart by the stored
`adapter`. A later change to one kind's normalizer makes only that kind's approvals stale-inert (ADR
0018, DEC-246 a2). Bumping both would force every developer to re-approve every HTTP profile for no
change to HTTP. (a4) says HTTP is at version 2; the code has 3, bumped before release, and (a7) reads
(a4) as "HTTP stays at its current version, 3". HTTP is untouched, and the sign snapshot starts at 1.

**(iv) Commands:** `ward key generate <alias>`, `ward key public <alias>`, `ward sign <profile>`.
`ward sign` reads the bytes on standard input (at most 64 KiB) and writes the raw 64-byte signature
to standard output; `--base64` writes it as text, and `--json` carries it as base64 in the envelope.
A sign is audited with the existing audit record, admission then completion, with `profile` the sign
profile and `secretId` the key's id, so the audit schema is unchanged. Bytes outside every prefix are
refused before admission and so are not audited, as a run refused before it is sent is not. If the
completion event cannot be written after a signature exists, the signature is still returned and the
exit is nonzero (`auditRecorded: false` under `--json`), as `ward run` reports it, and the failure is
named on standard error (DEC-262 a7), so an unaudited signature cannot read as success. Sign keys are
not in `ward status` or `ward doctor` (a7); `secret list`, `inspect` and `key public` show them. No result or error
carries key material.

## Consequences

- The seed is stored base64 inside the encrypted state document like any secret, and is unsealed
  only inside Ward's own process to sign, then zeroed.
- Because `kind` makes an older build refuse the vault, a downgrade cannot back up or inject the
  seed. A vault the developer never put a sign key in stays usable by every build.
- A sign approval alone does not make an older build refuse a vault: a build whose snapshot
  version differs holds an approval of another version inert (DEC-246 a2). It is the sign key's
  `kind` that refuses. A sign approval left after its key is deleted is held inert by an older
  build, which is fail-safe.
- An HTTPS profile and a sign profile cannot stand in for each other: `ward run` refuses a sign
  approval and `ward sign` refuses an HTTP one, and a sign key is never an HTTPS credential.
- The sign snapshot version line must never take the value 3, the current HTTP version. A build
  from before part 2 compares every stored approval against 3 only: a sign approval at any other
  value is held inert (stale), but one at 3 would pass that check, be read as an HTTP snapshot,
  and make the build refuse the whole vault as `vault_state_malformed`. A later HTTP bump does not
  lift the rule for builds already shipped.
- Tests use synthetic keys and a temporary store only; the RFC 8032 test vector 1 pins the
  signing and public-key derivation.
