---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Backup container and restore authority
tags:
  - security
  - recovery
  - crypto
status: stable
summary: An encrypted backup opens without the OS keychain, and a restore lands only in an empty destination, under a fresh key and vault id, with every binding cleared.
generated:
  by: lore/0.11.0
  at: 2026-09-28T23:35:00.000Z
---

# Backup container and restore authority

## Status

Accepted. It implements spec §10 for WCLI-13 and records the points §10 leaves
to the implementation: the container's encoding, how the parameters a file
names are judged, and what a restore does to the authority the vault carried.
The threat model it sits inside is [P0 threat model and
non-guarantees](0002-p0-threat-model-and-non-guarantees.md); the state it
carries is the one [Project binding identity](0005-project-binding-identity.md)
defines.

## Context

Spec §10 asks for an encrypted backup that is independently decryptable
without the old OS keychain, and says plainly that copying `ward.db` does not
provide that property: the database holds the sealed snapshot, and the key
that opens it lives in the platform credential store, so a database copy
without its key is unopenable and a copy with its key is a copy of the whole
secret. A backup therefore has to carry the vault's plaintext under a
*different* key — one derived from something the developer can write down and
keep elsewhere: a passphrase.

Two questions §10 leaves open. What exactly a backup file is, as bytes that a
future version must still read and that an attacker can hand back with any
field changed. And what a restore is allowed to revive: it lands in a store
that is not the one the backup came from, on a machine whose credential store
never held the original key.

## Decision

**A backup is one JSON document holding base64 fields: the format version,
the origin vault id and revision, the KDF parameters with a fresh salt, and
one AES-256-GCM nonce, ciphertext and tag. The parameters, the version, the
origin and the salt are authenticated as header data. A restore creates a
fresh vault key and vault id for an empty destination and clears every local
binding.**

- **The parameter set is named, matched exactly, and judged before anything
  is derived.** v1 is scrypt with `N=131072`, `r=8`, `p=1`, a fresh 32-byte
  salt and a 32-byte output key, then AES-256-GCM with a fresh 12-byte nonce
  — spec §10's proposed parameters, recorded as a format decision rather
  than as a claim of a universal standard. A file naming any other version
  or parameter set is refused by name (`backup_unsupported`) *before* a
  derivation is attempted, because those fields are attacker-controlled
  input and the set they name decides how much memory the derivation would
  allocate. Nothing is clamped and nothing is weakened automatically to make
  a slow machine or a foreign file pass.
- **The header is authenticated, so a file's meaning cannot be edited.**
  Domain, format version, origin vault id, revision and every KDF parameter
  including the salt are bound as associated data. A container relabelled
  with another vault, replayed under another revision or given another
  parameter set fails to open rather than being interpreted. What is not
  claimed: rollback resistance, or that an old *backup* copied elsewhere is
  in any way invalidated by a later one.
- **A backup file is created once, owner-only, and never replaced.** Mode
  0600 with `O_CREAT|O_EXCL|O_NOFOLLOW`, so an existing path, a link and a
  directory are all refused rather than written through; only ciphertext
  reaches the file and no plaintext copy is ever made. A failed write removes
  what it created, best effort. Reads are bounded by the container limit and
  refuse anything that is not a regular file.
- **The passphrase is read from a terminal, and only from a terminal.** Echo
  is suppressed by reading with the terminal in raw mode — no mask is
  printed, because a mask discloses the passphrase's length. There is no
  argument, environment variable, pipe or configuration path to it, on the
  command line or anywhere in the code; a caller with no terminal is refused
  before the credential store is touched. That is a guardrail against a
  non-interactive caller and, as with registration, explicitly not proof of
  a person (spec §4.3). Passphrase *entropy* is what matters; length alone is
  not proof of strength, and the command's own guidance says so.
- **A restore goes only into an empty destination.** A vault that already
  exists is refused (`vault_exists`) before anything is read, asked for or
  created. The destination then receives a fresh vault key — stored before
  the vault is created, so an interrupted restore leaves at most a key
  nothing points at, never a vault whose key does not exist — and a fresh
  vault id, which also means the original machine's credential store is not
  part of opening the restore.
- **What a restore revives is identity, not authority.** Project records are
  preserved, so a restored vault still describes the same projects. Every
  local binding is cleared, so no checkout inherits access it was granted
  before; each one registers again through the interactive prompt. WCLI-9's
  profile approvals and WCLI-12's sharing grants do not exist in the state
  document yet; when they do, a restore must leave them inactive too, and the
  restore path rebuilds the document as a fixed projection for exactly that
  reason — the obligation is visible at the code that owes it rather than
  implied by a schema.

## Consequences

- **Recovery needs the file and the passphrase, and nothing else.** The
  native keystore item, the machine, and the old vault directory are all
  absent from that pair. A lost keychain item is therefore recoverable from a
  backup; a lost backup passphrase is not recoverable at all, which is the
  property the format exists for and also its sharpest edge.
- **Nothing here erases anything or revokes anything.** Ward makes no claim
  that an old backup becomes unreadable, and a restore does not revoke a
  credential at its provider or invalidate another copy of the vault. Those
  are stated rather than implied, per spec §10's own instruction not to
  promise them.
- **The parameters are a cost as well as a bound.** 128 MiB of scrypt table
  and roughly a tenth of a second per derivation on the measured machine
  (bun 1.3.14, macOS APFS), paid twice per backup (confirmation is a second
  read, not a second derivation) and once per restore. A future version
  raising them must introduce a version that can still read v1, because the
  format's whole purpose is to open on a machine that has nothing else.
- **A restore is the one place besides `ward setup` that mints a key**, which
  is why the source-level invariant that guards key creation now names two
  callers instead of one, and why the behavioural half — a non-empty
  destination leaves its key and vault untouched — is asserted separately.
