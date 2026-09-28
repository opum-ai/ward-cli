---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Vault storage and key custody
tags:
  - security
  - storage
  - keychain
status: draft
summary: Vault format version 1 and P0 key custody in the macOS Keychain, and what neither protects.
generated:
  by: lore/0.11.0
  at: 2026-09-28T16:53:26.276Z
---

# Vault storage and key custody

## Status

Accepted by the orchestrator (opum-agent) on 2026-09-28. It binds once opum-doc records the decision, as record ODOC-PENDING. That id must be filled in before this ADR lands.

## Context

Ward keeps every secret, binding, grant, approval and audit entry for one OS user in a single
vault under `~/.ward/` (spec §2, §6). Two questions had to be settled before storage and setup
code is written: how the vault is sealed, and how its key is held.

These measurements were taken on 2026-09-28 with bun 1.3.14 on macOS arm64:

- The envelope in `src/domain/envelope.ts` (WCLI-4) passes McGrew-Viega GCM test cases 13-16 in
  both directions under Bun (BoringSSL) and under Node 24.20 (OpenSSL 3.5.7). A golden envelope
  record, recorded identically under both runtimes, is pinned in `test/envelope.test.ts`.
- `@napi-rs/keyring` 2.1.0 embeds in, and loads from, a `bun build --compile` executable that has
  been moved elsewhere. Only the binding was constructed: no keychain item was read or written.
- The compiled executable is ad-hoc signed: `Identifier=a.out`, no team identifier, and its
  designated requirement is its bare cdhash. Two builds of identical source produced different
  cdhashes.
- The inherited `BUN_BE_BUN=1` turns the shipped executable into the full bun CLI, which runs
  arbitrary code under that same identity. `BUN_OPTIONS=--preload` injects code into an ordinary
  Ward run before any Ward code executes. No bun build flag disables either (WCLI-19).

## Decision

**Vault format version 1 is the envelope WCLI-4 implements.**

- A single logical snapshot is sealed with AES-256-GCM under a random 32-byte vault key.
- Every seal draws a fresh random 12-byte nonce and produces a 16-byte tag.
- The authenticated data is the UTF-8 encoding of the fixed-order JSON array
  `["opum.ward.vault", 1, vaultId, revision]`. The vault ID must be a canonical lowercase UUIDv4
  and the revision a safe integer of at least 1, so the authenticated data has exactly one
  encoding.
- Opening a record copies and validates every input, then authenticates the record, before any
  plaintext is returned. Failures are the five fixed `vault_*` catalogue codes.
- The logical vault is limited to 10 MiB.
- Any change to the authenticated-data encoding, its field order or its domain string requires a
  new format version. The golden test pins version 1.
- The sealed record is stored as a SQLite BLOB, and SQLite receives ciphertext only (spec §6.3).
  The store itself is WCLI-6.

**P0 key custody is a generic-password item in the macOS Keychain.**

- The item's service is `opum.ward` and its account is derived from the vault ID. It is written
  and read through `@napi-rs/keyring`, never through a command whose argv carries the key.
- The key is cached in memory for one invocation at most (spec §6.4).
- A noninteractive command must fail within a bounded time when the key is missing, locked or
  unavailable. It must never hang on a hidden approval prompt.

## Consequences

- **Rollback is not detected.** An older record that was valid under the same key still opens.
  This is a stated limit of the format, not a gap left for later.
- **The Keychain ACL is per-build and is not a security boundary.** The executable is ad-hoc
  signed, and its identity is the cdhash of one exact build. An ACL that trusts "ward" therefore
  trusts only that build. Expect an access prompt, or an ACL to re-grant, after every upgrade.
  Code running as the same user can reach the key anyway, for example through `BUN_BE_BUN`.
  This is consistent with [the threat model](0002-p0-threat-model-and-non-guarantees.md).
- **Developer ID signing is deferred past P0.** With it, the designated requirement would be team
  identifier plus bundle identifier. That is an operator account and release decision, held on
  the operator's list as opum-agent OPAG-672 rather than decided here. It is the precondition for any claim that the
  Keychain ACL protects anything, and until it exists no Ward document may make that claim.
- **WCLI-19 is accepted as a stated P0 limitation.** `BUN_OPTIONS` and `BUN_BE_BUN` reaching the
  packaged executable will be revisited together with signing.
- **Open and unmeasured: which Keychain API `@napi-rs/keyring` uses underneath.** It is either the
  legacy file-based keychain or the data-protection keychain, and the two have different ACL
  semantics. It is not a precondition for this decision. Measuring it means writing a throwaway
  item into the developer's real login keychain. It is an acceptance criterion on WCLI-5, and the
  developer authorises it when that task starts.
- One key opens the whole vault. Compromise of that key exposes every project's secrets
  (spec §2).
