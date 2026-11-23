---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Ward ships as a compiled signed program with a verifiable protected release path
tags:
  - release
  - distribution
  - security
summary: "DEC-301: Ward ships compiled, never as npm under node; Developer ID signing is the operator's; attestations and a protected release path come next, then a Homebrew tap."
generated:
  by: lore/0.15.1
  at: 2026-11-23T04:46:07.373Z
---

# Ward ships as a compiled signed program with a verifiable protected release path

## Status

Accepted. Operator decision DEC-301, recorded in opum-doc on 2026-11-23 from the operator's
first-party "yes save the docs", after opum-doc's recommendation. The full reasoning is opum-doc's
`docs/reference/distributing-opum-compiled-cli-tools.md`; this ADR records what binds Ward.

## Context

macOS Keychain grants an item to a program, identified by its code signature. If Ward ran as an
npm package, the program asking Keychain for the vault key would be `node`, and any script `node`
runs could read the key without a prompt. [ADR 0001](0001-vault-storage-and-key-custody.md)
records the measurements behind shipping one compiled file instead.

Ward has shipped through GitHub releases since 0.1.0 (2026-10-26) and 0.1.1 (2026-11-02). Today the
binary is ad-hoc signed, so its designated requirement is a bare cdhash: every upgrade is a new
program to Keychain and needs a manual "Always Allow". The release workflow also lets any token
with write access push a `main` commit and a matching tag (WCLI-103), and a download carries only a
checksum published beside it (WCLI-109).

## Decision

**Ward ships as one compiled program (`ward-darwin-arm64`), never as JavaScript under `node`.**
`"private": true` in `package.json` reflects this design and stays. The program's identity is
tightened, never loosened: the inherited `BUN_BE_BUN` and `BUN_OPTIONS` variables that can turn
the shipped file into a general runtime (WCLI-19) are a defect to close, not a channel to rely on.

The distribution practice, in priority order:

1. **Developer ID signing and notarization.** Upgrades then keep Keychain access silently and
   Gatekeeper stops warning. It needs an Apple Developer Program membership, which is the
   operator's decision and is **open**. The signing key never lives in a session. Until it is
   decided, nothing here assumes it.
2. **A verifiable, protected release path.** GitHub artifact attestations so
   `gh attestation verify` proves a download came from this repository's CI at a given commit
   (WCLI-109, W-15), and only reviewed `main` can be tagged and released (WCLI-103, W-8). That is the aim, delivered
   in full only when the operator applies the rulesets in the
   [protect-the-release-path runbook](../runbooks/protect-the-release-path.md); its option A leaves
   an admin credential able to tag an unreviewed commit. Neither
   waits on the Apple account.
3. **A Homebrew tap**, `opum-ai/homebrew-tap`, pointing at the signed release and pinning its
   checksum; saws installs fleet hosts through it. This follows item 1 and is not started.
4. **Later channels:** an npm package that only installs the signed program (the esbuild pattern,
   never running Ward under `node`); Linux tarballs with checksums and attestations, gated on
   Ward's TPM work (WCLI-21); apt or rpm only on demand.

## Consequences

- A change that would run Ward under `node`, or publish it as an npm package that executes
  JavaScript, contradicts this ADR.
- The tap and the saws pin must not be added before a signed release exists. The release
  artifact they pin has to be the Developer ID one.
- Settings that protect the release path (rulesets, tag protection, environments) are
  security-posture changes: this repository prepares them and the operator applies them.
- Until item 1 lands, each upgrade still needs one Keychain re-approval, as the release notes say.
- Attestation proves provenance, not trustworthiness of the source; it does not replace signing.
