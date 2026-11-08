---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Committed platform target
tags:
  - platform
  - security
status: stable
summary: Ward commits to macOS, Linux and Windows; the first developer preview is macOS-only, and each platform ships after its own T26 run.
generated:
  by: lore/0.11.0
  at: 2026-09-28T18:09:51.345Z
---

# Committed platform target

## Status

Accepted. An operator ruling made to the orchestrator (opum-agent) on 2026-09-28 and tracked there
as OPAG-675. It is recorded in opum-doc as ODOC-316,
`docs/adr/wards-committed-platform-target-macos-linux-and-windows.md` (opum-doc main 900319d),
which is a sibling of ODOC-312 rather than an amendment of it.

## Context

Spec §2 (the Portability row) said to qualify macOS first and Linux only with a verified
persistent, protected native backend, and it never mentioned Windows. lore and quest commit to
macOS, Linux and Windows. The key-custody design in
[vault storage and key custody](0001-vault-storage-and-key-custody.md) is macOS-specific, and
the adapter from WCLI-5 fails closed on any other platform.

## Decision

**Ward's committed platform target is macOS, Linux and Windows.**

- **The first developer preview is macOS-only, and this ruling does not delay it.**
- **Linux ships only after its own T26 qualification run.** That run uses a verified persistent,
  protected native credential backend, such as Secret Service, and never a plaintext file or a
  session-only store. Tracked as WCLI-21.
- **Windows ships only after its own T26 qualification run**, against Windows Credential Manager.
  The spec never mentioned Windows; this ruling is what adds it. Tracked as WCLI-22.
- **Untested platforms are still not advertised.** A T26 run means a real native key-provider
  integration and a packaged-binary smoke test on that platform. Mocked unit tests do not count.

## Consequences

- Until WCLI-21 or WCLI-22 lands, the Keychain adapter reports `vault_key_store_unsupported`
  off macOS. That is the intended state of the preview, not a defect.
- CI today is GitHub-hosted Linux ARM64 (ubuntu-24.04-arm) only. It runs Ward's tests on Linux but is not a T26 run
  for any platform. Windows needs a runner or machine that does not exist yet.
- WCLI-15's qualification matrix names the platform each T26 result came from.
