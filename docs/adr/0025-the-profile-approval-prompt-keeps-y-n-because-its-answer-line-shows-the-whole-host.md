---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: The profile approval prompt keeps y/N because its answer line shows the whole host
tags:
  - profile
  - consent
summary: "DEC-255 (3): the approval prompt keeps y/N, not typing the host, because its answer line shows the whole host."
generated:
  by: lore/0.14.1
  at: 2026-11-02T19:06:41.997Z
---

# The profile approval prompt keeps y/N because its answer line shows the whole host

## Status

Accepted, 2026-11-02, under **DEC-255 (3)**, recorded by opum-doc and carried
here from its outcome. The record binds, not this document's copy of it; the
decision's text is DEC-255 (3) in opum-doc. Implemented by WCLI-100.

## Context

The profile approval prompt ([ADR 0003](0003-profile-approval-authority.md))
asks the developer to approve one exact operation. The review behind WCLI-100
(W-5) found its layout spoofable by whitespace, and asked whether the developer
should have to type the destination host instead of answering `y`. The first
fix capped the host at 120 characters and kept the left end, which could hide
a registrable suffix; the Opus review of #233 caught it.

## Decision

1. **Keep `y/N`.** The developer is not asked to type the host.
2. **Because the answer line carries what is being approved**: the method, the
   whole host and the header count, on the line the developer answers
   (`src/adapters/terminal-consent.ts`). The host is ASCII, has no spaces and is
   bounded by the profile's URL limit, so it is shown whole, never capped. A
   test pins a 150-character host that ends in the attacker's domain.
3. **The display is escaped, not trusted.** Runs of spaces, no-break and
   other blank-rendering code points are escaped, at most 8 headers show with
   a count line, names are capped at 60 characters and values at 120.

## Consequences

- **Fewer keystrokes, same information.** The developer sees the whole host
  before answering; typing it would add friction without showing more.
- **Residuals, not fixed.** A backslash is not escaped, so the escaping is not
  injective, which cannot forge a host because the answer line cannot carry a
  backslash. Headers are listed by name, so the declaration picks which 8 show;
  the line says the full set is in the manifest. Follow-up: WCLI-128.
- **Revisit** if a way appears to make the host on that line differ from the one
  the request uses; that would be a new decision, not a reading of this one.
