---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: A secret in one named header is an auth scheme beside bearer
tags:
  - auth
  - profile
summary: "DEC-248: auth.type header carries a secret in one named header, with a refused-name set shared with profile headers, a folded collision check, a literal approval comparison, and snapshot version 3."
generated:
  by: lore/0.14.1
  at: 2026-10-29T17:39:46.542Z
---

# A secret in one named header is an auth scheme beside bearer

## Status

Accepted, 2026-10-29, under **DEC-248**, recorded by opum-doc at
opum-ai/opum-doc#1490 under the design delegation and carried here from its
outcome. The record binds, not this document's copy of it; the decision's text
is DEC-248 in opum-doc. Implemented by WCLI-84.

## Context

A profile's `auth` carried only `type` and `secret`, and the type had to be
`bearer`, so a credential that must travel in a named header could not be
expressed. Spec 9.2 names the custom API-key header as a bounded extension
after Bearer, and WCLI-33 held it. An approval pins the normalized operation
([ADR 0003](0003-profile-approval-authority.md)), so the header's name is part
of what a developer approves, and a new accepted shape moves the snapshot
version ([ADR 0018](0018-profilesnapshotversion-bumps-at-the-first-release.md)).

## Decision

1. **`auth.type: "header"`** is `{type, name, secret}`. The key set is exact per
   type: bearer is `{type, secret}`. A key a type does not own is
   `profile_unsupported`; a missing or malformed `name` is `profile_invalid`.
2. **Names.** An RFC 9110 token of at most 128 characters, not refused. The
   invariant: a declared header may not make the request differ from what the
   prompt showed (method, path, authority, framing). Refused in an ordinary
   header and as `auth.name`: credentials (`authorization`), routing and
   authority (`host`), framing (`content-length`), hop-by-hop (`te`)
   and method, path or authority overrides (`x-original-url`). A name is
   case-folded, then `_` to `-`, in every refused-name, reserved-name,
   duplicate and collision check; the approval comparison stays literal
   (Decision 5). A refusal is
   `profile_invalid`, or `vault_state_malformed` for a stored snapshot, and its
   detail names Ward's canonical constant only, never profile bytes. The list
   is `refusedHeaderNames` in `src/domain/profile.ts`; the rulings are DEC-248
   and WCLI-98.
3. **Collision.** An ordinary header named as `auth.name`, in the same fold, is
   `profile_invalid`: the secret never silently wins or loses.
4. **Wire.** The credential line keeps its slot after the profile headers, with
   the stored bytes unchanged and no scheme prefix, under the same
   `isFieldValue` checks. The transport validates the name as a token.
5. **Comparison.** The name is kept as written and compared literally;
   `differingProfileFields` reports a change as `auth`, and serialization
   writes it.
6. **Redaction.** The snapshot holds the alias and the name, never the value.
   The consent prompt reads `auth: header <Name>, from the secret alias
   <alias>`. The audit record gains no field.
7. **Version.** `profileSnapshotVersion` is 3: every version-2 approval is held
   inert and re-approved. [ADR 0023](0023-keep-the-vault-state-reader-s-exact-key-set-comparison-at-the-first-release.md)'s
   exact key-set comparison stays.

## Consequences

- **Re-approval.** Nothing is migrated. The release notes carry the warning
  because the release workflow compares versions.
- **Ordinary headers tighten.** A declaration using `Cookie`, `Host` or a
  `proxy-*` header as a public header is refused, closing a standing gap.
- **The refused set is easy to widen and costly to narrow**, which is why
  `cookie` is refused now. A new refused name needs a version bump, except
  WCLI-98's, folded into 3.
- **WCLI-33 is narrowed to HTTP Basic.**
