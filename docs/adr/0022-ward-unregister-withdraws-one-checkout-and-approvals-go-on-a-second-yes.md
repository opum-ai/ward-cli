---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: ward unregister withdraws one checkout, and approvals go on a second yes
tags:
  - bindings
  - security
summary: ward unregister removes this checkout's binding on one confirmation and its approvals on a second; it is interactive and never touches another root (DEC-217 Q4).
generated:
  by: lore/0.14.1
  at: 2026-10-20T23:27:49.652Z
---

# ward unregister withdraws one checkout, and approvals go on a second yes

## Status

Accepted. Decided by opum-doc as **DEC-217** (ODOC-488), question Q4, read from
the decision record on opum-doc `dev`. Implemented under WCLI-73. It supersedes
the "no unregister" gap [ADR 0005](0005-project-binding-identity.md) recorded.

## Context

A binding could not be removed by any command. A discarded clone left its
binding, and every approval tied to it, in the vault, so a developer had no way
to withdraw that checkout's access. That contradicts the
product's own revocation principle, and approvals are now time-bound
([ADR 0021](0021-a-profile-approval-expires-24-hours-by-default.md)) but a
binding is not. A moved checkout's binding is a different case: it is matched by
path, device and inode, so it is not reachable from the new location and
`unregister` cannot free it.

## Decision

1. **`ward unregister` is interactive and trusted-terminal only.** No terminal,
   or a terminal that stops answering, is refused with
   `unregister_requires_terminal`; "unavailable" is never consent. It is a
   developer's act and is marked `admin` in the manifest.
2. **It removes this checkout's binding only**, matched by path, device and
   inode as every binding is, and never another root's binding, whatever project
   that binding names. Its approvals are matched by the same identity and the
   binding's project, so another project's approval at this identity is kept. A
   checkout with no binding is refused with `project_not_registered` and the vault is not written.
3. **Removing the binding is one confirmation; removing that binding's profile
   approvals is a second.** The second is asked only when the checkout has
   approvals. Declining it removes the binding and keeps the approvals.
4. **The set is re-checked inside the write transaction**: if it differs from
   the one shown, `binding_changed` (DEC-255 a9) is raised and nothing is removed.
5. **It needs no manifest.** The binding is the authority being withdrawn, and a
   checkout whose manifest was deleted is one a developer may want to unregister.

## Consequences

Kept approvals are bound to a clone's identity (ADR 0026): re-registering the
same clone revives this version's, never an earlier one's. The report says so, and a developer who wants a clean start answers yes to both questions.
This follows DEC-217 as written; whether declining the second question should
instead leave approvals inert on re-registration is a point put to review.
Unregistering does not touch secrets, grants or the audit history, and revokes
nothing at a credential's provider.
