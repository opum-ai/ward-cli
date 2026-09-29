---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: The init multiselect's prompt library is a pinned dependency
tags:
  - dependencies
  - cli
summary: "@clack/prompts is Ward's first UI dependency, added at an exact version after the operator approved it as its own question (DEC-52)."
generated:
  by: lore/0.11.0
  at: 2026-09-29T17:05:00.000Z
---

# The init multiselect's prompt library is a pinned dependency

## Status

Accepted. The operator approved the dependency first-party through opum-doc on
2026-09-29 as its own question, relayed by opum-agent (ODOC-OP-2026-09-29-19)
alongside DEC-52, and recorded under WCLI-14. The operator's answer was the
recommended option:

> Yes, add @clack/prompts (Recommended)

The option the operator saw said the package is pinned and reviewed like any
other. It was asked as its own question, separately from the interaction
shape, because it adds a third-party package to a secrets CLI.

## Context

Spec §13 asks Ward to "minimize dependencies and pin versions", and Ward's
only runtime dependency so far is `@napi-rs/keyring`, a native binding that
was reviewed and pinned for the same reason. DEC-48 pointed at the peers'
pattern, and lore-cli's own comment defines that shared pattern as including
"the same library (@clack/prompts)" - so following the instruction implied a
new runtime dependency, which is why it went back to the operator as its own
question rather than riding in on the multiselect's answer.

The review, at the version adopted: `@clack/prompts@1.8.0`, MIT, pure
JavaScript (no native code), with four transitive dependencies - `@clack/core`
pinned to 1.5.0 by clack itself, and `sisteransi`, `fast-wrap-ansi`,
`fast-string-width` on caret ranges whose resolved versions are pinned by
`bun.lock`. lore-cli pins `1.8.0` exactly; quest-cli carries `^1.8.0`.

## Decision

1. **`@clack/prompts` is a Ward runtime dependency, pinned to an exact
   version** (`1.8.0`, no range) in `package.json`, with the transitive set
   pinned by the committed lockfile - the same treatment `@napi-rs/keyring`
   gets.
2. **It is used at exactly one call site**: the `ward init` instruction-file
   multiselect, behind the `src/adapters/init-prompt.ts` adapter. The
   application layer depends on the `InstructionFileChooser` interface, not
   on the library, so replacing the library later touches one adapter.
3. **Its output stream and gate are Ward's to set**, not the library's
   defaults: DEC-52 fixes stderr, both-streams TTY gating, and cancel
   handling, all wired in that adapter.

## Consequences

- **Ward's dependency surface grows by one pure-JS package** (six packages
  with its transitive set). That is a real cost, accepted deliberately: the
  alternative was hand-rolling a raw-mode checkbox in a secrets CLI, which is
  more security-relevant code than a prompt library, not less.
- **The pin moves only deliberately.** A version bump is a dependency change
  like any other and follows the same rule as the keyring binding: resolve,
  review, pin. No range is accepted for the direct dependency even though a
  peer uses one.
- **Removal stays cheap.** If the dependency is ever dropped, the interface,
  the tests that exercise the gate and cancel mapping, and the command's
  behavior are all independent of the library; only the adapter's one line
  changes.
