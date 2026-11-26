---
# yaml-language-server: $schema=../../.lore/schemas/reference.schema.json
type: Reference
title: Developer ID signing and notarization path
tags:
  - release
  - security
  - signing
summary: "Ward's accepted Developer ID signing and notarization path (DEC-301 (a3), WCLI-183): design, operator steps in order, decided choices; not built yet."
---

# Developer ID signing and notarization path

**Status: accepted by opum-doc as the build design (DEC-301 (a3)); nothing is built.** This is WCLI-183,
step 1 of DEC-301 item 1, written before any signing code, workflow edit, secret or install exists.
The open choices are decided below, in the sections they were open in. It
records the accepted path, what is measured and what is not, every operator step in order, and the
choices that are not Ward's to make. Anything marked *unmeasured* is a claim to test in the
rehearsal below, not a fact.

## What is fixed in advance (opum-doc, DEC-301 (a2))

1. No session holds the Developer ID certificate's private key or the notarization credential. The
   operator creates both and stores them where the path needs them. They are credentials, so
   creating or moving them never happens on instruction.
2. Signing and notarization run in Ward's release workflow on reviewed `main`, with the
   credentials in a protected GitHub environment, unless a reason against appears below.
3. Every operator step is listed once, in order, as one batch.
4. The Homebrew tap and the saws pin wait for a signed release
   ([ADR 0029](../adr/0029-ward-ships-as-a-compiled-signed-program-with-a-verifiable-protected-release-path.md)).

## What changes for the user, and what does not

Today the binary is ad-hoc signed: its designated requirement is its bare cdhash, so every build is
a new program to Keychain and each upgrade needs a manual re-approval
([ADR 0001](../adr/0001-vault-storage-and-key-custody.md)). A Developer ID signature makes the
requirement "this identifier, signed by this Apple team", so a later build signed by the same team
with the same identifier should keep Keychain access. *Unmeasured:* that the legacy file-based
login keychain item Ward uses (measured under WCLI-5) honours the new requirement without a
prompt. The rehearsal measures it. The first Developer ID build still needs one re-approval,
because the existing item trusts the old cdhash.

The Keychain ACL is still not a security boundary while `BUN_BE_BUN` and `BUN_OPTIONS` reach the
executable (WCLI-19); signing is the precondition ADR 0001 names, not the whole fix.

## Recommended path

**Two jobs, so the signing credential never meets dependency code.** Today one macOS job installs
dependencies, builds, signs ad hoc and uploads. If that job also held a Developer ID key, every
package install script it runs would sit beside the key. So:

- `build` (no environment, no secrets): unchanged apart from producing an unsigned, ad-hoc-signed
  artifact, as now.
- `sign` (new, `environment: release`, hosted macOS runner): downloads that artifact, runs no
  package manager and no third-party code except pinned actions and Apple's own tools, signs with
  the Developer ID identity, submits for notarization, verifies, uploads the signed artifact. It is
  the only job that can read the signing secrets.
- `verify`, `attest` (WCLI-109) and `release` then follow `sign` and act on the signed bytes.

Inside `sign`, on a macOS runner:

1. Create a temporary keychain, import the `.p12` into it, allow `codesign` to use the key without
   a prompt (`security set-key-partition-list`), and delete the keychain in a final step that
   always runs.
2. `codesign --force --options runtime --timestamp --identifier <identifier> --sign "<Developer ID
   Application identity>" ward-darwin-arm64`. Hardened runtime is required for notarization.
3. *Unmeasured, the largest technical unknown:* a `bun build --compile` executable embeds a
   JavaScript engine and may need hardened-runtime entitlements (JIT and executable memory) to run
   at all once hardened. The rehearsal must run the signed binary's own smoke test; the
   **Decided (DEC-301 (a3)): no entitlements by default.** `allow-jit` and/or
   `allow-unsigned-executable-memory` may be added only if the rehearsal's smoke test fails without
   them, with the fewest that pass and both runs cited. Anything else comes to opum-doc first,
   and above all `allow-dyld-environment-variables` and `disable-library-validation`, because of
   the `BUN_` exposure (WCLI-19). A plist, if any, is passed with `--entitlements`.
4. Zip the binary, `xcrun notarytool submit --wait` with the API-key credential, require status
   `Accepted`, and keep the log. A bare command-line executable cannot be stapled, so the ticket
   lives with Apple and Gatekeeper reads it online; *unmeasured:* how a first run of a
   curl-downloaded, un-quarantined binary behaves offline. The released asset stays the bare
   `ward-darwin-arm64` so the install runbook and checksum flow do not change.
5. `codesign --verify --strict`, then check the designated requirement names the team and
   identifier (`codesign -d -r-`), then the existing cdhash agreement check, all before upload.
   `spctl --assess` is not used: it rejects a bare executable that is correctly signed.

The existing gates keep their meaning: verify re-checks the downloaded asset, attestation covers
the signed bytes, and the notes' sha256 and cdhash come from the signed file. The "expect one
keychain re-approval per upgrade" line in the notes changes only after the rehearsal shows it.

### Credentials, and why an App Store Connect API key

Notarization needs a credential. An App Store Connect API key (a `.p8` file, a key id and an issuer
id) is revocable, scoped to a team, tied to no person's password and needs no two-factor prompt, so
it suits CI better than an Apple ID with an app-specific password. Both are operator-created.

## The rehearsal (how the first real tag avoids being the first test)

A tag is frozen once the tag ruleset exists, so a failed first signing run on a real tag would burn
a version
([protect the release path](../runbooks/protect-the-release-path.md)). The `release` environment
therefore allows two deployment targets, decided as one environment (DEC-301 (a3)): tags matching
`v*` and the branch `main`. The publish job stays tag-only. A
`workflow_dispatch` run from `main` signs and notarizes, runs the smoke test and publishes
nothing; the Release job stays tag-only. `main` is the gated ref, so no unreviewed branch reaches
the secrets. The rehearsal measures: entitlements needed, notarization acceptance, the designated
requirement text, Keychain behaviour across two builds from the same identity, and the offline
first-run question.

## Operator steps, in order (one batch for opum-doc to put to the operator)

1. Open the Apple Developer account and read two facts: the membership is **active**, and it is an
   **individual** or an **organization**. Only the Account Holder can create a Developer ID
   certificate.
2. On a Mac the operator controls, create a certificate signing request in Keychain Access, then in
   the developer portal (Certificates, IDs & Profiles) create a **Developer ID Application**
   certificate from it and install the download. The private key never leaves that Mac except in
   step 3.
3. Export the certificate and its private key as a `.p12` with a strong password, kept out of
   every session's reach and out of the repository.
4. In App Store Connect (Users and Access, Integrations) create a team API key whose role is
   enough for notarization (confirm the minimum role), download the `.p8` once, and note the key id
   and issuer id.
5. Apply WCLI-103's settings, runbook steps 1 to 4 (`main` and tag rulesets, the `release`
   environment, the immutable-releases decision), and add `main` to the environment's deployment
   targets beside `v*`. The environment's required reviewer is the operator, with administrator
   bypass off (`"can_admins_bypass": false` in the environment's PUT body). Until WCLI-182 lands,
   this protection assumes no session acts as an administrator; it does not hold against one.
6. Store five values as **environment secrets** on `release`, from files and never typed into a
   session: the base64 `.p12`, its password, the `.p8`, the key id and the issuer id. For example
   `base64 < cert.p12 | gh secret set APPLE_CERT_P12_BASE64 --env release --repo opum-ai/ward-cli`
   and `gh secret set APPLE_CERT_PASSWORD --env release --repo opum-ai/ward-cli` (prompts for the
   value). Two non-secret values, the signing identity string and the team id, go in as
   environment variables.
7. Read the decided choices below; nothing is left open for this step except any the rehearsal
   raises.
8. Accept this draft's build step (opum-doc), after which a separate task edits `release.yml` with
   its own dispatch-floor read and Opus review. Then run the rehearsal from `main` and read its
   result before cutting any tag.
9. Cut the first Developer ID release. Expect one Keychain re-approval on that upgrade; after it,
   expect silence on the next, and confirm it.

No step has a session read, print, store or send a credential value.

## Choices, as decided by opum-doc (DEC-301 (a3))

- **Code-signing identifier: `ai.opum.ward`, and it never changes.** The designated requirement
  hangs on it; it is set explicitly with `--identifier`, not left to the file name.
- **One `release` environment, targets `v*` and `main`.** The publish job stays tag-only.
- **Entitlements: none by default**, as in the build steps above.
- **Required reviewer: the operator, administrator bypass off.** See operator step 5 for what that
  does not cover until WCLI-182 lands.
- **Certificate expiry.** The certificate's expiry date goes in Ward's publish runbook when it is
  created. A renewal keeps the team id and the identifier, so the requirement survives it.
- **Individual or organization** is settled by the enrolment; operator step 1 reads which. An
  individual account puts the operator's legal name in the signing identity shown for every
  release; an organization shows its name. The requirement is pinned to the team id, so the name
  does not affect Keychain trust.

## Files a build task would touch (not touched here)

`.github/workflows/release.yml`, `test/release-workflow.test.ts`, a new `scripts/` helper for the
keychain import and cleanup, the install and publish runbooks, ADR 0001's deferral paragraph, and
`docs/runbooks/protect-the-release-path.md` (the environment targets). Each is a release-path
change that needs its own dispatch-floor read and an Opus review.

## Related

WCLI-109 (attestation) is local work that must follow `sign` once this lands: `attest` then needs
`[build, sign, verify]` and attests the signed bytes. WCLI-182 (admin credential on the operator's
host) bears on step 5, because the secrets' protection assumes sessions do not hold admin.
