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
rehearsal or on the operator's Mac (both below), not a fact.

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
prompt. A hosted runner has no Ward Keychain item, so the rehearsal below cannot measure this; it
is measured on the operator's Mac, or by a session using a synthetic store and a key-provider
namespace of its own, never a real `~/.ward` item. *Expected, not measured:* the first Developer
ID build still needs one re-approval, because the existing item trusts the old cdhash.

The Keychain ACL is still not a security boundary while `BUN_BE_BUN` and `BUN_OPTIONS` reach the
executable (WCLI-19); signing is the precondition ADR 0001 names, not the whole fix.

## Recommended path

**Two jobs, so the signing credential never meets dependency code.** Today one macOS job installs
dependencies, builds, signs ad hoc and uploads. If that job also held a Developer ID key, every
package install script it runs would sit beside the key. So:

- `build` (no environment, no secrets): unchanged, producing the ad-hoc-signed artifact it does
  today.
- `sign` (new, `environment: release`, hosted macOS runner): downloads that artifact, runs no
  package manager and no third-party code except pinned actions, Apple's own tools, the runner's
  `node` and this repository's first-party scripts. It re-signs with the Developer ID identity,
  submits for notarization, verifies, regenerates the `.sha256` and `release-notes.md` from the
  re-signed bytes, and uploads the signed artifact. It is the only job that **references** the
  signing secrets. It is not the only job entitled to them: under the decided single environment
  the existing `release` job also names `environment: release`, so it can read the same secrets,
  but it runs only a checkout, a pinned artifact download, `sha256sum` and first-party `node`, and
  references none. The build task's test
  should assert that no other job references `secrets.APPLE_*`. Consequence: the required reviewer
  is asked for both `sign` and `release` on every tag, and for `sign` on every rehearsal
  (*unmeasured*).
- `verify`, `attest` (WCLI-109) and `release` then follow `sign` and act on the signed bytes:
  `verify` re-checks the signed asset, `attest` attests it, `release` publishes it.

Inside `sign`, on a macOS runner:

1. Create a temporary keychain with a random password, import the `.p12` into it, allow `codesign`
   to use the key without a prompt (`security set-key-partition-list`), and delete the keychain in
   a final step that always runs.
2. `codesign --force --options runtime --timestamp --identifier ai.opum.ward --sign "<Developer ID
   Application identity>" ward-darwin-arm64`. Hardened runtime is required for notarization.
3. *Unmeasured, the largest technical unknown:* a `bun build --compile` executable embeds a
   JavaScript engine and may need hardened-runtime entitlements (JIT and executable memory) to run
   at all once hardened. The signed binary's own smoke test decides it. **The smoke test runs in `verify`** (no
   environment, no secrets) against the signed artifact, never in `sign`: a compiled binary carries
   the Bun runtime and every bundled dependency, and `sign` holds the private key and the decoded
   credential files until its final cleanup, so running it there would put dependency code beside
   the key. The build task adds the smoke step to `verify`.
   **Decided (DEC-301 (a3)): no entitlements by default.** `allow-jit` and/or
   `allow-unsigned-executable-memory` may be added only if the smoke test fails without them, with
   the fewest that pass and both runs cited. Anything else comes to opum-doc first, and above all
   `allow-dyld-environment-variables` and `disable-library-validation`, because of the `BUN_`
   exposure (WCLI-19). A plist, if any, is passed with `--entitlements`.
4. Zip the binary, `xcrun notarytool submit --wait` with the API-key credential, require status
   `Accepted`, and keep the log. A bare command-line executable cannot be stapled, so the ticket
   lives with Apple and Gatekeeper reads it online; *unmeasured:* how a first run of a
   curl-downloaded, un-quarantined binary behaves offline (measured on the operator's Mac, as
   above). The released asset stays the bare `ward-darwin-arm64` so the install runbook and
   checksum flow do not change.
5. `codesign --verify --strict`, then check the designated requirement names the team and
   identifier (`codesign -d -r-`), then the existing cdhash agreement check, all before upload.
   `spctl --assess` is not used: it is expected to reject a bare executable even when it is
   correctly signed (*unmeasured* here).

Secret hygiene in `sign`: decode the `.p12` and `.p8` under `$RUNNER_TEMP`, outside any upload
path; upload explicit filenames, as `build` does at `release.yml`'s upload step; pass each secret
through the `env` of only the step that needs it; no `set -x`; remove the decoded files in the same
always-run cleanup that deletes the keychain.

The existing gates keep their meaning: verify re-checks the downloaded asset, attestation covers
the signed bytes, and the notes' sha256 and cdhash come from the signed file. The "expect one
keychain re-approval per upgrade" line in the notes changes only after the operator's Mac shows it.

### Credentials, and why an App Store Connect API key

Notarization needs a credential. An App Store Connect API key (a `.p8` file, a key id and an issuer
id) is revocable, scoped to a team, tied to no person's password and needs no two-factor prompt, so
it suits CI better than an Apple ID with an app-specific password. Both are operator-created.

## The rehearsal (how the first real tag avoids being the first test)

A tag is frozen once the tag ruleset exists, so a failed first signing run on a real tag would burn
a version ([protect the release path](../runbooks/protect-the-release-path.md)). The `release`
environment therefore allows two deployment targets, decided as one environment (DEC-301 (a3)):
tags matching `v*` and the branch `main`. A `workflow_dispatch` run from `main` signs and
notarizes, runs the smoke test (in `verify`) and publishes nothing; the Release job stays tag-only. The run does
upload the signed binary as a public run artifact (it is not a secret).

A behaviour change the build task owns: today a `workflow_dispatch` from any branch is a full dry
run. Under this design signing is gated on a tag or on `main`, because the environment's branch
policy would refuse `sign` on any other branch; a dispatch from another branch therefore builds
only, and `verify`, `attest` and `release` are skipped with it. The dry run for signing becomes
main-only.

`main` is the gated ref only after operator step 5 applies the `main` ruleset; `main` has no rules
today. So step 5 before any rehearsal is load-bearing: without it, anyone who can push to `main`
can reach the secrets by a dispatch run. The rehearsal measures: entitlements needed, notarization
acceptance, and the designated requirement text. It does not measure Keychain behaviour or the
offline first run (see above).

## Operator steps, in order (one batch for opum-doc to put to the operator)

1. Open the Apple Developer account and read two facts: the membership is **active**, and it is an
   **individual** or an **organization**. Only the Account Holder can create a Developer ID
   certificate.
2. On a Mac the operator controls, create a certificate signing request in Keychain Access, then in
   the developer portal (Certificates, IDs & Profiles) create a **Developer ID Application**
   certificate from it and install the download. Note the certificate's expiry date for the
   publish runbook. The private key never leaves that Mac except in step 3.
3. Export the certificate and its private key as a `.p12` with a strong password, kept out of
   every session's reach and out of the repository.
4. In App Store Connect (Users and Access, Integrations) create a team API key whose role is
   enough for notarization (confirm the minimum role), download the `.p8` once, and note the key id
   and issuer id.
5. Apply WCLI-103's settings, runbook steps 1 to 4 (`main` and tag rulesets, the `release`
   environment, the immutable-releases decision), and add `main` to the environment's deployment
   targets beside `v*`. The environment's required reviewer is the operator, with administrator
   bypass off (`"can_admins_bypass": false` in the environment's PUT body). Until WCLI-182 lands,
   this protection assumes no session acts as an administrator; it does not hold against one. The
   protect runbook is updated with these additions by the build task (WCLI-185); until it lands,
   run, after the runbook's step 3 commands:
   `gh api repos/opum-ai/ward-cli/environments/release/deployment-branch-policies --method POST
   -f name=main -f type=branch`, and add `"can_admins_bypass": false` and the operator's
   `"reviewers": [{ "type": "User", "id": <numeric id> }]` to the environment's PUT body.
6. Store five values as **environment secrets** on `release`, from files and never typed into a
   session: the base64 `.p12`, its password, the `.p8`, the key id and the issuer id. For example
   `base64 < cert.p12 | gh secret set APPLE_CERT_P12_BASE64 --env release --repo opum-ai/ward-cli`
   and `gh secret set APPLE_CERT_PASSWORD --env release --repo opum-ai/ward-cli` (prompts for the
   value). Two non-secret values, the signing identity string and the team id, go in as
   environment variables.
7. Once the build task has landed (a separate release-path change with its own review), run the
   rehearsal: trigger the release workflow by `workflow_dispatch` from `main` and **approve the
   `release` deployment** when the reviewer prompt appears.
8. Read the rehearsal's result before any tag: notarization `Accepted`, the designated requirement
   names the team and `ai.opum.ward`, and the smoke test passes without entitlements (or with the
   fewest entitlements the decided rule allows, both runs cited). Then, on the operator's Mac, install the signed
   binary over an ad-hoc build with a synthetic vault and check the Keychain behaviour and the
   offline first run, which the rehearsal cannot show.
9. Cut the first Developer ID release and approve its `sign` and `release` deployments. Expect one
   Keychain re-approval on that upgrade; after it, expect silence on the next, and confirm it.

No step has a session read, print, store or send a credential value.

## Choices, as decided by opum-doc (DEC-301 (a3))

- **Code-signing identifier: `ai.opum.ward`, and it never changes.** The designated requirement
  hangs on it; it is set explicitly with `--identifier`, not left to the file name.
- **One `release` environment, targets `v*` and `main`.** The publish job stays tag-only.
- **Entitlements: none by default**, as in the build steps above.
- **Required reviewer: the operator, administrator bypass off.** See operator step 5 for what that
  does not cover until WCLI-182 lands.
- **Certificate expiry.** The expiry date goes in the new publish-and-signing section the build
  task adds to `publish-a-mac-signed-ward-release-asset.md` (that runbook exists today and has no
  such section). *Expected, not measured:* a renewal keeps the team id and the identifier, so the
  requirement survives it.
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
