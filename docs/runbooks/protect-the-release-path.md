---
# yaml-language-server: $schema=../../.lore/schemas/runbook.schema.json
type: Runbook
title: Protect the release path
tags:
  - release
  - security
summary: Operator steps that protect main, v* tags and the release environment, and the immutable-releases decision (WCLI-103, W-8); Ward prepares them and never applies them.
generated:
  by: lore/0.15.1
  at: 2026-11-23T04:53:27.704Z
---

# Protect the release path

## Purpose

Closes the W-8 finding (WCLI-103): protection exists only on `dev`, so a token with write access
could push a `main` commit and a matching tag and publish a release.

**The control is the settings below, which only the operator applies.** Ward's sessions prepare them
and never run the write commands. `release.yml` also checks the tagged commit (it must be on `dev`
and carry green Check, Docs and Tracker integrity runs from GitHub Actions), but that is a guard
against a mistaken tag, not a defence against a writer: a tag push runs the workflow file as it
exists at the tagged commit, so someone who can push both can delete the check in the same commit.
Until the rulesets are applied, W-8 is not closed.

## Prerequisites

- `gh` is signed in as the repository's owner or an admin.
- Measured on 2026-11-23 and to be re-measured before applying: the only ruleset is 24097150
  ("require CI on dev", branch, active, no bypass actors), there are no environments, tags are
  `v0.1.0` and `v0.1.1`, and `GET repos/opum-ai/ward-cli/immutable-releases` prints
  `{"enabled":false,"enforced_by_owner":false}`.
- The three required check names and integration 15368 come from ruleset 24097150. They must match
  `scripts/check-release-gated.mjs` and the job names in `ci.yml`.

## Steps

1. **Gate `main` like `dev`.** `main` only ever receives a fast-forward of a gated `dev`, so the same
   required checks pass on that SHA's existing history, and a direct push of an unchecked commit is
   refused. No bypass actors.

   ```sh
   gh api repos/opum-ai/ward-cli/rulesets --method POST --input - <<'JSON'
   {
     "name": "require CI on main",
     "target": "branch",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
     "bypass_actors": [],
     "rules": [
       { "type": "deletion" },
       { "type": "non_fast_forward" },
       { "type": "required_status_checks",
         "parameters": {
           "strict_required_status_checks_policy": false,
           "do_not_enforce_on_create": false,
           "required_status_checks": [
             { "context": "Check", "integration_id": 15368 },
             { "context": "Docs", "integration_id": 15368 },
             { "context": "Tracker integrity", "integration_id": 15368 }
           ] } }
     ]
   }
   JSON
   ```

2. **Protect the release tags.** Two rulesets, so the bypass question is explicit.

   Operator choice (A/B), recommendation first:
   - **A (recommended): no bypass for update and deletion, and an admin bypass for creation only.**
     An existing `v*` tag can never be moved or deleted by anyone; only a repository admin, the
     operator, can create one.
   - **B: no bypass anywhere.** Nobody can create a `v*` tag while the ruleset is active, so each
     release needs the creation ruleset switched to disabled for the tag push and back, which is
     itself a settings change at release time.

   The commands below are A. For B drop the `bypass_actors` entry of the first.

   ```sh
   gh api repos/opum-ai/ward-cli/rulesets --method POST --input - <<'JSON'
   {
     "name": "restrict release tag creation",
     "target": "tag",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
     "bypass_actors": [
       { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
     ],
     "rules": [ { "type": "creation" } ]
   }
   JSON
   gh api repos/opum-ai/ward-cli/rulesets --method POST --input - <<'JSON'
   {
     "name": "freeze release tags",
     "target": "tag",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
     "bypass_actors": [],
     "rules": [ { "type": "update" }, { "type": "deletion" } ]
   }
   JSON
   ```

   `update` already refuses moving a tag, so no `non_fast_forward` rule is added: it is a branch
   rule, and a tag ruleset carrying it may be refused with HTTP 422.

3. **Create the `release` environment limited to `v*` tags.** The release job names it. Without this
   step GitHub creates it unprotected on first use, so do this before the next release.
   **Add a required reviewer (recommended).** It is the one environment setting that puts a person
   in front of a release: add `"reviewers": [{ "type": "User", "id": <your numeric id> }]` (from
   `gh api users/<login> --jq .id`) to the first command's body. The environment binds only a job
   that names it, which the workflow at the tagged commit decides, so it adds a click for the
   operator and is not a defence against someone who can edit the workflow.

   ```sh
   gh api repos/opum-ai/ward-cli/environments/release --method PUT --input - <<'JSON'
   { "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true } }
   JSON
   gh api repos/opum-ai/ward-cli/environments/release/deployment-branch-policies \
     --method POST -f name='v*' -f type=tag
   ```

4. **Immutable releases (decision).** Recommended: enable. The publish script already creates a
   draft, uploads every asset and only then publishes (`scripts/publish-release.mjs`), which is the
   order immutable releases need, so nothing in the workflow changes. The cost is that a published
   release's tag and assets can never change: a bad release is superseded by a new version, never
   repaired in place.

   **It removes an existing route.** [Publish a Mac-signed Ward release asset](publish-a-mac-signed-ward-release-asset.md)
   steps 4 and 5 and its Rollback repair a published release with `gh release upload --clobber`.
   Enabling immutability makes that upload fail, so a wrong asset means a new version. GitHub's
   documentation says a published immutable release keeps its title and notes editable, so the
   `gh release edit --notes-file` parts should still work; that is read from the documentation, not
   measured here. Enable it before the first release that carries build provenance.

   ```sh
   gh api repos/opum-ai/ward-cli/immutable-releases --method PUT
   ```

5. **Verify what you applied**, then promote as usual:

   ```sh
   gh api repos/opum-ai/ward-cli/rulesets --jq '.[] | {id, name, target, enforcement}'
   gh api repos/opum-ai/ward-cli/rules/branches/main --jq '[.[].type]'
   gh api repos/opum-ai/ward-cli/environments/release --jq '.deployment_branch_policy'
   gh api repos/opum-ai/ward-cli/immutable-releases
   ```

   The next `git push origin origin/dev:main` must still succeed, because the dev tip already has
   the three checks; a push of any unchecked commit to `main` must be refused. That push also runs
   `ci.yml` on `main`, which starts a second Check, Docs and Tracker integrity set on the same SHA:
   wait for the runs on both `dev` and `main` before cutting the tag.

## Rollback

Delete a ruleset with `gh api repos/opum-ai/ward-cli/rulesets/<id> --method DELETE`, the
environment with `gh api repos/opum-ai/ward-cli/environments/release --method DELETE`, and turn
immutable releases off with `--method DELETE` on its endpoint. Immutability cannot be undone for a
release already published under it.

If the dev-gate step in `release.yml` blocks a legitimate release, the tag is not on `dev` or a
check is missing or red on that commit. Promote `dev` to `main` through the normal path, wait for
the push runs on both `dev` and `main` to go green, and cut a new tag. Do not weaken the step.
