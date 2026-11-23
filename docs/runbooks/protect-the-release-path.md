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
could push a `main` commit and a matching tag and publish a release. Two layers close it. The
release workflow now asks for the gate itself (already in `release.yml`: the tagged commit must be
on `dev` and carry green Check, Docs and Tracker integrity runs from GitHub Actions, and the release
job runs in the `release` environment). The settings below are GitHub security posture, which only
the operator applies. Ward's sessions prepare them and never run the write commands.

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

2. **Protect the release tags.** Nobody but a repository admin creates a `v*` tag, and no one moves
   or deletes one. This adds one bypass actor (the Admin repository role, id 5), which is the
   operator who cuts the tag; if you would rather have none, drop `bypass_actors` and lift the
   ruleset for the one tag push. The workflow gate holds either way: an admin-made tag still has to
   be on `dev` with green checks.

   ```sh
   gh api repos/opum-ai/ward-cli/rulesets --method POST --input - <<'JSON'
   {
     "name": "protect release tags",
     "target": "tag",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
     "bypass_actors": [
       { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
     ],
     "rules": [
       { "type": "creation" },
       { "type": "update" },
       { "type": "deletion" },
       { "type": "non_fast_forward" }
     ]
   }
   JSON
   ```

3. **Create the `release` environment limited to `v*` tags.** The release job names it. Without this
   step GitHub creates it unprotected on first use, so do this before the next release.
   Add `"reviewers": [{ "type": "User", "id": <your numeric id> }]` (from
   `gh api users/<login> --jq .id`) to the first command if you want an approval click per release.

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
   repaired in place. That matches how this repository already treats a release. Enable it before
   the first release that carries build provenance.

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
   the three checks; a push of any unchecked commit to `main` must be refused.

## Rollback

Delete a ruleset with `gh api repos/opum-ai/ward-cli/rulesets/<id> --method DELETE`, the
environment with `gh api repos/opum-ai/ward-cli/environments/release --method DELETE`, and turn
immutable releases off with `--method DELETE` on its endpoint. Immutability cannot be undone for a
release already published under it.

If the dev-gate step in `release.yml` blocks a legitimate release, the tag is not on `dev` or a
check is missing or red on that commit. Promote `dev` to `main` through the normal path, wait for
the push run on `dev` to go green, and cut a new tag. Do not weaken the step.
