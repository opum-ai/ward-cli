<!-- quest:agent-instructions:begin -->
# Quest agent instructions

This project uses Quest CLI 0.14.1 for tracker operations. Run `quest manifest --json` to discover the supported command contract.

Read the matching guide before tracker work: `quest instructions overview` for the command set and machine contract, `quest instructions task-creation` before creating or splitting tasks, `quest instructions task-execution` before claiming, planning, or recording progress, `quest instructions task-finalization` before checking acceptance criteria or closing a task, and `quest instructions workspace` for initialization, managed instructions, and Backlog.md migration. `quest instructions --list` lists every guide. Search for an existing record with `quest search "<query>" --json` before creating one, and run `quest help <command>` for a command's options and examples.

Quest writes require an explicit actor declaration: `--actor <id> --actor-kind human` for a person, or `--actor <id> --actor-kind delegated-agent --accountable-human <id>` for an agent acting on a person's behalf. Do not edit Quest-authored records directly. CI should run `quest agents --check --require-installed --target claude`: current instructions, and a version-only difference (only the pinned Quest CLI version number is stale) both exit 0; missing, drifted, or malformed managed instructions exit 6. Quest does not retry write conflicts automatically; callers should read the latest task state and perform their own bounded retry when a command returns conflict/exit 5.
<!-- quest:agent-instructions:end -->

<!-- lore:agents:begin -->
This repo uses **lore** — an OKF-native documentation CLI — for the docs bundle under `docs/`.
Drive docs work through `lore` (not a plain editor or `grep`) so Story <-> Task coupling, managed
blocks, and cross-links stay coherent.

- **Find and read docs:** `lore query "<words>" --limit 5`, then `lore read <id>` for the best hit.
- **Skill:** installed from the `opum-lore` Claude Code plugin, not this repository — how to drive lore.
- **Just-in-time detail:** run `lore instructions` for the canonical agent loop, then
  `lore instructions <topic>` (`retrieval`, `linking`, `sync`, `check`, `validation`, `types`, `workspace`, `agents`).
<!-- lore:agents:end -->

## What this repository is

Ward (`ward`): a local-first secret-management CLI for agentic engineering, part of the Opum
product family. An agent names a credential and an approved operation; Ward consumes the
credential without returning its value to the agent. The repository holds the design record and
the implementation it specifies: `WARD_MVP_AGENT_SPEC.md` is the v0.1 implementation brief, and
the agent skill lives at `skills/ward/SKILL.md`, packaged here as the `opum-ward` plugin. No
Ward release has shipped yet.

@~/.claude/opum-fleet-operating.md

<!-- opum:repo-profile:begin -->
## ward-cli — repository profile

Facts true of this repository only. The operating model above is byte-identical
fleet-wide; this block is where repositories legitimately differ. Keep these
headings, in this order, and write "None known." rather than deleting one that
has no entries yet.

### Role

Owns the Ward CLI and its agent skill. Adopted into the fleet on 2026-09-28 under
opum-agent OPAG-655. Tracker prefix `WCLI`. The repository is private for now.

### SDLC

The lifecycle is the `opum-sdlc` skill in the `opum-workflow` plugin. Task before
branch; squash into `dev`; fast-forward `dev` to `main`. Hook-written tracker notes
depend on `OPUM_HOOK_ACTOR` and `OPUM_HOOK_ACCOUNTABLE_HUMAN` in the committed
`.claude/settings.json`; with either unset the hooks write nothing.

**The gated ref is `dev`.** Measured live on 2026-09-28 with
`gh api repos/opum-ai/ward-cli/rules/branches/dev`: ruleset 24097150, "require CI on
dev", active, no bypass actors, requires `Check`, `Docs` and `Tracker integrity`,
each pinned to integration 15368 (GitHub Actions), strict policy off. `main` has no
rules. A required check can only pass on a SHA that has already been through CI, so
nothing can be pushed straight to `dev`, a tracker-only change included: every
change lands through a pull request. Re-measure rather than trust this paragraph.
Renaming or removing a CI job means updating the ruleset in the same change, or
every merge blocks on a check that never reports.

CI is `.github/workflows/ci.yml` (WCLI-17), on `[self-hosted, Linux, ARM64]`. The
org and repository runner listings both report 0 runners, yet every job is picked
up within seconds by the `mbpm2` group's ephemeral `linux-arm64-*` runners. A
listing is not evidence either way; an actual job's `runner_name` is.

### Retirement machinery carried here

None known.

### What other repositories read from here

None known yet. Planned: `opum-marketplace` will pin a federated entry for the
proposed `opum-ward` plugin at an immutable release reference. It must not be added
before that release artifact exists (spec §11.3).

### Constraints and couplings to respect

Ward is versioned independently of the lore/quest pair. Do not align its version
number with theirs or read compatibility into a matching one; probe
`lore manifest --json` and `quest manifest --json` instead (spec §11.1).

Ward must work with neither Lore nor Quest installed. It must never import their
code or write into `.lore/` or `.quest/` storage; integration goes through their
public CLIs only.

The spec's design decisions (vault format, keychain binding, plugin name) are open
design questions recorded in opum-doc, not settled contracts. This session owns the
code and argues them there.

Development and tests use synthetic credentials and a dedicated temporary store and
key-provider namespace. Never touch the developer's real `~/.ward/` vault or its
keychain item, and never request a real credential in an agent session.

The lore and quest skills ship as the `opum-lore` and `opum-quest` plugins
(`agents.skill_source = "plugin"` in `.lore/config.toml` and
`.quest/workspace.toml`). A copy under `.claude/skills/` is drift;
`lore agents --check --target claude` and
`quest agents --check --require-installed --target claude` both exit 0 when clean.
<!-- opum:repo-profile:end -->
