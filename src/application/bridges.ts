// The Ward guidance block and where it goes (spec §11.2). The text is
// spec §11.2's minimal nudge, verbatim: it names the commands an agent runs
// and never claims a command exists, which is why it points at
// `ward instructions` rather than carrying a command list of its own.
//
// Selecting a target writes the block into that host's instruction file
// only. The optional per-host skill file (`skills/ward/SKILL.md` under
// `.claude/` or `.agents/`) and the `ward agents` refresh command are
// WCLI-14's scope; this module owns the block and its target map, which that
// command reuses.
import type { AgentTarget } from "../contract/manifest.ts";
import type { ProjectDocument } from "./project-files.ts";

export const wardBlockBody = [
  "## Credentials: Ward",
  "Use `ward instructions` and the Ward skill before credential-dependent work.",
  "Use `ward check <profile> --json`, then `ward run <profile> --json`.",
  "Never request, print, export, copy, or store secret values in agent context,",
  ".env files, environment variables, source, logs, Lore, or Quest.",
  "Missing binding, approval, or credential means stop and request human setup",
  "outside this session. Never self-approve or bypass Ward.",
  "",
].join("\n");

export const agentTargetDocuments: Record<AgentTarget, ProjectDocument> = {
  claude: "claude-instructions",
  codex: "codex-instructions",
};

export const agentTargetNames: Record<AgentTarget, string> = {
  claude: "Claude Code (CLAUDE.md)",
  codex: "Codex (AGENTS.md)",
};
