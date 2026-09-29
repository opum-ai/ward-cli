// The Ward guidance block and where it goes (spec §11.2). The text is
// spec §11.2's minimal nudge, verbatim: it names the commands an agent runs
// and never claims a command exists, which is why it points at
// `ward instructions` rather than carrying a command list of its own.
//
// Selecting a target writes the block into that host's instruction file
// only. This module owns the block, where it goes, and where a leftover copy
// of the skill would sit for each host - the paths `ward agents` judges a
// found copy at, never writes (DEC-44, DEC-47).
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

// Where each host would discover a local copy of the skill (spec §11.2).
// Ward writes neither document; they exist so a copy somebody put there is
// judged and named rather than silently ignored (DEC-47).
export const agentTargetSkillDocuments: Record<AgentTarget, ProjectDocument> = {
  claude: "claude-skill",
  codex: "codex-skill",
};

export const agentTargetNames: Record<AgentTarget, string> = {
  claude: "Claude Code (CLAUDE.md)",
  codex: "Codex (AGENTS.md)",
};
