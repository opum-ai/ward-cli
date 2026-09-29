// The port through which Ward reaches the files it manages inside a
// checkout: the tracked project manifest and the agent instruction files.
// Implementations are bound to one canonical worktree root and may only
// touch the paths named here, so no command argument ever becomes a
// filesystem path (spec §6.2).

export type ProjectDocument =
  | "manifest"
  | "claude-instructions"
  | "codex-instructions"
  | "claude-skill"
  | "codex-skill";

export const projectDocumentPaths: Record<ProjectDocument, string> = {
  manifest: ".ward/project.json",
  "claude-instructions": "CLAUDE.md",
  "codex-instructions": "AGENTS.md",
  // Where a leftover copy of the skill sits, per host (spec §11.2, DEC-47).
  // Ward writes neither path: the skill ships from the opum-ward plugin, and
  // these are the names `ward agents` judges a found copy at.
  "claude-skill": ".claude/skills/ward/SKILL.md",
  "codex-skill": ".agents/skills/ward/SKILL.md",
};

export interface ProjectFiles {
  // The document's text, or undefined when it does not exist. Never creates
  // anything. Refuses to read through a link that leaves the repository.
  read(document: ProjectDocument): string | undefined;
  // Replaces the document atomically, creating it and any directory it needs.
  // Refuses a path that is a link leaving the repository, and never follows
  // one (spec §11.2).
  write(document: ProjectDocument, content: string): void;
  // Removes the document, reporting whether a file was there to remove.
  // Refuses a path that is a link leaving the repository, the same as read
  // and write. Reached only for the skill paths, and only for a copy whose
  // bytes are the packaged skill's (DEC-47); an instruction file is never
  // removed.
  remove(document: ProjectDocument): boolean;
}
