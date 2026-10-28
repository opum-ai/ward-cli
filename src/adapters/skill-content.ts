// The packaged skill's own bytes, embedded at build time (DEC-47, ADR 0015).
//
// `ward agents` judges a local skill file at the two host paths spec §11.2
// names, and `--force` removes one only when its bytes are exactly the file
// the plugin ships. That comparison needs the file's content in the binary,
// and this import is how it gets there: the bundler inlines
// plugin/skills/ward/SKILL.md, so the copy Ward compares against is always the copy
// cut from the same commit, and it cannot drift from what the plugin
// distributes. The skill is public guidance; nothing secret reaches it.
import packagedSkill from "../../plugin/skills/ward/SKILL.md" with {
  type: "text",
};

export const packagedSkillContent: string = packagedSkill;
