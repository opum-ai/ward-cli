// T25's local half (spec §11.3): the skill, the plugin manifest and the CLI
// are cut from one repository at one tag, so their versions must not be able
// to disagree at release time. The public federated index is a later phase
// and another repository's artifact; what this file can settle is the half
// that lives here.
//
// Enforced as a test rather than as a release runbook, which is the peer
// pattern that came from paying for it: lore-cli added exactly this check
// after 0.4.3 shipped carrying 0.4.2 (LCLI-447), and quest-cli's own runbook
// says of its plugin.json that "nothing generates it and no test compares it
// to package.json, which is exactly why it drifted silently". Ward takes the
// enforced form.
import { describe, expect, test } from "bun:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import pluginJson from "../plugin/.claude-plugin/plugin.json" with {
  type: "json",
};
import packageJson from "../package.json" with { type: "json" };

const repositoryRoot = join(import.meta.dir, "..");

describe("the plugin manifest agrees with what this repository ships", () => {
  test("its version is the CLI's version", () => {
    // The failure this catches is silent by construction: a release bumps
    // package.json, the plugin keeps the previous number, and an installed
    // plugin describes a contract the installed CLI does not have.
    expect(pluginJson.version).toBe(packageJson.version);
  });

  test("it is named opum-ward and resolves to this repository", () => {
    expect(pluginJson.name).toBe("opum-ward");
    expect(pluginJson.repository).toBe("https://github.com/opum-ai/ward-cli");
  });

  test("the skill it packages is the one under plugin/skills/ward and is frontmattered", () => {
    const skill = readFileSync(
      join(repositoryRoot, "plugin", "skills", "ward", "SKILL.md"),
      "utf8",
    );
    expect(skill.startsWith("---\n")).toBe(true);
    const frontmatter = skill.slice(4, skill.indexOf("\n---", 3));
    // The skill's own name is what a host resolves when it lists the skill;
    // the plugin's name is what a marketplace resolves. They are different
    // strings on purpose (`opum-ward` and `ward`), and only the repository
    // knows both, so the agreement is asserted rather than assumed.
    expect(frontmatter).toMatch(/^name: ward$/m);
    expect(frontmatter).toMatch(/^description: \S/m);
  });
});

describe("the plugin ships from a lean directory (DEC-246 a4, a7)", () => {
  test("plugin/ carries only .claude-plugin/plugin.json and skills/", () => {
    const pluginRoot = join(repositoryRoot, "plugin");
    const entries = readdirSync(pluginRoot).sort();
    expect(entries).toEqual([".claude-plugin", "skills"]);
    expect(readdirSync(join(pluginRoot, ".claude-plugin"))).toEqual([
      "plugin.json",
    ]);
    // A plugin install fetches this directory and nothing beside it, so a
    // manifest or lockfile here would be the dependency tree coming back.
    for (const name of ["package.json", "node_modules", "bun.lock"]) {
      expect(entries).not.toContain(name);
    }
  });

  test("the old root locations no longer carry the plugin", () => {
    expect(existsSync(join(repositoryRoot, ".claude-plugin"))).toBe(false);
    expect(existsSync(join(repositoryRoot, "skills"))).toBe(false);
  });
});
