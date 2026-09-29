// WCLI-14: the `ward agents` bridge half of spec §8's two rows, over the
// managed block spec §11.2 defines.
//
// What is pinned here is the pair of properties a bridge has to have: the
// check judges without touching a file, and the write replaces exactly the
// bytes between Ward's own markers, leaving user prose and a peer's block
// untouched. A malformed marker pair is the same conflict on both paths,
// because a file Ward refuses to write is one it also refuses to judge.
//
// The skill-file half of spec §8's row is pinned by its own block below
// (DEC-47): Ward writes no local skill file, a copy found at either host's
// path is drift that fails --check, and --force removes one only when its
// bytes are exactly the packaged skill's.
//
// Every case runs in a throwaway checkout with no vault; nothing touches the
// developer's repositories, ~/.ward or keychain.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { packagedSkillContent } from "../src/adapters/skill-content.ts";
import { wardBlockBody } from "../src/application/bridges.ts";
import { runWard } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import {
  managedBlockBegin,
  managedBlockEnd,
} from "../src/domain/managed-block.ts";

const root = mkdtempSync(join(tmpdir(), "ward-agents-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;
// `locateCheckout` walks upward for a `.git` entry, which is all a checkout
// needs to be for this command; the entry does not have to be a repository.
function checkout(): string {
  const directory = join(root, `case-${++cases}`);
  mkdirSync(join(directory, ".git"), { recursive: true });
  return directory;
}

// The body already ends with its own newline, which is what the block writer
// lays between the body and the closing marker.
const block = `${managedBlockBegin}\n${wardBlockBody}${managedBlockEnd}\n`;

// A run in JSON mode has its envelope parsed for the assertions below, and a
// run in text mode keeps its text: `--json` prints the envelope and never the
// human line, so a test that wants to read the human sentence must not ask
// for JSON.
async function ward(cwd: string, ...argv: string[]) {
  const result = await runWard(argv, {
    cwd,
    wardDirectory: join(cwd, "no-vault"),
  });
  const asJson = argv.includes("--json");
  return {
    ...result,
    json:
      asJson && result.stdout.trim() !== ""
        ? JSON.parse(result.stdout)
        : undefined,
    error: result.stderr.trim() === "" ? undefined : JSON.parse(result.stderr),
  };
}

describe("ward agents --check", () => {
  test("an absent block is reported without failing, and creates no file", async () => {
    const cwd = checkout();
    const result = await ward(
      cwd,
      "agents",
      "--check",
      "--target",
      "claude",
      "--json",
    );
    // Absence is a legitimate state - spec §11.2 calls the local bridge
    // explicitly selected, and init may run without one - so it is reported
    // rather than failed. --require-installed is what a caller that has
    // adopted the bridge uses to make it stop.
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.json.kind).toBe("agents.status");
    expect(result.json.data).toEqual({
      target: "claude",
      document: "CLAUDE.md",
      fileExists: false,
      state: "absent",
      skill: {
        document: ".claude/skills/ward/SKILL.md",
        state: "absent",
        matchesPackaged: false,
      },
    });
    expect(existsSync(join(cwd, "CLAUDE.md"))).toBe(false);

    const strict = await ward(
      cwd,
      "agents",
      "--check",
      "--require-installed",
      "--target",
      "claude",
      "--json",
    );
    expect(strict.exitCode).toBe(exitCodes.validation);
    expect(strict.json.data.state).toBe("absent");
    expect(existsSync(join(cwd, "CLAUDE.md"))).toBe(false);
  });

  test("a file without a block is reported as such, not as a missing file", async () => {
    const cwd = checkout();
    writeFileSync(join(cwd, "CLAUDE.md"), "# House rules\n");
    const strict = await ward(
      cwd,
      "agents",
      "--check",
      "--require-installed",
      "--target",
      "claude",
      "--json",
    );
    expect(strict.exitCode).toBe(exitCodes.validation);
    expect(strict.json.data.fileExists).toBe(true);
    expect(strict.json.data.state).toBe("absent");
  });

  test("a block this build writes is current, and checking writes nothing", async () => {
    const cwd = checkout();
    writeFileSync(join(cwd, "AGENTS.md"), `# Notes\n\n${block}`);
    const before = readFileSync(join(cwd, "AGENTS.md"));
    const result = await ward(
      cwd,
      "agents",
      "--check",
      "--target",
      "codex",
      "--json",
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.json.data).toEqual({
      target: "codex",
      document: "AGENTS.md",
      fileExists: true,
      state: "current",
      skill: {
        document: ".agents/skills/ward/SKILL.md",
        state: "absent",
        matchesPackaged: false,
      },
    });
    expect(readFileSync(join(cwd, "AGENTS.md")).equals(before)).toBe(true);
  });

  test("a hand-edited block is stale, and the text names the repair", async () => {
    const cwd = checkout();
    writeFileSync(
      join(cwd, "CLAUDE.md"),
      `${managedBlockBegin}\n## Credentials: Ward\nAsk me for the value.\n${managedBlockEnd}\n`,
    );
    const result = await ward(cwd, "agents", "--check", "--target", "claude");
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(result.stdout).toContain("is not the one this build writes");
    expect(result.stdout).toContain("--update-instructions --target claude");
  });

  test("malformed markers are a state to a check and a conflict to a write", async () => {
    const cwd = checkout();
    const duplicated = `${managedBlockBegin}\n${wardBlockBody}\n${managedBlockBegin}\n${managedBlockEnd}\n`;
    writeFileSync(join(cwd, "CLAUDE.md"), duplicated);
    // The check answers about the repository, so it reports the state the
    // caller asked about and fails the check; the writer refuses the write
    // it cannot make, which is the catalogue's conflict.
    const checked = await ward(
      cwd,
      "agents",
      "--check",
      "--target",
      "claude",
      "--json",
    );
    expect(checked.exitCode).toBe(exitCodes.validation);
    expect(checked.json.data.state).toBe("malformed");

    const updated = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(updated.exitCode).toBe(exitCodes.conflict);
    expect(updated.error.code).toBe("instructions_markers_conflict");
    expect(readFileSync(join(cwd, "CLAUDE.md"), "utf8")).toBe(duplicated);
  });
});

describe("ward agents --update-instructions", () => {
  test("adds the block to each target's own document and nothing else", async () => {
    const cwd = checkout();
    const created = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(created.exitCode).toBe(exitCodes.success);
    expect(created.json.data).toEqual({
      target: "claude",
      document: "CLAUDE.md",
      status: "created",
      skill: {
        document: ".claude/skills/ward/SKILL.md",
        state: "absent",
        matchesPackaged: false,
        removed: false,
      },
    });
    expect(readFileSync(join(cwd, "CLAUDE.md"), "utf8")).toBe(block);
    expect(existsSync(join(cwd, "AGENTS.md"))).toBe(false);

    const codex = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "codex",
      "--json",
    );
    expect(codex.json.data.document).toBe("AGENTS.md");
    expect(readFileSync(join(cwd, "AGENTS.md"), "utf8")).toBe(block);
  });

  test("carries user prose and a peer's block through byte for byte", async () => {
    const cwd = checkout();
    const mine = "# House rules\n\nRun the tests before you push.\n";
    const peer = "<!-- lore:begin -->\nLore's own block.\n<!-- lore:end -->\n";
    writeFileSync(join(cwd, "CLAUDE.md"), `${mine}\n${peer}`);
    const result = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(result.json.data.status).toBe("updated");
    expect(readFileSync(join(cwd, "CLAUDE.md"), "utf8")).toBe(
      `${mine}\n${peer}\n${block}`,
    );
  });

  test("refreshes a stale block in place and reports a second run as unchanged", async () => {
    const cwd = checkout();
    writeFileSync(
      join(cwd, "CLAUDE.md"),
      `# House rules\n\n${managedBlockBegin}\nstale text\n${managedBlockEnd}\n`,
    );
    const refreshed = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(refreshed.json.data.status).toBe("updated");
    expect(readFileSync(join(cwd, "CLAUDE.md"), "utf8")).toBe(
      `# House rules\n\n${block}`,
    );

    const bytes = readFileSync(join(cwd, "CLAUDE.md"));
    const again = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(again.json.data.status).toBe("unchanged");
    expect(readFileSync(join(cwd, "CLAUDE.md")).equals(bytes)).toBe(true);

    const inText = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
    );
    expect(inText.stdout).toContain("nothing changed");
  });

  test("refuses an instruction file that is a link out of the checkout", async () => {
    const outside = join(root, "outside.md");
    writeFileSync(outside, "# Not Ward's file\n");
    const cwd = checkout();
    symlinkSync(outside, join(cwd, "CLAUDE.md"));
    const result = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(result.error.code).toBe("project_path_unsafe");
    expect(readFileSync(outside, "utf8")).toBe("# Not Ward's file\n");
    expect(readlinkSync(join(cwd, "CLAUDE.md"))).toBe(outside);
  });

  test("needs no vault: the command runs with no vault directory at all", async () => {
    const cwd = checkout();
    await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(existsSync(join(cwd, "no-vault"))).toBe(false);
  });
});

describe("ward agents usage", () => {
  test("names exactly one of the two forms", async () => {
    const cwd = checkout();
    const neither = await ward(cwd, "agents", "--target", "claude", "--json");
    expect(neither.exitCode).toBe(exitCodes.usage);
    expect(neither.error.code).toBe("agent_form_invalid");

    const both = await ward(
      cwd,
      "agents",
      "--check",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(both.exitCode).toBe(exitCodes.usage);
    expect(both.error.code).toBe("agent_form_invalid");
  });

  test("refuses --require-installed on the writing form instead of ignoring it", async () => {
    const cwd = checkout();
    const result = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--require-installed",
      "--target",
      "claude",
      "--json",
    );
    expect(result.exitCode).toBe(exitCodes.usage);
    expect(result.error.code).toBe("agent_option_unexpected");
    expect(existsSync(join(cwd, "CLAUDE.md"))).toBe(false);
  });

  test("requires a known target and echoes no value", async () => {
    const cwd = checkout();
    const missing = await ward(cwd, "agents", "--check", "--json");
    expect(missing.exitCode).toBe(exitCodes.usage);
    expect(missing.error.code).toBe("agent_target_unknown");

    const unknown = await ward(
      cwd,
      "agents",
      "--check",
      "--target",
      "gemini",
      "--json",
    );
    expect(unknown.exitCode).toBe(exitCodes.usage);
    expect(unknown.error.code).toBe("agent_target_unknown");
    expect(JSON.stringify(unknown.error)).not.toContain("gemini");
  });

  test("refuses --force on the checking form instead of ignoring it", async () => {
    const cwd = checkout();
    const result = await ward(
      cwd,
      "agents",
      "--check",
      "--force",
      "--target",
      "claude",
      "--json",
    );
    expect(result.exitCode).toBe(exitCodes.usage);
    expect(result.error.code).toBe("agent_option_unexpected");
  });

  test("the manifest declares the command as writing files and opening no vault", async () => {
    const cwd = checkout();
    const manifest = await ward(cwd, "manifest", "--json");
    const agents = manifest.json.data.commands.find(
      (command: { name: string }) => command.name === "agents",
    );
    expect(agents).toBeDefined();
    expect(agents.mutates).toBe(true);
    expect(agents.unlocksVault).toBe(false);
    expect(agents.kind).toBe("agents.status");
    expect(agents.resultKinds).toEqual(["agents.updated"]);
  });
});

describe("the local skill file (DEC-47)", () => {
  function skillPath(cwd: string, host: "claude" | "codex"): string {
    return host === "claude"
      ? join(cwd, ".claude", "skills", "ward", "SKILL.md")
      : join(cwd, ".agents", "skills", "ward", "SKILL.md");
  }

  function plant(cwd: string, host: "claude" | "codex", content: string) {
    const path = skillPath(cwd, host);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    return path;
  }

  test("the packaged skill is embedded in the build, and is not empty", () => {
    // The comparison below rests on this constant being the real file. If
    // the text import ever resolved to nothing, every empty file would
    // "exactly match the packaged skill" and --force would remove files it
    // must never touch, so this is asserted rather than assumed.
    expect(packagedSkillContent.length).toBeGreaterThan(0);
    expect(packagedSkillContent).toContain("name: ward");
  });

  test("a present copy is drift: --check exits 6 and names the path", async () => {
    const cwd = checkout();
    plant(cwd, "claude", packagedSkillContent);
    const result = await ward(
      cwd,
      "agents",
      "--check",
      "--target",
      "claude",
      "--json",
    );
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(result.json.data.skill).toEqual({
      document: ".claude/skills/ward/SKILL.md",
      state: "present",
      matchesPackaged: true,
    });

    // The pair: the same checkout's other host has no copy, and passes.
    const bare = await ward(
      cwd,
      "agents",
      "--check",
      "--target",
      "codex",
      "--json",
    );
    expect(bare.exitCode).toBe(exitCodes.success);
    expect(bare.json.data.skill).toEqual({
      document: ".agents/skills/ward/SKILL.md",
      state: "absent",
      matchesPackaged: false,
    });
  });

  test("--force removes a copy that exactly matches the packaged skill", async () => {
    const cwd = checkout();
    const path = plant(cwd, "claude", packagedSkillContent);
    const result = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--force",
      "--target",
      "claude",
      "--json",
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.json.data.skill).toEqual({
      document: ".claude/skills/ward/SKILL.md",
      state: "absent",
      matchesPackaged: true,
      removed: true,
    });
    expect(existsSync(path)).toBe(false);
    expect(readFileSync(join(cwd, "CLAUDE.md"), "utf8")).toBe(block);
  });

  test("--force never removes a differing file, and says why", async () => {
    const cwd = checkout();
    const path = plant(cwd, "claude", "# my own notes\n");
    const result = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--force",
      "--target",
      "claude",
      "--json",
    );
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.json.data.skill.removed).toBe(false);
    expect(result.json.data.skill.matchesPackaged).toBe(false);
    expect(existsSync(path)).toBe(true);
    expect(readFileSync(path, "utf8")).toBe("# my own notes\n");
  });

  test("an exact copy stays without --force", async () => {
    const cwd = checkout();
    const path = plant(cwd, "claude", packagedSkillContent);
    const plain = await ward(
      cwd,
      "agents",
      "--update-instructions",
      "--target",
      "claude",
      "--json",
    );
    expect(plain.exitCode).toBe(exitCodes.success);
    expect(plain.json.data.skill).toEqual({
      document: ".claude/skills/ward/SKILL.md",
      state: "present",
      matchesPackaged: true,
      removed: false,
    });
    expect(existsSync(path)).toBe(true);
  });

  test("the check names the healthy absence of a path it looked at", async () => {
    const cwd = checkout();
    const result = await ward(cwd, "agents", "--check", "--target", "codex");
    expect(result.stdout).toContain(".agents/skills/ward/SKILL.md");
    expect(result.stdout).toContain("ships from the opum-ward plugin");
  });
});
