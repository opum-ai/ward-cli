// `ward agents`: judge and maintain Ward's own managed block in one agent
// host's instruction file (spec §8's two rows, spec §11.2). Nothing here
// reads the vault or needs a key: the block is public guidance, and the
// project-files port allows exactly the documents this target names, refusing
// a path that is a link out of the checkout.
//
// The skill half of spec §8's row is answered by DEC-44 and DEC-47: the skill
// ships from the opum-ward plugin and Ward writes no local skill file, so a
// file found at either host's skill path is drift rather than something to
// maintain - it is reported, never refreshed, and `--force` removes it only
// when its bytes are exactly the packaged skill's, the same rule
// `quest agents` applies to an orphaned copy (ADR 0015). The bytes compared
// against arrive through `packagedSkill` rather than being read here, so this
// module stays free of the bundler's asset import and a test can hand it any
// content.
//
// The exit-code shape is the fleet's, taken from `quest agents` rather than
// invented: absence is reported and not failed, because a checkout without a
// bridge is a legitimate state (spec §11.2 calls the local bridge explicitly
// selected, and `ward init` may run without one); `--require-installed` is
// what makes absence a failure for a caller that has adopted the bridge, and
// stale or malformed guidance always fails, because those are contradictions
// rather than configurations. A present local skill file fails for the same
// reason, and unlike the block it is not an option to install. A file Ward
// refuses to touch at all - a link out of the checkout - still raises the
// catalogue's own error, because that is a refusal to act on a path rather
// than a state of the block.
import type { ExitCode } from "../contract/envelope.ts";
import { exitCodes } from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import type { AgentTarget } from "../contract/manifest.ts";
import {
  type ManagedBlockUpdate,
  managedBlockStatus,
  upsertManagedBlock,
} from "../domain/managed-block.ts";
import {
  agentTargetDocuments,
  agentTargetSkillDocuments,
  wardBlockBody,
} from "./bridges.ts";
import {
  type ProjectDocument,
  type ProjectFiles,
  projectDocumentPaths,
} from "./project-files.ts";

// The three states spec §8's row names, plus the one the marker grammar has
// a distinct answer for. "malformed" is a state rather than a raised conflict
// here, the way `ward doctor` reports the same file, because a check answers
// about a repository and a caller reading `--json` should get the state it
// asked about; the writer raises the conflict instead, because it will not
// write a file it cannot judge.
export type AgentBridgeState = "absent" | "current" | "stale" | "malformed";

// A local skill file is either not there - the healthy state, because the
// skill ships from the plugin (DEC-44) - or present, which is drift: Ward
// writes no local skill file at all. `matchesPackaged` says whether a present
// copy is byte-for-byte the file the plugin ships, which is the only copy
// `--force` will remove (DEC-47).
export type AgentSkillState = "absent" | "present";

export interface AgentSkillReport {
  readonly document: string;
  readonly state: AgentSkillState;
  readonly matchesPackaged: boolean;
}

export interface AgentSkillUpdateReport extends AgentSkillReport {
  // True only when this run removed the file; the state is then "absent".
  readonly removed: boolean;
}

export interface AgentBridgeReport {
  readonly target: AgentTarget;
  readonly document: string;
  // Whether the file itself exists, kept separate from the block's state:
  // "no file" and "a file with no Ward block" are different sentences, and
  // one boolean is cheaper than a reader inferring it from the other field.
  readonly fileExists: boolean;
  readonly state: AgentBridgeState;
  readonly skill: AgentSkillReport;
}

export interface AgentBridgeApplied {
  readonly target: AgentTarget;
  readonly document: string;
  readonly status: ManagedBlockUpdate["status"];
  readonly skill: AgentSkillUpdateReport;
}

export const agentTargets: readonly AgentTarget[] = ["claude", "codex"];

export function isAgentTarget(value: string): value is AgentTarget {
  return (agentTargets as readonly string[]).includes(value);
}

export function checkAgentBridge(
  target: AgentTarget,
  files: ProjectFiles,
  options: { requireInstalled: boolean; packagedSkill: string },
): { data: AgentBridgeReport; text: string; exitCode: ExitCode } {
  const document = agentTargetDocuments[target];
  const path = projectDocumentPaths[document];
  const stored = files.read(document);
  const state = blockState(stored ?? "");
  const skill = skillState(target, files, options.packagedSkill);
  const data: AgentBridgeReport = {
    target,
    document: path,
    fileExists: stored !== undefined,
    state,
    skill,
  };
  return {
    data,
    text: checkText(data),
    // A present local skill file fails regardless of --require-installed,
    // the way stale or malformed guidance does: it is a contradiction, not a
    // configuration a caller may choose not to have.
    exitCode:
      skill.state === "present"
        ? exitCodes.validation
        : stateExitCode(state, options.requireInstalled),
  };
}

export function updateAgentBridge(
  target: AgentTarget,
  files: ProjectFiles,
  options: { force: boolean; packagedSkill: string },
): { data: AgentBridgeApplied; text: string } {
  const document: ProjectDocument = agentTargetDocuments[target];
  const path = projectDocumentPaths[document];
  // Malformed markers raise here, from the same lookup the check reports:
  // upsertManagedBlock refuses a file whose markers are incomplete,
  // duplicated or out of order rather than guessing which pair was meant.
  // The removal below therefore never runs on a file Ward refused to judge.
  const update = upsertManagedBlock(files.read(document) ?? "", wardBlockBody);
  // A block already matching this build's bytes is not rewritten: the file's
  // modification time is a fact other tools read, and an unchanged write is
  // how a refresh starts showing up in diffs nobody made.
  if (update.status !== "unchanged") files.write(document, update.text);

  const skill = skillState(target, files, options.packagedSkill);
  // Only a copy whose bytes are exactly the packaged skill is removed, and
  // only when --force asked: a hand-edited file is reported and left alone,
  // the rule `quest agents --force` applies to an orphaned copy (DEC-47).
  const removed =
    skill.state === "present" && options.force && skill.matchesPackaged;
  if (removed) files.remove(agentTargetSkillDocuments[target]);
  const skillUpdate: AgentSkillUpdateReport = {
    ...skill,
    state: removed ? "absent" : skill.state,
    removed,
  };
  const data: AgentBridgeApplied = {
    target,
    document: path,
    status: update.status,
    skill: skillUpdate,
  };
  return { data, text: updateText(data) };
}

function skillState(
  target: AgentTarget,
  files: ProjectFiles,
  packagedSkill: string,
): AgentSkillReport {
  const document = agentTargetSkillDocuments[target];
  const content = files.read(document);
  return {
    document: projectDocumentPaths[document],
    state: content === undefined ? "absent" : "present",
    matchesPackaged: content !== undefined && content === packagedSkill,
  };
}

function blockState(text: string): AgentBridgeState {
  try {
    return managedBlockStatus(text, wardBlockBody);
  } catch (error) {
    if (
      error instanceof WardError &&
      error.code === "instructions_markers_conflict"
    )
      return "malformed";
    throw error;
  }
}

function stateExitCode(
  state: AgentBridgeState,
  requireInstalled: boolean,
): ExitCode {
  switch (state) {
    case "current":
      return exitCodes.success;
    case "absent":
      // The reported state carries the answer either way; the flag decides
      // whether a caller wants absence to stop it.
      return requireInstalled ? exitCodes.validation : exitCodes.success;
    case "stale":
    case "malformed":
      return exitCodes.validation;
  }
}

// What the skill half of the check says. The healthy state is named rather
// than implied, so a reader can see which path was looked at - the same
// reason the summary of `clean:temp` reports what it scanned.
function skillCheckLine(skill: AgentSkillReport, target: AgentTarget): string {
  if (skill.state === "absent")
    return `No local skill file at ${skill.document}; the skill ships from the opum-ward plugin.`;
  const drift = `${skill.document} exists, but Ward writes no local skill file - the skill ships from the opum-ward plugin - so this is drift.`;
  return skill.matchesPackaged
    ? `${drift} It exactly matches the packaged skill: delete it, or run \`ward agents --update-instructions --target ${target} --force\` to remove it.`
    : `${drift} Its bytes differ from the packaged skill, so \`--force\` will not remove it; delete it by hand if it should not be there.`;
}

function checkText(report: AgentBridgeReport): string {
  const { document, fileExists, state, target } = report;
  const repair = `Run \`ward agents --update-instructions --target ${target}\`.`;
  const block =
    state === "current"
      ? `${document} carries Ward's guidance block, and it is current.`
      : state === "stale"
        ? `${document}'s Ward guidance block is not the one this build writes. ${repair}`
        : state === "malformed"
          ? `${document}'s Ward block markers are incomplete, duplicated or out of order, so Ward cannot judge the block. ${repair}`
          : [
              fileExists
                ? `${document} carries no Ward guidance block.`
                : `${document} does not exist, so it carries no Ward guidance block.`,
              repair,
            ].join("\n");
  return `${block}\n${skillCheckLine(report.skill, target)}`;
}

// What the writer says about the skill half. "absent" is silent only when it
// was absent all along; a removal is named, and a present file that stayed is
// named with the reason.
function skillUpdateLine(skill: AgentSkillUpdateReport): string | undefined {
  if (skill.removed)
    return `Removed the local skill file at ${skill.document}: its bytes exactly matched the packaged skill.`;
  if (skill.state === "absent") return undefined;
  return skill.matchesPackaged
    ? `${skill.document} exists and exactly matches the packaged skill; Ward writes no local skill file, and removing it needs --force.`
    : `${skill.document} exists and differs from the packaged skill; Ward writes no local skill file, and --force removes only an exact copy. Delete it by hand if it should not be there.`;
}

function updateText(applied: AgentBridgeApplied): string {
  const block =
    applied.status === "created"
      ? `Added Ward's guidance block to ${applied.document}.`
      : applied.status === "updated"
        ? `Refreshed Ward's guidance block in ${applied.document}.`
        : `${applied.document} already carries the current block; nothing changed.`;
  const skill = skillUpdateLine(applied.skill);
  return skill === undefined ? block : `${block}\n${skill}`;
}
