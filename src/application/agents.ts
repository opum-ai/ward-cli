// `ward agents`: judge and maintain Ward's own managed block in one agent
// host's instruction file (spec §8's two rows, spec §11.2). Nothing here
// reads the vault or needs a key: the block is public guidance, and the
// project-files port allows exactly the document this target names, refusing
// a path that is a link out of the checkout.
//
// What is deliberately NOT here is the other half of spec §8's row, "and
// selected local skill files". How a local skill file is explicitly selected
// - a flag, a key in `.ward/project.json`, or host-plugin detection - is an
// open design question on WCLI-14, and the answer decides a tracked project
// document's schema. This command therefore writes and judges the block and
// says so, rather than inventing a selection and shipping it as a contract.
//
// The exit-code shape is the fleet's, taken from `quest agents` rather than
// invented: absence is reported and not failed, because a checkout without a
// bridge is a legitimate state (spec §11.2 calls the local bridge explicitly
// selected, and `ward init` may run without one); `--require-installed` is
// what makes absence a failure for a caller that has adopted the bridge, and
// stale or malformed guidance always fails, because those are contradictions
// rather than configurations. A file Ward refuses to touch at all - a link
// out of the checkout - still raises the catalogue's own error, because that
// is a refusal to act on a path rather than a state of the block.
import type { ExitCode } from "../contract/envelope.ts";
import { exitCodes } from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import type { AgentTarget } from "../contract/manifest.ts";
import {
  type ManagedBlockUpdate,
  managedBlockStatus,
  upsertManagedBlock,
} from "../domain/managed-block.ts";
import { agentTargetDocuments, wardBlockBody } from "./bridges.ts";
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

export interface AgentBridgeReport {
  readonly target: AgentTarget;
  readonly document: string;
  // Whether the file itself exists, kept separate from the block's state:
  // "no file" and "a file with no Ward block" are different sentences, and
  // one boolean is cheaper than a reader inferring it from the other field.
  readonly fileExists: boolean;
  readonly state: AgentBridgeState;
}

export interface AgentBridgeApplied {
  readonly target: AgentTarget;
  readonly document: string;
  readonly status: ManagedBlockUpdate["status"];
}

export const agentTargets: readonly AgentTarget[] = ["claude", "codex"];

export function isAgentTarget(value: string): value is AgentTarget {
  return (agentTargets as readonly string[]).includes(value);
}

export function checkAgentBridge(
  target: AgentTarget,
  files: ProjectFiles,
  options: { requireInstalled: boolean },
): { data: AgentBridgeReport; text: string; exitCode: ExitCode } {
  const document = agentTargetDocuments[target];
  const path = projectDocumentPaths[document];
  const stored = files.read(document);
  const state = blockState(stored ?? "");
  const data: AgentBridgeReport = {
    target,
    document: path,
    fileExists: stored !== undefined,
    state,
  };
  return {
    data,
    text: checkText(data),
    exitCode: stateExitCode(state, options.requireInstalled),
  };
}

export function updateAgentBridge(
  target: AgentTarget,
  files: ProjectFiles,
): { data: AgentBridgeApplied; text: string } {
  const document: ProjectDocument = agentTargetDocuments[target];
  const path = projectDocumentPaths[document];
  // Malformed markers raise here, from the same lookup the check reports:
  // upsertManagedBlock refuses a file whose markers are incomplete,
  // duplicated or out of order rather than guessing which pair was meant.
  const update = upsertManagedBlock(files.read(document) ?? "", wardBlockBody);
  // A block already matching this build's bytes is not rewritten: the file's
  // modification time is a fact other tools read, and an unchanged write is
  // how a refresh starts showing up in diffs nobody made.
  if (update.status !== "unchanged") files.write(document, update.text);
  const data: AgentBridgeApplied = {
    target,
    document: path,
    status: update.status,
  };
  return { data, text: updateText(data) };
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

function checkText(report: AgentBridgeReport): string {
  const { document, fileExists, state, target } = report;
  const repair = `Run \`ward agents --update-instructions --target ${target}\`.`;
  switch (state) {
    case "current":
      return `${document} carries Ward's guidance block, and it is current.`;
    case "stale":
      return `${document}'s Ward guidance block is not the one this build writes. ${repair}`;
    case "malformed":
      return `${document}'s Ward block markers are incomplete, duplicated or out of order, so Ward cannot judge the block. ${repair}`;
    case "absent":
      return [
        fileExists
          ? `${document} carries no Ward guidance block.`
          : `${document} does not exist, so it carries no Ward guidance block.`,
        repair,
      ].join("\n");
  }
}

function updateText(applied: AgentBridgeApplied): string {
  switch (applied.status) {
    case "created":
      return `Added Ward's guidance block to ${applied.document}.`;
    case "updated":
      return `Refreshed Ward's guidance block in ${applied.document}.`;
    case "unchanged":
      return `${applied.document} already carries the current block; nothing changed.`;
  }
}
