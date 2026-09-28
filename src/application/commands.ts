import packageJson from "../../package.json" with { type: "json" };
import { exitCodes, type ResultKind } from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import {
  type CommandSpec,
  commands,
  findCommand,
  universalFlags,
  usageLine,
} from "../contract/manifest.ts";
import { findInstructionTopic, instructionTopics } from "./instructions.ts";

export interface CommandInput {
  positionals: string[];
  flags: ReadonlyMap<string, string | true>;
}

export interface CommandOutput {
  kind: ResultKind;
  data: unknown;
  text: string;
}

export type CommandHandler = (input: CommandInput) => CommandOutput;

export const version: string = packageJson.version;

function manifest(): CommandOutput {
  const data = { cli: "ward", version, exitCodes, universalFlags, commands };
  const text = commands
    .map((command) => `${usageLine(command)}\n  ${command.summary}`)
    .join("\n");
  return { kind: "manifest.registry", data, text };
}

function instructions(input: CommandInput): CommandOutput {
  if (input.flags.has("--list")) {
    if (input.positionals.length > 0)
      throw new WardError("unexpected_argument");
    const topics = instructionTopics.map(({ key, title }) => ({ key, title }));
    return {
      kind: "instructions.list",
      data: { topics },
      text: topics
        .map(({ key, title }) => `${key.padEnd(14)}${title}`)
        .join("\n"),
    };
  }
  // An unknown topic is not echoed: the lookup key came from argv.
  const topic = findInstructionTopic(input.positionals[0] ?? "overview");
  if (topic === undefined) throw new WardError("unknown_topic");
  return {
    kind: "instructions.topic",
    data: topic,
    text: `${topic.title}\n\n${topic.body}`,
  };
}

function commandUsage(command: CommandSpec): string {
  const all = [...command.flags, ...universalFlags];
  // Wide enough for the longest flag on this command, so a long one (init's
  // --no-register) cannot run into its own summary. 12 is every other
  // command's width, so this stays the layout they already print.
  const width = Math.max(12, ...all.map((flag) => flag.name.length + 2));
  const flags = all.map(
    (flag) => `  ${flag.name.padEnd(width)}${flag.summary}`,
  );
  return [
    usageLine(command),
    "",
    command.summary,
    "",
    "Options:",
    ...flags,
  ].join("\n");
}

function help(input: CommandInput): CommandOutput {
  const name = input.positionals[0];
  if (name === undefined) {
    const lines = commands.map(
      (command) => `  ${command.name.padEnd(14)}${command.summary}`,
    );
    return {
      kind: "help.usage",
      data: {
        version,
        commands: commands.map(({ name, summary }) => ({ name, summary })),
      },
      text: [
        `ward ${version}`,
        "",
        "Usage: ward <command> [options]",
        "",
        "Commands:",
        ...lines,
      ].join("\n"),
    };
  }
  const command = findCommand(name);
  if (command === undefined) throw new WardError("unknown_command");
  return { kind: "help.usage", data: { command }, text: commandUsage(command) };
}

export const handlers: Record<string, CommandHandler> = {
  manifest,
  instructions,
  help,
};
