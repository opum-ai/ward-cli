import { type ExitCode, exitCodes, type ResultKind } from "./envelope.ts";

export interface ArgumentSpec {
  name: string;
  required: boolean;
}

export interface FlagSpec {
  name: `--${string}`;
  takesValue: boolean;
  summary: string;
}

// How sensitive a command's successful output is. Every P0 command is one of
// these; no command's output class is "secret", because none returns a value.
export type OutputSensitivity = "public" | "metadata" | "status";

export interface CommandSpec {
  name: string;
  summary: string;
  args: ArgumentSpec[];
  flags: FlagSpec[];
  kind: ResultKind;
  mutates: boolean;
  // True when the command reads or decrypts the user vault. A command with
  // `unlocksVault: false` must never resolve ~/.ward/ or the key provider.
  unlocksVault: boolean;
  // True when the command must be run by the developer in a trusted terminal,
  // never by an agent on its own behalf.
  admin: boolean;
  outputSensitivity: OutputSensitivity;
  exitCodes: ExitCode[];
  examples: string[];
}

const jsonFlag: FlagSpec = {
  name: "--json",
  takesValue: false,
  summary: "Print the result envelope as JSON.",
};

export const commands: CommandSpec[] = [
  {
    name: "manifest",
    summary:
      "Describe Ward's commands, flags, exit codes and output sensitivity without unlocking the vault.",
    args: [],
    flags: [jsonFlag],
    kind: "manifest.registry",
    mutates: false,
    unlocksVault: false,
    admin: false,
    outputSensitivity: "public",
    exitCodes: [exitCodes.success, exitCodes.usage],
    examples: ["ward manifest --json"],
  },
  {
    name: "instructions",
    summary:
      "Print agent guidance for credential-dependent work without unlocking the vault.",
    args: [{ name: "topic", required: false }],
    flags: [
      {
        name: "--list",
        takesValue: false,
        summary: "List the available topics.",
      },
      jsonFlag,
    ],
    kind: "instructions.topic",
    mutates: false,
    unlocksVault: false,
    admin: false,
    outputSensitivity: "public",
    exitCodes: [exitCodes.success, exitCodes.usage, exitCodes.notFound],
    examples: [
      "ward instructions",
      "ward instructions agent-rules",
      "ward instructions --list",
    ],
  },
  {
    name: "help",
    summary: "Show usage for Ward or one command.",
    args: [{ name: "command", required: false }],
    flags: [jsonFlag],
    kind: "help.usage",
    mutates: false,
    unlocksVault: false,
    admin: false,
    outputSensitivity: "public",
    exitCodes: [exitCodes.success, exitCodes.usage],
    examples: ["ward help", "ward help instructions"],
  },
];

export function findCommand(name: string): CommandSpec | undefined {
  return commands.find((command) => command.name === name);
}

export function usageLine(command: CommandSpec): string {
  const args = command.args.map((arg) =>
    arg.required ? `<${arg.name}>` : `[${arg.name}]`,
  );
  const flags = command.flags.map((flag) =>
    flag.takesValue ? `[${flag.name} <value>]` : `[${flag.name}]`,
  );
  return ["ward", command.name, ...args, ...flags].join(" ");
}
