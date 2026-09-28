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
  // The result kind of the command's primary form.
  kind: ResultKind;
  // Kinds its other forms emit, such as `instructions --list`.
  resultKinds?: ResultKind[];
  mutates: boolean;
  // True when the command reads or decrypts the user vault. A command with
  // `unlocksVault: false` must never read or write ~/.ward/ or call the key
  // provider.
  unlocksVault: boolean;
  // True when the command must be run by the developer in a trusted terminal,
  // never by an agent on its own behalf.
  admin: boolean;
  outputSensitivity: OutputSensitivity;
  exitCodes: ExitCode[];
  examples: string[];
}

// Accepted by every command, so not repeated in each command's `flags`.
export const universalFlags: FlagSpec[] = [
  {
    name: "--help",
    takesValue: false,
    summary: "Show usage for this command.",
  },
];

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
    exitCodes: [exitCodes.success, exitCodes.uncaught, exitCodes.usage],
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
    resultKinds: ["instructions.list"],
    mutates: false,
    unlocksVault: false,
    admin: false,
    outputSensitivity: "public",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
    ],
    examples: [
      "ward instructions",
      "ward instructions agent-rules",
      "ward instructions --list",
    ],
  },
  {
    name: "setup",
    summary:
      "Create the vault key in the OS credential store and the encrypted vault. Run this once, yourself, in a trusted terminal; never on an agent's behalf.",
    args: [],
    flags: [jsonFlag],
    kind: "setup.complete",
    mutates: true,
    unlocksVault: true,
    admin: true,
    outputSensitivity: "metadata",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
      exitCodes.conflict,
      exitCodes.validation,
      exitCodes.indeterminate,
    ],
    examples: ["ward setup", "ward setup --json"],
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
    exitCodes: [exitCodes.success, exitCodes.uncaught, exitCodes.usage],
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
