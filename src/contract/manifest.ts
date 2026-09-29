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

// The agent hosts Ward writes a guidance block for (spec §11.2).
export type AgentTarget = "claude" | "codex";

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
    name: "init",
    summary:
      "Create this repository's Ward project manifest, add Ward's guidance block to CLAUDE.md and/or AGENTS.md, and register this checkout with the developer's vault. Registration is confirmed by the developer in an interactive terminal; --no-register prepares the project files without granting access.",
    args: [],
    flags: [
      {
        name: "--no-register",
        takesValue: false,
        summary:
          "Prepare the project files without registering this checkout, so it gains no access to the project's secrets. Safe for agent-driven preparation.",
      },
      {
        name: "--claude",
        takesValue: false,
        summary: "Add or refresh Ward's block in CLAUDE.md.",
      },
      {
        name: "--codex",
        takesValue: false,
        summary: "Add or refresh Ward's block in AGENTS.md.",
      },
      jsonFlag,
    ],
    kind: "init.complete",
    mutates: true,
    // Registration reads the encrypted vault; --no-register does not, but
    // the declaration covers what the command can do.
    unlocksVault: true,
    // Not marked admin: spec §8 names `ward init --no-register --claude
    // --codex` as agent-driven preparation. What holds the line is the
    // interactive terminal a registration needs, not a label here.
    admin: false,
    outputSensitivity: "metadata",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
      exitCodes.denied,
      exitCodes.conflict,
      exitCodes.validation,
      exitCodes.indeterminate,
    ],
    examples: [
      "ward init --no-register",
      "ward init --no-register --claude --codex",
    ],
  },
  {
    name: "status",
    summary:
      "Report this checkout's project, binding, vault and key-provider state, for the current project only, without changing anything.",
    args: [],
    flags: [jsonFlag],
    kind: "status.report",
    mutates: false,
    // Reads the vault header, the vault key and the decrypted state; writes
    // nothing.
    unlocksVault: true,
    admin: false,
    outputSensitivity: "status",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
    ],
    examples: ["ward status", "ward status --json"],
  },
  {
    name: "doctor",
    summary:
      "Run read-only health checks over the vault location, the key provider, document versions, this checkout's binding and the agent instruction blocks; exit 6 when a check fails.",
    args: [],
    flags: [jsonFlag],
    kind: "doctor.report",
    mutates: false,
    unlocksVault: true,
    admin: false,
    outputSensitivity: "status",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
      exitCodes.validation,
    ],
    examples: ["ward doctor", "ward doctor --json"],
  },
  {
    name: "backup",
    summary:
      "Create one passphrase-encrypted backup of the vault, in a trusted terminal. The backup opens without this machine's OS credential store item, and Ward neither keeps nor prints the passphrase.",
    args: [],
    flags: [
      {
        name: "--output",
        takesValue: true,
        summary:
          "The file to create. Must not already exist, and is created readable only by you.",
      },
      jsonFlag,
    ],
    kind: "backup.complete",
    mutates: true,
    unlocksVault: true,
    admin: true,
    outputSensitivity: "metadata",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
      exitCodes.denied,
      exitCodes.conflict,
      exitCodes.validation,
    ],
    examples: ["ward backup --output ward-backup.json"],
  },
  {
    name: "restore",
    summary:
      "Restore a backup into an empty vault directory under a fresh vault key and a fresh vault id, with every checkout binding cleared pending explicit re-registration. Run it yourself, in a trusted terminal.",
    args: [],
    flags: [
      {
        name: "--input",
        takesValue: true,
        summary: "The backup file to open.",
      },
      jsonFlag,
    ],
    kind: "restore.complete",
    mutates: true,
    unlocksVault: true,
    admin: true,
    outputSensitivity: "metadata",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
      exitCodes.denied,
      exitCodes.conflict,
      exitCodes.validation,
      exitCodes.indeterminate,
    ],
    examples: ["ward restore --input ward-backup.json"],
  },
  {
    name: "secret",
    summary:
      "Set, list, inspect or delete this project's secrets. A value is entered hidden in a trusted terminal, or piped with --stdin for trusted automation; it is never an argument and never printed. Setting and deleting are the developer's acts.",
    args: [
      { name: "action", required: true },
      { name: "alias", required: false },
    ],
    flags: [
      {
        name: "--stdin",
        takesValue: false,
        summary:
          "Read the value from standard input to EOF as exact bytes. For trusted automation; replaces an existing alias without an interactive prompt. Not a way for an agent to request or handle a real value.",
      },
      jsonFlag,
    ],
    kind: "secret.set",
    resultKinds: ["secret.list", "secret.inspect", "secret.delete"],
    mutates: true,
    // Reads and writes the encrypted vault through the project binding.
    unlocksVault: true,
    // Not marked admin: listing and inspecting are safe for an agent, and
    // what holds the line on entry is the hidden terminal a value needs,
    // not a label here (the same reasoning `ward init` records).
    admin: false,
    outputSensitivity: "metadata",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.notFound,
      exitCodes.denied,
      exitCodes.conflict,
      exitCodes.validation,
      exitCodes.indeterminate,
    ],
    examples: [
      "ward secret set example-alias",
      "ward secret list",
      "ward secret inspect example-alias",
      "ward secret delete example-alias",
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
