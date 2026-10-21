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
    name: "agents",
    summary:
      "Judge or refresh Ward's own guidance block in one agent host's instruction file (CLAUDE.md for claude, AGENTS.md for codex), and judge the host's local skill path, where Ward writes nothing and a found file is drift. Reads no vault.",
    args: [],
    flags: [
      {
        name: "--check",
        takesValue: false,
        summary:
          "Report whether the block is absent, stale or current, and whether a local skill file is present, without changing a file. Stale or malformed guidance, or a present local skill file, exits 6.",
      },
      {
        name: "--require-installed",
        takesValue: false,
        summary:
          "With --check: make an absent block exit 6 as well, for a checkout that has adopted the bridge.",
      },
      {
        name: "--update-instructions",
        takesValue: false,
        summary:
          "Add or refresh the block, leaving every other byte of the file as it was.",
      },
      {
        name: "--force",
        takesValue: false,
        summary:
          "With --update-instructions: remove the local skill file at the target's skill path when its bytes exactly match the packaged skill. A differing file is reported, never removed.",
      },
      {
        name: "--target",
        takesValue: true,
        summary: "Which host to act on: claude or codex. Required.",
      },
      jsonFlag,
    ],
    kind: "agents.status",
    resultKinds: ["agents.updated"],
    // Only --update-instructions writes, and it writes one instruction file -
    // plus, under --force, removes a local skill file whose bytes exactly
    // match the packaged skill; --check changes nothing. `mutates` describes
    // what a caller would be authorizing, which for this command is files
    // nobody's access depends on.
    mutates: true,
    unlocksVault: false,
    // Not admin: the block is public guidance, and preparing a checkout for
    // agent work is the whole point of a bridge. Nothing here grants access;
    // that is `ward init`'s registration, in a terminal.
    admin: false,
    outputSensitivity: "public",
    exitCodes: [
      exitCodes.success,
      exitCodes.uncaught,
      exitCodes.usage,
      exitCodes.conflict,
      exitCodes.validation,
    ],
    // Only the read-only form appears here, and that is a constraint rather
    // than a preference: non-disclosure.test.ts runs every example of every
    // command that does not unlock the vault, in this repository's own root,
    // and requires it to exit 0. An example that writes would create an
    // instruction file in the checkout running the suite, and one with
    // --require-installed would fail on this repository, which has not
    // adopted the bridge. The writing form is documented by its flag above.
    examples: ["ward agents --check --target claude"],
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
      "Create this repository's Ward project manifest, add Ward's guidance block to CLAUDE.md and/or AGENTS.md, and register this checkout with the developer's vault. On an interactive terminal with no target flag, which files to write is a multiselect; --claude/--codex, --json or a non-terminal run take the non-interactive path instead. Registration is confirmed by the developer in an interactive terminal; --no-register prepares the project files without granting access.",
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
        summary:
          "Add or refresh Ward's block in CLAUDE.md, and skip the interactive file choice.",
      },
      {
        name: "--codex",
        takesValue: false,
        summary:
          "Add or refresh Ward's block in AGENTS.md, and skip the interactive file choice.",
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
    name: "audit",
    summary:
      "Report this project's retained operational events, sanitized, for the current project only, with the vault's retention bound stated rather than left to discover; read-only, and not a tamper-proof audit claim.",
    args: [],
    flags: [jsonFlag],
    kind: "audit.report",
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
      exitCodes.denied,
      exitCodes.conflict,
      exitCodes.validation,
      exitCodes.indeterminate,
    ],
    examples: ["ward audit", "ward audit --json"],
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
      "Set, list, inspect or delete this project's secrets, or grant one to another project for use only and revoke the grant. A value is entered hidden in a trusted terminal, or piped with --stdin for trusted automation; it is never an argument and never printed. Setting, deleting and granting are the developer's acts, and a granted alias is use-only in the project that receives it.",
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
      {
        name: "--to",
        takesValue: true,
        summary:
          "With grant: the id of the target project, which must already be registered in this vault. One owner secret, one target project; there is no wildcard.",
      },
      {
        name: "--as",
        takesValue: true,
        summary:
          "With grant: the alias the target project will use for the secret. Refused if the target already has a secret or grant under it.",
      },
      {
        name: "--from",
        takesValue: true,
        summary:
          "With revoke: the id of the target project whose grant of this secret to revoke. Blocks runs admitted afterwards; it recalls nothing already sent and revokes nothing at the provider.",
      },
      jsonFlag,
    ],
    kind: "secret.set",
    resultKinds: [
      "secret.list",
      "secret.inspect",
      "secret.delete",
      "secret.grant",
      "secret.revoke",
    ],
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
      "ward secret grant example-alias --to 7c1d9a52-3e84-4b6f-9a10-5d2e8f4b6c31 --as shared-alias",
      "ward secret revoke example-alias --from 7c1d9a52-3e84-4b6f-9a10-5d2e8f4b6c31",
    ],
  },
  {
    name: "profile",
    summary:
      "List this project's HTTPS profiles, or approve and revoke one. A manifest declares a request; the developer's approval, given in a trusted terminal, is what authorizes an operation.",
    args: [
      { name: "action", required: true },
      { name: "name", required: false },
    ],
    flags: [jsonFlag],
    kind: "profile.list",
    resultKinds: ["profile.approve", "profile.revoke"],
    mutates: true,
    unlocksVault: true,
    // Not marked admin: listing is safe for an agent, and what holds the line
    // on approving or revoking is the interactive terminal the question needs
    // (the same reasoning `ward init` and `ward secret` record).
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
      "ward profile list",
      "ward profile approve example-profile",
      "ward profile revoke example-profile",
    ],
  },
  {
    name: "check",
    summary:
      "Report whether this checkout is ready to run a declared profile — the binding, the approval and the stored credential — with no network I/O. Exit 6 when it is not ready.",
    args: [{ name: "profile", required: false }],
    flags: [jsonFlag],
    kind: "check.report",
    mutates: false,
    unlocksVault: true,
    admin: false,
    outputSensitivity: "status",
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
    examples: ["ward check", "ward check example-profile"],
  },
  {
    name: "run",
    summary:
      "Execute exactly the operation this checkout approved for a profile and report a status-only outcome. Ward sends the approved snapshot, follows no redirect, retries nothing on its own, connects only to a public destination, and returns no body, header or upstream message.",
    args: [{ name: "profile", required: true }],
    flags: [
      jsonFlag,
      {
        name: "--actor-label",
        takesValue: true,
        summary:
          "Record what the caller asserts about who it is, on this run's audit events. Bounded by the alias grammar; self-asserted correlation metadata, never authorization.",
      },
      {
        name: "--task-label",
        takesValue: true,
        summary:
          "Record what the caller asserts about what this run belongs to, on this run's audit events. Bounded by the alias grammar; self-asserted correlation metadata, never authorization.",
      },
    ],
    kind: "run.result",
    // It writes the run's own admission and completion events and changes
    // nothing else: no credential is created, changed or deleted by a run,
    // and the profile's approval and snapshot are read and not rewritten.
    // `mutates` describes what a caller would be authorizing, and a run
    // authorizes an external operation rather than a change to this vault.
    mutates: false,
    unlocksVault: true,
    // Not admin. Spec §15's vertical slice ends at an agent performing
    // `ward run`, and what holds the line on authority is upstream of it:
    // the developer's approval, checked against the stored snapshot before a
    // byte is sent.
    admin: false,
    outputSensitivity: "status",
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
      "ward run example-profile",
      "ward run example-profile --json",
      "ward run example-profile --actor-label example-agent --task-label example-task",
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
