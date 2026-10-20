import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { createBackupFiles } from "../adapters/backup-file.ts";
import { canonicalDirectory, locateCheckout } from "../adapters/checkout.ts";
import {
  createKeychainKeyProvider,
  keychainService,
} from "../adapters/keychain.ts";
import { observeMachine } from "../adapters/machine.ts";
import { createTerminalPassphrase } from "../adapters/passphrase.ts";
import { createProjectFiles } from "../adapters/project-files.ts";
import { createTerminalSecretValues } from "../adapters/secret-value.ts";
import { packagedSkillContent } from "../adapters/skill-content.ts";
import { acquireSetupSession } from "../adapters/setup-session.ts";
import { createHttpsTransport } from "../adapters/https-transport.ts";
import { createTerminalInstructionChoice } from "../adapters/init-prompt.ts";
import { createSqliteVaultStore } from "../adapters/sqlite-vault-store.ts";
import {
  createTerminalConsent,
  createTerminalGrantApprover,
  createTerminalProfileApprover,
  createTerminalUnregisterApprover,
} from "../adapters/terminal-consent.ts";
import type {
  UnregisterApprover,
  GrantApprover,
  ProfileApprover,
  RegistrationApprover,
} from "../application/approvals.ts";
import { runAudit } from "../application/audit.ts";
import {
  type PassphraseSource,
  runBackup,
  runRestore,
} from "../application/backup.ts";
import type { InstructionFileChooser } from "../application/instruction-choice.ts";
import {
  type CommandInput,
  type CommandOutput,
  handlers,
  version,
} from "../application/commands.ts";
import type { KeyProvider } from "../application/key-provider.ts";
import { initProject } from "../application/project.ts";
import { runCheck, runProfile } from "../application/profiles.ts";
import { runOperation } from "../application/run.ts";
import type { Transport } from "../application/transport.ts";
import {
  type ReportingOptions,
  runDoctor,
  runStatus,
} from "../application/reporting.ts";
import { runSetup } from "../application/setup.ts";
import { runUnregister } from "../application/unregister.ts";
import { runSecret, type SecretValueSource } from "../application/secrets.ts";
import {
  type ExitCode,
  exitCodeForErrorType,
  exitCodes,
  success,
} from "../contract/envelope.ts";
import { errorEnvelope, WardError } from "../contract/errors.ts";
import { type AgentTarget, findCommand } from "../contract/manifest.ts";
import {
  checkAgentBridge,
  isAgentTarget,
  updateAgentBridge,
} from "../application/agents.ts";
import { parseArguments } from "./parse.ts";

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: ExitCode;
  // The process must exit on its own rather than waiting for the event
  // loop to drain: a native credential-store call can stay pending after
  // its bound expired and keep the process alive (WCLI-5 review). Only the
  // entry point acts on this; in-process callers read it.
  exitExplicitly?: boolean;
}

export interface RunOptions {
  // Where the user vault lives. Defaults to ~/.ward; tests and callers
  // that must never touch the real vault override it.
  wardDirectory?: string;
  // The credential store the vault key lives in. Defaults to the platform
  // provider; tests and qualification probes override it.
  keyProvider?: KeyProvider;
  // The directory the command acts in. Defaults to the process's working
  // directory; tests resolve projects in a temporary checkout.
  cwd?: string;
  // Who answers Ward's registration question. Defaults to the terminal
  // prompt; tests supply an answer.
  approver?: RegistrationApprover;
  // Who answers `ward init`'s instruction-file multiselect, when the run
  // offers it (DEC-48/DEC-52: a terminal, no --claude/--codex, no --json).
  // Defaults to the terminal; tests supply a choice so no real terminal is
  // needed.
  instructionFiles?: InstructionFileChooser;
  // Where a backup passphrase comes from. Defaults to the terminal with echo
  // suppressed; tests and qualification probes supply one. There is no
  // option, argument or environment path to it, here or anywhere.
  passphrases?: PassphraseSource;
  // Where a secret value comes from: hidden terminal entry, exact bytes from
  // stdin, and the replacement question. Defaults to the terminal adapter;
  // tests supply one so no real terminal is needed. There is no option,
  // argument or environment path to a value, here or anywhere.
  secrets?: SecretValueSource;
  // Who answers Ward's approval question for an HTTPS profile. Defaults to
  // the terminal prompt; tests supply an answer.
  profileApprover?: ProfileApprover;
  // Who answers the question a secret grant asks. Defaults to the terminal
  // prompt; tests supply an answer.
  grantApprover?: GrantApprover;
  // Who answers the questions `ward unregister` asks. Defaults to the
  // terminal prompt; tests supply the answers.
  unregisterApprover?: UnregisterApprover;
  // The clock, for timestamps recorded in the vault.
  now?: () => Date;
  // The identifiers Ward writes into records it creates. Defaults to
  // `crypto.randomUUID`; tests supply a sequence so the ids they assert on
  // are the ids they expect.
  newId?: () => string;
  // The network client `ward run` sends through. Defaults to the in-process
  // HTTPS transport; tests substitute one, which is the only way a test can
  // reach a request path without a network. There is no command-line,
  // configuration or environment path to it.
  transport?: Transport;
  // What the OS says about this process's user and host, recorded on the
  // events `ward run` writes. Defaults to reading the platform; tests supply
  // one so the record they assert on carries values they can predict, and so
  // no test depends on the machine it runs on. There is no command-line,
  // configuration or environment path to it: an observed identity that a
  // caller could pass would not be observed. Typed from the adapter rather
  // than from the domain type it returns, because this layer may not import
  // the domain.
  machine?: typeof observeMachine;
}

function failure(error: WardError): RunResult {
  const envelope = errorEnvelope(error);
  return {
    stdout: "",
    stderr: `${JSON.stringify(envelope)}\n`,
    exitCode: exitCodeForErrorType[envelope.error_type],
  };
}

// The composition root for `ward setup`: the real store and provider, and
// the lock and journal, are only touched when setup actually runs, so
// --help, instructions and every other command initialize nothing.
async function setupCommand(options: RunOptions): Promise<{
  output: { kind: "setup.complete"; data: unknown; text: string };
  exitExplicitly: boolean;
}> {
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const session = acquireSetupSession(directory);
  const store = createSqliteVaultStore({ directory });
  const keyProvider =
    options.keyProvider ??
    createKeychainKeyProvider({ service: keychainService });
  const result = await runSetup({ session, store, keyProvider });
  return {
    output: {
      kind: "setup.complete" as const,
      data: result,
      text: [
        "Ward is set up on this machine.",
        `The vault key is in the OS credential store and the encrypted vault is at ${directory}.`,
        "Do not move or delete either.",
      ].join("\n"),
    },
    // A bounded call may have been abandoned even when setup ultimately
    // succeeded (an unconfirmed write resolved by load), and the pending
    // native call can keep the process alive.
    exitExplicitly: keyProvider.abandonedCall?.() ?? false,
  };
}

// The composition root for `ward init`. The checkout is resolved from the
// directory the command runs in, and the project files are bound to that
// root; the store and provider are constructed but only touched when the
// run registers the checkout.
async function initCommand(
  input: CommandInput,
  options: RunOptions,
): Promise<CommandOutput> {
  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const targets: AgentTarget[] = [];
  if (input.flags.has("--claude")) targets.push("claude");
  if (input.flags.has("--codex")) targets.push("codex");
  // DEC-48/DEC-52: with no target flag, on a terminal, and without --json,
  // the files are chosen through the multiselect the peer CLIs ask; a
  // script, a pipe, --json or an explicit flag gets the non-interactive path
  // and is never prompted. A cancel aborts the whole run here, before
  // initProject writes anything - deliberately not "select nothing", which
  // would carry on to the registration question the developer interrupted.
  if (targets.length === 0 && !input.flags.has("--json")) {
    const chooser =
      options.instructionFiles ?? createTerminalInstructionChoice();
    if (chooser.available()) {
      const chosen = await chooser.choose();
      if (chosen === undefined) throw new WardError("init_cancelled");
      targets.push(...chosen);
    }
  }

  const result = await initProject({
    checkout,
    files: createProjectFiles(checkout.root),
    store: createSqliteVaultStore({ directory }),
    keyProvider:
      options.keyProvider ??
      createKeychainKeyProvider({ service: keychainService }),
    approver: options.approver ?? createTerminalConsent(),
    // Canonical, so the check against the (canonical) checkout root compares
    // two names for a location rather than two spellings of one.
    vaultDirectory: canonicalDirectory(directory),
    register: !input.flags.has("--no-register"),
    targets,
    now: options.now ?? (() => new Date()),
    newProjectId: () => randomUUID(),
  });
  const { text, ...data } = result;
  return { kind: "init.complete", data, text };
}

// The composition root for `ward agents`. The checkout is resolved the way
// every project command resolves it, and the project files are bound to that
// root; no vault, key provider or terminal is touched, so this command works
// in a checkout Ward has never seen.
function agentsCommand(
  input: CommandInput,
  options: RunOptions,
): CommandOutput {
  const check = input.flags.has("--check");
  const update = input.flags.has("--update-instructions");
  if (check === update) throw new WardError("agent_form_invalid");
  if (update && input.flags.has("--require-installed"))
    throw new WardError("agent_option_unexpected");
  if (check && input.flags.has("--force"))
    throw new WardError("agent_option_unexpected");
  const target = input.flags.get("--target");
  if (typeof target !== "string" || !isAgentTarget(target))
    throw new WardError("agent_target_unknown");
  if (input.positionals.length > 0) throw new WardError("unexpected_argument");

  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const files = createProjectFiles(checkout.root);
  if (check) {
    const result = checkAgentBridge(target, files, {
      requireInstalled: input.flags.has("--require-installed"),
      packagedSkill: packagedSkillContent,
    });
    return {
      kind: "agents.status",
      data: result.data,
      text: result.text,
      exitCode: result.exitCode,
    };
  }
  const result = updateAgentBridge(target, files, {
    force: input.flags.has("--force"),
    packagedSkill: packagedSkillContent,
  });
  return { kind: "agents.updated", data: result.data, text: result.text };
}

// The composition root for `ward backup`. The passphrase is read from the
// terminal through the adapter — never an argument, the environment or a
// pipe — and the vault key comes from the platform credential store.
async function backupCommand(
  input: CommandInput,
  options: RunOptions,
): Promise<{ output: CommandOutput; exitExplicitly: boolean }> {
  const path = input.flags.get("--output");
  if (typeof path !== "string") throw new WardError("missing_required_option");
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const keyProvider =
    options.keyProvider ??
    createKeychainKeyProvider({ service: keychainService });
  const result = await runBackup({
    store: createSqliteVaultStore({ directory }),
    keyProvider,
    passphrases: options.passphrases ?? createTerminalPassphrase(),
    files: createBackupFiles(),
    path,
  });
  return {
    output: {
      kind: "backup.complete" as const,
      data: result,
      text: [
        "Backup written.",
        "",
        `  file:     ${result.path}`,
        `  vault:    ${result.vaultId}`,
        `  revision: ${result.revision}`,
        `  bytes:    ${result.bytes}`,
        "",
        "Ward cannot open it without the passphrase, and keeps no copy of either.",
        "Keep it somewhere you control: recovery from a lost key or a damaged",
        "vault needs this file and its passphrase, and the OS credential store",
        "is not part of it. Ward does not erase old copies of a backup, and a",
        "restore does not revoke anything at a credential's provider.",
      ].join("\n"),
    },
    exitExplicitly: keyProvider.abandonedCall?.() ?? false,
  };
}

// The composition root for `ward restore`. It restores only into an empty
// vault directory, under a fresh key and vault id, and clears every local
// binding, so the caller re-registers each checkout explicitly.
async function restoreCommand(
  input: CommandInput,
  options: RunOptions,
): Promise<{ output: CommandOutput; exitExplicitly: boolean }> {
  const path = input.flags.get("--input");
  if (typeof path !== "string") throw new WardError("missing_required_option");
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const keyProvider =
    options.keyProvider ??
    createKeychainKeyProvider({ service: keychainService });
  const result = await runRestore({
    store: createSqliteVaultStore({ directory }),
    keyProvider,
    passphrases: options.passphrases ?? createTerminalPassphrase(),
    files: createBackupFiles(),
    path,
    newVaultId: () => randomUUID(),
  });
  return {
    output: {
      kind: "restore.complete" as const,
      data: result,
      text: [
        "Vault restored.",
        "",
        `  vault:    ${result.vaultId}`,
        `  revision: ${result.revision}`,
        `  projects: ${result.projects}`,
        "",
        "It was restored under a new vault key and a new vault id, so this",
        "machine's credential store was never part of opening it.",
        "Every checkout binding, every profile approval and every cross-project",
        "grant is cleared: run `ward init` in each repository that should use",
        "these projects again, re-approve its profiles, and have each owner",
        "grant a shared secret again. Restoring an older backup does not revive",
        "authority that was granted, changed or revoked since it was taken.",
      ].join("\n"),
    },
    exitExplicitly: keyProvider.abandonedCall?.() ?? false,
  };
}

// The composition roots for `ward status`, `ward doctor` and `ward audit`.
// All three resolve the checkout the way every project command does and build
// the same read-only ports; none touches the store or the provider until the
// application layer reads through them.
function reporting(options: RunOptions): {
  options: ReportingOptions;
  keyProvider: KeyProvider;
} {
  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const keyProvider =
    options.keyProvider ??
    createKeychainKeyProvider({ service: keychainService });
  return {
    keyProvider,
    options: {
      checkout,
      files: createProjectFiles(checkout.root),
      store: createSqliteVaultStore({ directory }),
      keyProvider,
    },
  };
}

async function statusCommand(
  options: RunOptions,
): Promise<{ output: CommandOutput; exitExplicitly: boolean }> {
  const prepared = reporting(options);
  const result = await runStatus(prepared.options);
  return {
    output: {
      kind: "status.report" as const,
      data: result.data,
      text: result.text,
    },
    exitExplicitly: prepared.keyProvider.abandonedCall?.() ?? false,
  };
}

async function doctorCommand(
  options: RunOptions,
): Promise<{ output: CommandOutput; exitExplicitly: boolean }> {
  const prepared = reporting(options);
  const result = await runDoctor(prepared.options);
  return {
    output: {
      kind: "doctor.report" as const,
      data: result.data,
      text: result.text,
      exitCode: result.exitCode,
    },
    exitExplicitly: prepared.keyProvider.abandonedCall?.() ?? false,
  };
}

async function auditCommand(
  options: RunOptions,
): Promise<{ output: CommandOutput; exitExplicitly: boolean }> {
  const prepared = reporting(options);
  const result = await runAudit(prepared.options);
  return {
    output: {
      kind: "audit.report" as const,
      data: result.data,
      text: result.text,
    },
    exitExplicitly: prepared.keyProvider.abandonedCall?.() ?? false,
  };
}

// The composition root for `ward secret`. The checkout is resolved the way
// every project command resolves it; the value source is the terminal
// adapter — hidden entry, stdin bytes, and the replacement question — and
// may be replaced by a caller that must not touch a terminal.
async function secretCommand(
  input: CommandInput,
  options: RunOptions,
): Promise<CommandOutput> {
  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const action = input.positionals[0];
  if (action === undefined) throw new WardError("missing_argument");
  const result = await runSecret(
    {
      action,
      alias: input.positionals[1],
      viaStdin: input.flags.has("--stdin"),
      to: optionalFlag(input, "--to"),
      as: optionalFlag(input, "--as"),
      from: optionalFlag(input, "--from"),
    },
    {
      checkout,
      files: createProjectFiles(checkout.root),
      store: createSqliteVaultStore({ directory }),
      keyProvider:
        options.keyProvider ??
        createKeychainKeyProvider({ service: keychainService }),
      values: options.secrets ?? createTerminalSecretValues(),
      grants: options.grantApprover ?? createTerminalGrantApprover(),
      now: options.now ?? (() => new Date()),
      newSecretId: () => randomUUID(),
      newGrantId: () => randomUUID(),
    },
  );
  return { kind: result.kind, data: result.data, text: result.text };
}

// The composition root for `ward unregister`. It needs the checkout's
// identity and the vault, and a terminal to ask on; it reads no manifest.
async function unregisterCommand(options: RunOptions): Promise<CommandOutput> {
  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const result = await runUnregister({
    checkout,
    store: createSqliteVaultStore({ directory }),
    keyProvider:
      options.keyProvider ??
      createKeychainKeyProvider({ service: keychainService }),
    approver: options.unregisterApprover ?? createTerminalUnregisterApprover(),
  });
  return { kind: result.kind, data: result.data, text: result.text };
}

// The composition root for `ward profile`. Approving and revoking are the
// developer's acts, so the approver is the terminal adapter and the vault is
// written only after an interactive answer.
async function profileCommand(
  input: CommandInput,
  options: RunOptions,
): Promise<CommandOutput> {
  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const action = input.positionals[0];
  if (action === undefined) throw new WardError("missing_argument");
  const result = await runProfile(
    {
      action,
      profile: input.positionals[1],
      ttl: optionalFlag(input, "--ttl"),
    },
    {
      checkout,
      files: createProjectFiles(checkout.root),
      store: createSqliteVaultStore({ directory }),
      keyProvider:
        options.keyProvider ??
        createKeychainKeyProvider({ service: keychainService }),
      approver: options.profileApprover ?? createTerminalProfileApprover(),
      now: options.now ?? (() => new Date()),
    },
  );
  return { kind: result.kind, data: result.data, text: result.text };
}

// The composition root for `ward check`. It builds the same read-only ports
// every project command builds and no transport port at all: readiness is
// answered from the vault and the manifest, and this command has no way to
// reach the network even by mistake.
async function checkCommand(
  input: CommandInput,
  options: RunOptions,
): Promise<CommandOutput> {
  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const result = await runCheck(
    { profile: input.positionals[0] },
    {
      now: options.now ?? (() => new Date()),
      checkout,
      files: createProjectFiles(checkout.root),
      store: createSqliteVaultStore({ directory }),
      keyProvider:
        options.keyProvider ??
        createKeychainKeyProvider({ service: keychainService }),
    },
  );
  return {
    kind: result.kind,
    data: result.data,
    text: result.text,
    ...(result.exitCode === undefined ? {} : { exitCode: result.exitCode }),
  };
}

// An optional flag's value, or undefined when the caller left it off. The
// parser has already refused a repeated flag and a flag given no value, so the
// only other thing it can hold is `true` — the value it records for a flag
// declared to take none, which neither of `ward run`'s labels is.
function optionalFlag(input: CommandInput, name: string): string | undefined {
  const value = input.flags.get(name);
  return typeof value === "string" ? value : undefined;
}

// The composition root for `ward run`. Unlike every other command's, it
// builds a transport — the in-process HTTPS client by default, and whatever
// the caller supplied when a test is exercising the run path without a
// network. Nothing here reads the clock or generates an identifier on its
// own: both are handed to the application, so the records this command
// writes carry the values its caller can predict.
async function runCommand(
  input: CommandInput,
  options: RunOptions,
): Promise<CommandOutput> {
  const checkout = locateCheckout(options.cwd ?? process.cwd());
  const directory = options.wardDirectory ?? join(homedir(), ".ward");
  const result = await runOperation(
    {
      profile: input.positionals[0],
      actorLabel: optionalFlag(input, "--actor-label"),
      taskLabel: optionalFlag(input, "--task-label"),
    },
    {
      checkout,
      files: createProjectFiles(checkout.root),
      store: createSqliteVaultStore({ directory }),
      keyProvider:
        options.keyProvider ??
        createKeychainKeyProvider({ service: keychainService }),
      transport: options.transport ?? createHttpsTransport(),
      now: options.now ?? (() => new Date()),
      newId: options.newId ?? randomUUID,
      observeMachine: options.machine ?? observeMachine,
    },
  );
  return {
    kind: result.kind,
    data: result.data,
    text: result.text,
    ...(result.exitCode === undefined ? {} : { exitCode: result.exitCode }),
  };
}

async function dispatch(
  argv: readonly string[],
  options: RunOptions,
): Promise<RunResult> {
  const [first, ...rest] = argv;
  if (first === "--version") {
    if (rest.length > 0) throw new WardError("unexpected_argument", 2);
    return { stdout: `${version}\n`, stderr: "", exitCode: exitCodes.success };
  }
  if (first === undefined || first === "--help" || first === "-h")
    return dispatch(["help", ...rest], options);
  const command = findCommand(first);
  if (command === undefined) throw new WardError("unknown_command", 1);

  const parsed = parseArguments(command, rest);
  if (parsed.flags.has("--help")) {
    const json = parsed.flags.has("--json") ? ["--json"] : [];
    return dispatch(["help", command.name, ...json], options);
  }
  let output: CommandOutput;
  let exitExplicitly = false;
  if (command.name === "setup") {
    const run = await setupCommand(options);
    output = run.output;
    exitExplicitly = run.exitExplicitly;
  } else if (command.name === "init") {
    output = await initCommand(parsed, options);
  } else if (command.name === "backup") {
    const run = await backupCommand(parsed, options);
    output = run.output;
    exitExplicitly = run.exitExplicitly;
  } else if (command.name === "restore") {
    const run = await restoreCommand(parsed, options);
    output = run.output;
    exitExplicitly = run.exitExplicitly;
  } else if (command.name === "status") {
    const run = await statusCommand(options);
    output = run.output;
    exitExplicitly = run.exitExplicitly;
  } else if (command.name === "doctor") {
    const run = await doctorCommand(options);
    output = run.output;
    exitExplicitly = run.exitExplicitly;
  } else if (command.name === "audit") {
    const run = await auditCommand(options);
    output = run.output;
    exitExplicitly = run.exitExplicitly;
  } else if (command.name === "secret") {
    output = await secretCommand(parsed, options);
  } else if (command.name === "profile") {
    output = await profileCommand(parsed, options);
  } else if (command.name === "unregister") {
    output = await unregisterCommand(options);
  } else if (command.name === "agents") {
    output = agentsCommand(parsed, options);
  } else if (command.name === "check") {
    output = await checkCommand(parsed, options);
  } else if (command.name === "run") {
    output = await runCommand(parsed, options);
  } else {
    const handler = handlers[command.name];
    if (handler === undefined) throw new WardError("unknown_command", 1);
    output = await handler(parsed);
  }
  const stdout = parsed.flags.has("--json")
    ? JSON.stringify(success(output.kind, output.data))
    : output.text;
  return {
    stdout: `${stdout}\n`,
    stderr: "",
    // A report can carry its own exit code (ward doctor: 6 when a check
    // failed); everything else exits 0.
    exitCode: output.exitCode ?? exitCodes.success,
    ...(exitExplicitly ? { exitExplicitly: true } : {}),
  };
}

// Every path out of Ward goes through here. Anything thrown that is not a
// WardError becomes a generic internal error: its message and stack could
// carry argv, file contents or upstream bytes, so none of it is printed.
export async function runWard(
  argv: readonly string[],
  options: RunOptions = {},
): Promise<RunResult> {
  try {
    return await dispatch(argv, options);
  } catch (error) {
    const wardError =
      error instanceof WardError ? error : new WardError("uncaught");
    const result = failure(wardError);
    if (
      wardError.code === "vault_key_unavailable" ||
      wardError.code === "vault_key_write_unconfirmed"
    )
      result.exitExplicitly = true;
    return result;
  }
}
