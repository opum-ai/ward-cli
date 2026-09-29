import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { createBackupFiles } from "../adapters/backup-file.ts";
import { canonicalDirectory, locateCheckout } from "../adapters/checkout.ts";
import {
  createKeychainKeyProvider,
  keychainService,
} from "../adapters/keychain.ts";
import { createTerminalPassphrase } from "../adapters/passphrase.ts";
import { createProjectFiles } from "../adapters/project-files.ts";
import { acquireSetupSession } from "../adapters/setup-session.ts";
import { createSqliteVaultStore } from "../adapters/sqlite-vault-store.ts";
import { createTerminalConsent } from "../adapters/terminal-consent.ts";
import type { RegistrationApprover } from "../application/approvals.ts";
import {
  type PassphraseSource,
  runBackup,
  runRestore,
} from "../application/backup.ts";
import {
  type CommandInput,
  type CommandOutput,
  handlers,
  version,
} from "../application/commands.ts";
import type { KeyProvider } from "../application/key-provider.ts";
import { initProject } from "../application/project.ts";
import { runSetup } from "../application/setup.ts";
import {
  type ExitCode,
  exitCodeForErrorType,
  exitCodes,
  success,
} from "../contract/envelope.ts";
import { errorEnvelope, WardError } from "../contract/errors.ts";
import { type AgentTarget, findCommand } from "../contract/manifest.ts";
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
  // Where a backup passphrase comes from. Defaults to the terminal with echo
  // suppressed; tests and qualification probes supply one. There is no
  // option, argument or environment path to it, here or anywhere.
  passphrases?: PassphraseSource;
  // The clock, for timestamps recorded in the vault.
  now?: () => Date;
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
        "Every checkout binding is cleared: run `ward init` in each repository",
        "that should use these projects again, and re-approve anything the old",
        "vault had approved. Restoring an older backup does not revive authority",
        "that was granted, changed or revoked since it was taken.",
      ].join("\n"),
    },
    exitExplicitly: keyProvider.abandonedCall?.() ?? false,
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
    exitCode: exitCodes.success,
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
