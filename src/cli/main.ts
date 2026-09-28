import { homedir } from "node:os";
import { join } from "node:path";
import {
  createKeychainKeyProvider,
  keychainService,
} from "../adapters/keychain.ts";
import { acquireSetupSession } from "../adapters/setup-session.ts";
import { createSqliteVaultStore } from "../adapters/sqlite-vault-store.ts";
import type { KeyProvider } from "../application/key-provider.ts";
import { runSetup } from "../application/setup.ts";
import {
  handlers,
  version,
  type CommandOutput,
} from "../application/commands.ts";
import {
  type ExitCode,
  exitCodeForErrorType,
  exitCodes,
  success,
} from "../contract/envelope.ts";
import { errorEnvelope, WardError } from "../contract/errors.ts";
import { findCommand } from "../contract/manifest.ts";
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
