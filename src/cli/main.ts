#!/usr/bin/env bun
import { handlers, version } from "../application/commands.ts";
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
}

function failure(error: WardError): RunResult {
  const envelope = errorEnvelope(error);
  return {
    stdout: "",
    stderr: `${JSON.stringify(envelope)}\n`,
    exitCode: exitCodeForErrorType[envelope.error_type],
  };
}

function dispatch(argv: readonly string[]): RunResult {
  const [first, ...rest] = argv;
  if (first === "--version") {
    if (rest.length > 0) throw new WardError("unexpected_argument", 2);
    return { stdout: `${version}\n`, stderr: "", exitCode: exitCodes.success };
  }
  if (first === undefined || first === "--help" || first === "-h")
    return dispatch(["help", ...rest]);
  const command = findCommand(first);
  const handler = command === undefined ? undefined : handlers[command.name];
  if (command === undefined || handler === undefined)
    throw new WardError("unknown_command", 1);

  // `ward <command> --help` is help for that command, wherever the flag sits
  // before a `--` terminator.
  const optionsEnd = rest.indexOf("--");
  const options = optionsEnd === -1 ? rest : rest.slice(0, optionsEnd);
  if (
    command.name !== "help" &&
    (options.includes("--help") || options.includes("-h"))
  ) {
    return dispatch(["help", command.name]);
  }

  const parsed = parseArguments(command, rest);
  const output = handler(parsed);
  const stdout = parsed.flags.has("--json")
    ? JSON.stringify(success(output.kind, output.data))
    : output.text;
  return { stdout: `${stdout}\n`, stderr: "", exitCode: exitCodes.success };
}

// Every path out of Ward goes through here. Anything thrown that is not a
// WardError becomes a generic internal error: its message and stack could
// carry argv, file contents or upstream bytes, so none of it is printed.
export function runWard(argv: readonly string[]): RunResult {
  try {
    return dispatch(argv);
  } catch (error) {
    return failure(
      error instanceof WardError ? error : new WardError("uncaught"),
    );
  }
}

function emitUncaughtAndExit(): never {
  process.stderr.write(
    `${JSON.stringify(errorEnvelope(new WardError("uncaught")))}\n`,
  );
  process.exit(exitCodes.uncaught);
}

if (import.meta.main) {
  process.on("uncaughtException", emitUncaughtAndExit);
  process.on("unhandledRejection", emitUncaughtAndExit);
  const result = runWard(process.argv.slice(2));
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exitCode = result.exitCode;
}
