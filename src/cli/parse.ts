import { WardError } from "../contract/errors.ts";
import type { CommandSpec } from "../contract/manifest.ts";

export interface ParsedArguments {
  positionals: string[];
  flags: Map<string, string | true>;
}

// Parses the argv that follows the command name, strictly against the
// command's manifest entry. Faults are reported by 1-based position in the
// full argv (the command name is position 1), never by value: an unknown
// option could be `--ghp_...` pasted into the wrong place.
export function parseArguments(
  command: CommandSpec,
  argv: readonly string[],
): ParsedArguments {
  const positionals: string[] = [];
  const positionalPositions: number[] = [];
  const flags = new Map<string, string | true>();
  let optionsEnded = false;

  for (let index = 0; index < argv.length; index++) {
    const token = argv[index] as string;
    const position = index + 2;

    if (optionsEnded || !token.startsWith("-") || token === "-") {
      positionals.push(token);
      positionalPositions.push(position);
      continue;
    }
    if (token === "--") {
      optionsEnded = true;
      continue;
    }

    const equals = token.indexOf("=");
    const name = equals === -1 ? token : token.slice(0, equals);
    const spec = command.flags.find((flag) => flag.name === name);
    if (spec === undefined) throw new WardError("unknown_option", position);
    if (flags.has(spec.name)) throw new WardError("repeated_option", position);

    if (!spec.takesValue) {
      if (equals !== -1)
        throw new WardError("unexpected_option_value", position);
      flags.set(spec.name, true);
      continue;
    }

    if (equals !== -1) {
      flags.set(spec.name, token.slice(equals + 1));
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined)
      throw new WardError("missing_option_value", position);
    flags.set(spec.name, value);
    index++;
  }

  const required = command.args.filter((arg) => arg.required).length;
  if (positionals.length < required) throw new WardError("missing_argument");
  if (positionals.length > command.args.length) {
    throw new WardError(
      "unexpected_argument",
      positionalPositions[command.args.length],
    );
  }

  return { positionals, flags };
}
