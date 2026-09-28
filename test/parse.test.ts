import { describe, expect, test } from "bun:test";
import { parseArguments } from "../src/cli/parse.ts";
import { WardError } from "../src/contract/errors.ts";
import type { CommandSpec } from "../src/contract/manifest.ts";

const spec: CommandSpec = {
  name: "fixture",
  summary: "Parser fixture.",
  args: [
    { name: "first", required: true },
    { name: "second", required: false },
  ],
  flags: [
    { name: "--json", takesValue: false, summary: "" },
    { name: "--output", takesValue: true, summary: "" },
  ],
  kind: "fixture.result",
  mutates: false,
  unlocksVault: false,
  admin: false,
  outputSensitivity: "public",
  exitCodes: [0],
  examples: ["ward fixture a"],
};

function fault(argv: string[]): { code: string; position: number | undefined } {
  try {
    parseArguments(spec, argv);
  } catch (error) {
    if (error instanceof WardError)
      return { code: error.code, position: error.argumentPosition };
    throw error;
  }
  throw new Error("expected a parse fault");
}

describe("parseArguments", () => {
  test("reads positionals, boolean flags and both value forms", () => {
    expect(parseArguments(spec, ["a", "--json", "--output", "x"])).toEqual({
      positionals: ["a"],
      flags: new Map<string, string | true>([
        ["--json", true],
        ["--output", "x"],
      ]),
    });
    expect(
      parseArguments(spec, ["--output=--literal", "a", "b"]).flags.get(
        "--output",
      ),
    ).toBe("--literal");
  });

  test("treats everything after -- as positional", () => {
    expect(parseArguments(spec, ["--", "--json"]).positionals).toEqual([
      "--json",
    ]);
  });

  test("reports faults by position in the full argv", () => {
    expect(fault(["a", "--nope"])).toEqual({
      code: "unknown_option",
      position: 3,
    });
    expect(fault(["a", "--json=1"])).toEqual({
      code: "unexpected_option_value",
      position: 3,
    });
    expect(fault(["a", "--output"])).toEqual({
      code: "missing_option_value",
      position: 3,
    });
    expect(fault(["a", "--json", "--json"])).toEqual({
      code: "repeated_option",
      position: 4,
    });
    expect(fault(["--json"])).toEqual({
      code: "missing_argument",
      position: undefined,
    });
    expect(fault(["a", "--output", "c", "b", "c"])).toEqual({
      code: "unexpected_argument",
      position: 6,
    });
  });
});

describe("parseArguments --help", () => {
  test("--help and -h are accepted by every command and recorded as --help", () => {
    expect(parseArguments(spec, ["a", "-h"]).flags.get("--help")).toBe(true);
    expect(parseArguments(spec, ["--help"]).flags.get("--help")).toBe(true);
  });

  test("-h as an option's value is a value, not a help request", () => {
    const parsed = parseArguments(spec, ["a", "--output", "-h"]);
    expect(parsed.flags.get("--output")).toBe("-h");
    expect(parsed.flags.has("--help")).toBe(false);
  });

  test("--help is answered before argument counts are enforced", () => {
    expect(parseArguments(spec, ["--help"]).positionals).toEqual([]);
    expect(
      parseArguments(spec, ["a", "b", "c", "-h"]).flags.has("--help"),
    ).toBe(true);
  });

  test("--help after -- is a positional", () => {
    expect(parseArguments(spec, ["a", "--", "--help"]).positionals).toEqual([
      "a",
      "--help",
    ]);
  });
});
