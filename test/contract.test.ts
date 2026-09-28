import { describe, expect, test } from "bun:test";
import { handlers } from "../src/application/commands.ts";
import { instructionTopics } from "../src/application/instructions.ts";
import { runWard } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { commands } from "../src/contract/manifest.ts";

function json(stdout: string): Record<string, unknown> {
  return JSON.parse(stdout) as Record<string, unknown>;
}

describe("manifest", () => {
  test("is the fleet result envelope", () => {
    const result = runWard(["manifest", "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stderr).toBe("");
    const envelope = json(result.stdout);
    expect(Object.keys(envelope)).toEqual([
      "schemaVersion",
      "kind",
      "data",
      "principal",
    ]);
    expect(envelope.schemaVersion).toBe(1);
    expect(envelope.kind).toBe("manifest.registry");
    expect(envelope.principal).toBeNull();
  });

  test("lists exactly the commands that have handlers", () => {
    expect(commands.map((command) => command.name).sort()).toEqual(
      Object.keys(handlers).sort(),
    );
  });

  test("declares every exit code the contract defines", () => {
    const data = json(runWard(["manifest", "--json"]).stdout).data as {
      exitCodes: Record<string, number>;
    };
    expect(data.exitCodes).toEqual({ ...exitCodes });
  });

  test("every example emits a declared kind and a declared exit code", () => {
    for (const command of commands) {
      expect(command.examples.length).toBeGreaterThan(0);
      const declared: string[] = [command.kind, ...(command.resultKinds ?? [])];
      for (const example of command.examples) {
        const argv = example.split(" ").slice(1);
        const result = runWard(
          argv.includes("--json") ? argv : [...argv, "--json"],
        );
        expect(command.exitCodes).toContain(result.exitCode);
        expect(declared).toContain(json(result.stdout).kind as string);
      }
    }
  });

  test("every command declares exit codes 0 and 1", () => {
    for (const command of commands) {
      expect(command.exitCodes).toContain(exitCodes.success);
      expect(command.exitCodes).toContain(exitCodes.uncaught);
    }
  });
});

describe("instructions", () => {
  test("bare form prints the overview topic", () => {
    const result = runWard(["instructions", "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect((json(result.stdout).data as { key: string }).key).toBe("overview");
  });

  test("every listed topic resolves", () => {
    const listed = json(runWard(["instructions", "--list", "--json"]).stdout)
      .data as { topics: { key: string }[] };
    expect(listed.topics.map((topic) => topic.key)).toEqual(
      instructionTopics.map((topic) => topic.key),
    );
    for (const { key } of listed.topics) {
      expect(runWard(["instructions", key]).exitCode).toBe(exitCodes.success);
    }
  });

  test("--list takes no topic", () => {
    const result = runWard(["instructions", "--list", "overview"]);
    expect(result.exitCode).toBe(exitCodes.usage);
    expect(json(result.stderr).code).toBe("unexpected_argument");
  });

  test("an unknown topic exits 3", () => {
    const result = runWard(["instructions", "no-such-topic"]);
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(json(result.stderr).code).toBe("unknown_topic");
  });
});

describe("help", () => {
  test("no arguments, --help and help agree", () => {
    const bare = runWard([]);
    expect(bare.exitCode).toBe(exitCodes.success);
    expect(runWard(["--help"]).stdout).toBe(bare.stdout);
    expect(runWard(["help"]).stdout).toBe(bare.stdout);
  });

  test("<command> --help and -h are help for that command, including help", () => {
    for (const command of commands) {
      const expected = runWard(["help", command.name]).stdout;
      for (const flag of ["--help", "-h"]) {
        const result = runWard([command.name, flag]);
        expect(result.exitCode).toBe(exitCodes.success);
        expect(result.stdout).toBe(expected);
      }
    }
  });

  test("--help keeps --json on every path", () => {
    for (const argv of [
      ["--help", "--json"],
      ["manifest", "--help", "--json"],
      ["manifest", "--json", "--help"],
    ]) {
      const result = runWard(argv);
      expect(result.exitCode).toBe(exitCodes.success);
      expect(json(result.stdout).kind).toBe("help.usage");
    }
  });

  test("--version prints the package version", () => {
    const result = runWard(["--version"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stdout).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("errors", () => {
  test("usage faults exit 2 with a JSON diagnostic on stderr and nothing on stdout", () => {
    for (const argv of [
      ["manifest", "--nope"],
      ["manifest", "extra"],
      ["manifest", "--json", "--json"],
      ["nope"],
    ]) {
      const result = runWard(argv);
      expect(result.exitCode).toBe(exitCodes.usage);
      expect(result.stdout).toBe("");
      const envelope = json(result.stderr);
      expect(envelope.error_type).toBe("usage");
      expect(envelope).not.toHaveProperty("input");
    }
  });
});
