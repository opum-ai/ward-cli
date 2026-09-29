// The mock is imported first: main.ts reaches the keychain adapter, so
// bunfig.toml's preload alone would not cover a run from another cwd.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import type { PassphraseSource } from "../src/application/backup.ts";
import { handlers } from "../src/application/commands.ts";
import { instructionTopics } from "../src/application/instructions.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { commands } from "../src/contract/manifest.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

function json(stdout: string): Record<string, unknown> {
  return JSON.parse(stdout) as Record<string, unknown>;
}

// The example runner below executes every command's example, including
// `ward setup`, so it must never resolve the real vault directory or the
// real credential store. Each call gets a fresh directory, since setup
// examples are not idempotent across runs.
const root = mkdtempSync(join(tmpdir(), "ward-contract-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

// A throwaway checkout, so a command that resolves a project (`ward init`)
// has a worktree root to find and never writes into this repository. One
// directory for the whole example loop, so the relative paths an example
// names land inside it.
function checkout(): string {
  const directory = mkdtempSync(join(root, "repo-"));
  mkdirSync(join(directory, ".git"));
  return directory;
}

const exampleCheckout = checkout();

// A passphrase without a terminal. The example runner cannot type one; the
// adapter that reads a real one has its own tests.
const passphrases: PassphraseSource = {
  available: () => true,
  read: () => new TextEncoder().encode("contract-example-passphrase"),
};

function options(): RunOptions {
  const keychain = new MemoryKeychain();
  return {
    // The parent must exist: the store refuses to create it (WCLI-6).
    wardDirectory: join(mkdtempSync(join(root, "case-")), ".ward"),
    keyProvider: createKeychainKeyProvider({
      service: "opum.ward.contract",
      entry: keychain.entry,
    }),
    cwd: exampleCheckout,
    passphrases,
  };
}

// What an example needs from the machine before it can do what it says.
// `ward setup` and `ward init` create whatever they use, so they need
// nothing. `ward backup` needs a vault to copy, and `ward restore` needs an
// empty vault directory plus a backup file where its example names one,
// which is produced here by the command itself rather than by a fixture, so
// the example exercises the format that actually ships.
async function prepareExample(name: string): Promise<RunOptions> {
  const prepared = options();
  if (name === "backup") {
    const setup = await runWard(["setup", "--json"], prepared);
    expect(setup.exitCode).toBe(exitCodes.success);
  } else if (name === "restore") {
    // Whatever an earlier example left at the path is cleared first: the
    // file this example opens is one the command itself writes here.
    const exampleBackup = join(exampleCheckout, "ward-backup.json");
    rmSync(exampleBackup, { force: true });
    const source = options();
    expect((await runWard(["setup", "--json"], source)).exitCode).toBe(
      exitCodes.success,
    );
    const created = await runWard(
      ["backup", "--output", exampleBackup, "--json"],
      source,
    );
    expect(created.exitCode).toBe(exitCodes.success);
  }
  return prepared;
}

describe("manifest", () => {
  test("is the fleet result envelope", async () => {
    const result = await runWard(["manifest", "--json"]);
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
    // `setup`, `init`, `backup` and `restore` are dispatched by the
    // composition root in main.ts rather than by the synchronous handler
    // table, because they need the injected store, provider, checkout,
    // consent or terminal passphrase.
    const compositionRoot = ["setup", "init", "backup", "restore"];
    expect(commands.map((command) => command.name).sort()).toEqual(
      [...Object.keys(handlers), ...compositionRoot].sort(),
    );
  });

  test("declares every exit code the contract defines", async () => {
    const data = json((await runWard(["manifest", "--json"])).stdout).data as {
      exitCodes: Record<string, number>;
    };
    expect(data.exitCodes).toEqual({ ...exitCodes });
  });

  test("every example emits a declared kind and a declared exit code", async () => {
    // Examples are written the way a developer types them, so a path in one
    // is relative to the directory the terminal is in. The loop therefore
    // runs inside the throwaway checkout: without this, `--output
    // ward-backup.json` would land in the repository running the tests.
    // `RunOptions.cwd` cannot stand in for it, because it resolves the
    // command's project, not the process's filesystem.
    const previous = process.cwd();
    process.chdir(exampleCheckout);
    try {
      for (const command of commands) {
        expect(command.examples.length).toBeGreaterThan(0);
        const declared: string[] = [
          command.kind,
          ...(command.resultKinds ?? []),
        ];
        for (const example of command.examples) {
          const argv = example.split(" ").slice(1);
          const result = await runWard(
            argv.includes("--json") ? argv : [...argv, "--json"],
            await prepareExample(command.name),
          );
          expect(command.exitCodes).toContain(result.exitCode);
          expect(declared).toContain(json(result.stdout).kind as string);
        }
      }
    } finally {
      process.chdir(previous);
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
  test("bare form prints the overview topic", async () => {
    const result = await runWard(["instructions", "--json"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect((json(result.stdout).data as { key: string }).key).toBe("overview");
  });

  test("every listed topic resolves", async () => {
    const listed = json(
      (await runWard(["instructions", "--list", "--json"])).stdout,
    ).data as { topics: { key: string }[] };
    expect(listed.topics.map((topic) => topic.key)).toEqual(
      instructionTopics.map((topic) => topic.key),
    );
    for (const { key } of listed.topics) {
      expect((await runWard(["instructions", key])).exitCode).toBe(
        exitCodes.success,
      );
    }
  });

  test("--list takes no topic", async () => {
    const result = await runWard(["instructions", "--list", "overview"]);
    expect(result.exitCode).toBe(exitCodes.usage);
    expect(json(result.stderr).code).toBe("unexpected_argument");
  });

  test("an unknown topic exits 3", async () => {
    const result = await runWard(["instructions", "no-such-topic"]);
    expect(result.exitCode).toBe(exitCodes.notFound);
    expect(json(result.stderr).code).toBe("unknown_topic");
  });
});

describe("help", () => {
  test("no arguments, --help and help agree", async () => {
    const bare = await runWard([]);
    expect(bare.exitCode).toBe(exitCodes.success);
    expect((await runWard(["--help"])).stdout).toBe(bare.stdout);
    expect((await runWard(["help"])).stdout).toBe(bare.stdout);
  });

  test("<command> --help and -h are help for that command, including help", async () => {
    for (const command of commands) {
      const expected = (await runWard(["help", command.name])).stdout;
      for (const flag of ["--help", "-h"]) {
        const result = await runWard([command.name, flag]);
        expect(result.exitCode).toBe(exitCodes.success);
        expect(result.stdout).toBe(expected);
      }
    }
  });

  test("--help keeps --json on every path", async () => {
    for (const argv of [
      ["--help", "--json"],
      ["manifest", "--help", "--json"],
      ["manifest", "--json", "--help"],
    ]) {
      const result = await runWard(argv);
      expect(result.exitCode).toBe(exitCodes.success);
      expect(json(result.stdout).kind).toBe("help.usage");
    }
  });

  test("--version prints the package version", async () => {
    const result = await runWard(["--version"]);
    expect(result.exitCode).toBe(exitCodes.success);
    expect(result.stdout).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("errors", () => {
  test("usage faults exit 2 with a JSON diagnostic on stderr and nothing on stdout", async () => {
    for (const argv of [
      ["manifest", "--nope"],
      ["manifest", "extra"],
      ["manifest", "--json", "--json"],
      ["nope"],
    ]) {
      const result = await runWard(argv);
      expect(result.exitCode).toBe(exitCodes.usage);
      expect(result.stdout).toBe("");
      const envelope = json(result.stderr);
      expect(envelope.error_type).toBe("usage");
      expect(envelope).not.toHaveProperty("input");
    }
  });
});
