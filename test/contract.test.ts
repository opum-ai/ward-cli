// The mock is imported first: main.ts reaches the keychain adapter, so
// bunfig.toml's preload alone would not cover a run from another cwd.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import type {
  UnregisterApprover,
  GrantApprover,
  ProfileApprover,
  RegistrationApprover,
} from "../src/application/approvals.ts";
import type { PassphraseSource } from "../src/application/backup.ts";
import { handlers } from "../src/application/commands.ts";
import { instructionTopics } from "../src/application/instructions.ts";
import type { SecretValueSource } from "../src/application/secrets.ts";
import type { Transport } from "../src/application/transport.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { errorCatalog } from "../src/contract/errors.ts";
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

// A registration answer without a terminal, so an example that registers
// (`ward init` asked to register, and the secret examples' setup) can run.
const approver: RegistrationApprover = {
  available: () => true,
  ask: () => "approved",
};

// The same, for the HTTPS profile examples. The adapter that asks a real
// terminal has its own tests.
const profileApprover: ProfileApprover = {
  available: () => true,
  ask: () => "approved",
};

// The grant examples' answer, and the target project they name. Both are fixed
// because an example is a line a developer could type.
const grantApprover: GrantApprover = {
  available: () => true,
  ask: () => "approved",
};
// The same, for `ward unregister`'s two questions.
const unregisterApprover: UnregisterApprover = {
  available: () => true,
  ask: () => "approved",
};
const exampleGrantTarget = "7c1d9a52-3e84-4b6f-9a10-5d2e8f4b6c31";

// The profile the profile and check examples name, written into the manifest
// `ward init` created for them. The declaration and the examples move
// together: an example naming a profile the fixture does not declare fails
// as a not-found rather than passing quietly.
const exampleProfileDeclaration = {
  adapter: "http",
  method: "GET",
  url: "https://example.invalid/status",
  auth: { type: "bearer", secret: "example-token" },
  output: "status",
};

function declareExampleProfile(checkout: string): void {
  const manifestPath = join(checkout, ".ward", "project.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    profiles?: Record<string, unknown>;
  };
  manifest.profiles = { "example-profile": exampleProfileDeclaration };
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

// Secret values without a terminal or a pipe: what a hidden read would have
// returned, and consent to the replacement question. The adapter that reads
// a real terminal has its own tests.
const exampleSecretValue = new TextEncoder().encode("contract-example-value");
const secrets: SecretValueSource = {
  available: () => true,
  readHidden: () => exampleSecretValue.slice(),
  readStdin: () => exampleSecretValue.slice(),
  confirmReplace: () => true,
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
    approver,
    profileApprover,
    secrets,
  };
}

// What an example needs from the machine before it can do what it says.
// `ward setup` and `ward init` create whatever they use, so they need
// nothing. `ward backup` needs a vault to copy, and `ward restore` needs an
// empty vault directory plus a backup file where its example names one,
// which is produced here by the command itself rather than by a fixture, so
// the example exercises the format that actually ships.
async function prepareExample(name: string, example = ""): Promise<RunOptions> {
  const prepared = options();
  prepared.grantApprover = grantApprover;
  prepared.unregisterApprover = unregisterApprover;
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
  } else if (name === "key") {
    // A vault and a registered checkout; `public` finds the key `generate`
    // made, so the examples run in order against one state.
    expect((await runWard(["setup", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    expect((await runWard(["init", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    if (example.includes(" public ")) {
      expect(
        (
          await runWard(
            ["key", "generate", "example-signing-key", "--json"],
            prepared,
          )
        ).exitCode,
      ).toBe(exitCodes.success);
    }
  } else if (name === "secret") {
    // A vault, a registered checkout and one existing alias: `set` replaces
    // it through the hidden path, and `inspect` and `delete` find it.
    expect((await runWard(["setup", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    expect((await runWard(["init", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    expect(
      (
        await runWard(
          ["secret", "set", "example-alias", "--stdin", "--json"],
          prepared,
        )
      ).exitCode,
    ).toBe(exitCodes.success);
    // The project the grant examples name as their target, registered in the
    // same vault from a second checkout so a grant has someone to go to. The
    // revoke example needs a grant to revoke, so it is made first.
    const target = checkout();
    mkdirSync(join(target, ".ward"));
    writeFileSync(
      join(target, ".ward", "project.json"),
      `${JSON.stringify({ schemaVersion: 1, projectId: exampleGrantTarget })}\n`,
    );
    expect(
      (await runWard(["init", "--json"], { ...prepared, cwd: target }))
        .exitCode,
    ).toBe(exitCodes.success);
    if (example.includes(" revoke ")) {
      expect(
        (
          await runWard(
            [
              "secret",
              "grant",
              "example-alias",
              "--to",
              exampleGrantTarget,
              "--as",
              "shared-alias",
              "--json",
            ],
            prepared,
          )
        ).exitCode,
      ).toBe(exitCodes.success);
    }
  } else if (name === "unregister") {
    // A vault and a registered checkout: there has to be a binding to remove.
    expect((await runWard(["setup", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    expect((await runWard(["init", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
  } else if (name === "audit") {
    // A vault and a registered checkout: `ward audit` reads this project's
    // events through the binding, so the binding has to exist. An empty
    // history is a reportable answer, so no events are prepared.
    expect((await runWard(["setup", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    expect((await runWard(["init", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
  } else if (name === "sign") {
    // A vault, a registered checkout, a signing key, and a sign profile over
    // it that is approved. The stdin source below answers with a value that
    // begins with the profile's one prefix.
    for (const args of [["setup"], ["init"]])
      expect((await runWard([...args, "--json"], prepared)).exitCode).toBe(
        exitCodes.success,
      );
    expect(
      (
        await runWard(
          ["key", "generate", "example-signing-key", "--json"],
          prepared,
        )
      ).exitCode,
    ).toBe(exitCodes.success);
    const manifestPath = join(exampleCheckout, ".ward", "project.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      profiles?: Record<string, unknown>;
    };
    manifest.profiles = {
      "example-signer": {
        adapter: "sign",
        key: "example-signing-key",
        prefixes: [Buffer.from("contract-example").toString("base64")],
      },
    };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    expect(
      (
        await runWard(
          ["profile", "approve", "example-signer", "--json"],
          prepared,
        )
      ).exitCode,
    ).toBe(exitCodes.success);
  } else if (name === "profile" || name === "check" || name === "run") {
    // A vault, a registered checkout and a manifest declaring the profile
    // the examples name. `ward check` is expected to answer "not ready" —
    // no credential is stored — which is why 6 is a declared exit code for
    // it; the profile examples need an approval to exist, so the revoke
    // example has one to revoke and the approve example is a reapproval.
    expect((await runWard(["setup", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    expect((await runWard(["init", "--json"], prepared)).exitCode).toBe(
      exitCodes.success,
    );
    declareExampleProfile(exampleCheckout);
    if (name === "profile" || name === "run") {
      expect(
        (
          await runWard(
            ["profile", "approve", "example-profile", "--json"],
            prepared,
          )
        ).exitCode,
      ).toBe(exitCodes.success);
    }
    if (name === "run") {
      // The credential the approved declaration names, and a transport. An
      // example is a line a developer could type, and typing it here must
      // not reach the network: the transport answers with a status and
      // nothing else, which is the whole of what a run returns.
      expect(
        (
          await runWard(
            [
              "secret",
              "set",
              exampleProfileDeclaration.auth.secret,
              "--stdin",
              "--json",
            ],
            prepared,
          )
        ).exitCode,
      ).toBe(exitCodes.success);
      const statusOnly: Transport = {
        send: async () => ({ kind: "response", httpStatus: 200 }),
      };
      prepared.transport = statusOnly;
    }
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
    // `setup`, `init`, `status`, `doctor`, `backup`, `restore`, `secret`,
    // `profile`, `check` and `agents` are dispatched by the composition root
    // in main.ts rather than by the synchronous handler table, because they
    // need the injected store, provider, checkout, consent, terminal
    // passphrase, secret value source or profile approver.
    const compositionRoot = [
      "setup",
      "init",
      "status",
      "doctor",
      "audit",
      "backup",
      "restore",
      "secret",
      "key",
      "profile",
      "unregister",
      "check",
      "run",
      "sign",
      "agents",
    ];
    expect(commands.map((command) => command.name).sort()).toEqual(
      [...Object.keys(handlers), ...compositionRoot].sort(),
    );
  });

  test("status, doctor and audit are registered as read-only reporting commands", async () => {
    const data = json((await runWard(["manifest", "--json"])).stdout).data as {
      commands: {
        name: string;
        kind: string;
        mutates: boolean;
        unlocksVault: boolean;
      }[];
    };
    for (const [name, kind] of [
      ["status", "status.report"],
      ["doctor", "doctor.report"],
      ["audit", "audit.report"],
    ] as const) {
      const command = data.commands.find((entry) => entry.name === name);
      expect(command?.kind).toBe(kind);
      // All three report on the vault, so all three declare the unlock;
      // none mutates anything.
      expect(command?.mutates).toBe(false);
      expect(command?.unlocksVault).toBe(true);
    }
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
            await prepareExample(command.name, example),
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

  // WCLI-31 (DEC-13, option A). `setup_in_progress` is raised on paths that
  // can follow a real change — prepareVaultDirectory runs before the lock
  // and may already have created the vault directory — so the old sentence's
  // "Nothing was changed" was not true everywhere it could be reported. The decided wording claims
  // only what holds on every raise path: the key and the vault. The string
  // is the deliverable, so the test pins it exactly; the restructure that
  // would make a stronger claim true (creating the vault directory only
  // after the lock is held) is out of scope by the same decision.
  test("setup_in_progress claims only what holds on every raise path", () => {
    expect(errorCatalog.setup_in_progress.message).toBe(
      "Another Ward setup appears to be running on this machine. Ward did not create a key or a vault.",
    );
    expect(errorCatalog.setup_in_progress.message).not.toContain(
      "Nothing was changed",
    );
  });
});
