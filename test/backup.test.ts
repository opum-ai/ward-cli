// WCLI-13: `ward backup` and `ward restore` (spec §10).
//
// T20's shapes: a round trip that needs only the backup file and its
// passphrase — no native-keystore item — plus a wrong passphrase, a changed
// byte, a hostile parameter set and an oversized file, each refused with the
// destination untouched. T21: a restore lands under a fresh vault key and a
// fresh vault id, keeps the project records, clears every local binding and
// makes the checkout register again.
//
// Every case runs against temporary vault directories, a memory credential
// store and an in-process passphrase. Nothing here touches the developer's
// ~/.ward, the real keychain or a real terminal.
import "./support/no-real-keychain.ts";
import { afterAll, describe, expect, test } from "bun:test";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type { PassphraseSource } from "../src/application/backup.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import { backupLimits } from "../src/domain/backup.ts";
import { parseVaultState, type VaultState } from "../src/domain/vault-state.ts";
import { MemoryKeychain } from "./support/memory-keychain.ts";

const SERVICE = "opum.ward.backup";
const PASSPHRASE = "correct horse battery staple";
const root = mkdtempSync(join(tmpdir(), "ward-backup-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let cases = 0;

// A terminal that types the same passphrase every time, and can be told it
// has no terminal at all.
class FixedPassphrase implements PassphraseSource {
  interactive = true;
  reads = 0;
  available(): boolean {
    return this.interactive;
  }
  read(): Uint8Array {
    this.reads += 1;
    return new TextEncoder().encode(PASSPHRASE);
  }
}

// What answers Ward's registration question, without a terminal.
const approver = {
  available: () => true,
  ask: () => "approved" as const,
};

// One machine: a vault directory, the credential store behind it, and the
// terminal. Two machines share nothing, which is the situation a restore is
// for.
function machine() {
  const directory = join(mkdtempSync(join(root, `case-${++cases}-`)), ".ward");
  const keychain = new MemoryKeychain();
  const passphrases = new FixedPassphrase();
  const store = createSqliteVaultStore({ directory });
  const keyProvider = createKeychainKeyProvider({
    service: SERVICE,
    entry: keychain.entry,
  });
  return {
    directory,
    keychain,
    passphrases,
    store,
    keyProvider,
    options: (cwd: string): RunOptions => ({
      wardDirectory: directory,
      keyProvider,
      passphrases,
      cwd,
    }),
    header: () => store.header(),
    state: (key: Uint8Array): VaultState =>
      parseVaultState(store.read(key).plaintext),
  };
}

type Machine = ReturnType<typeof machine>;

function storedKey(machine: Machine): Uint8Array {
  const value = [...machine.keychain.items.values()][0];
  if (!Array.isArray(value)) throw new Error("no key is stored");
  return new Uint8Array(value as number[]);
}

// A checkout with a `.git` entry, so `ward init` has a root to bind.
function worktree(): string {
  const directory = mkdtempSync(join(root, `repo-${++cases}-`));
  mkdirSync(join(directory, ".git"));
  return directory;
}

function backupPath(): string {
  return join(mkdtempSync(join(root, `out-${++cases}-`)), "backup.json");
}

const json = (output: string) =>
  JSON.parse(output) as { kind: string; data: Record<string, unknown> };
const errorCode = (stderr: string) =>
  (JSON.parse(stderr) as { code: string }).code;

// A machine with a vault, a registered checkout, and a backup of it.
async function backedUp() {
  const origin = machine();
  const checkout = worktree();
  const setup = await runWard(["setup", "--json"], origin.options(checkout));
  expect(setup.exitCode).toBe(exitCodes.success);
  const init = await runWard(["init", "--json"], {
    ...origin.options(checkout),
    approver,
  });
  expect(init.exitCode).toBe(exitCodes.success);
  const path = backupPath();
  const backup = await runWard(
    ["backup", "--output", path, "--json"],
    origin.options(checkout),
  );
  expect(backup.exitCode).toBe(exitCodes.success);
  return {
    origin,
    checkout,
    path,
    projectId: json(init.stdout).data.projectId as string,
    backup: json(backup.stdout).data,
  };
}

describe("T20: a backup opens with only its passphrase", () => {
  test("restoring into a fresh machine keeps projects and clears bindings", async () => {
    const { origin, checkout, path, projectId, backup } = await backedUp();

    // The file is owner-only, and holds no plaintext: the project id the
    // source vault carries appears nowhere in it.
    expect(lstatSync(path).mode & 0o777).toBe(0o600);
    const text = readFileSync(path, "utf8");
    expect(text).not.toContain(projectId);
    expect(text.endsWith("\n")).toBe(true);

    // A machine that shares nothing with the first: a new vault directory
    // and a credential store with no item in it.
    const restored = machine();
    expect(restored.header()).toBeUndefined();

    const result = await runWard(
      ["restore", "--input", path, "--json"],
      restored.options(worktree()),
    );
    expect(result.exitCode).toBe(exitCodes.success);
    const data = json(result.stdout).data;
    expect(data.backupVaultId).toBe(backup.vaultId as string);
    expect(data.vaultId).not.toBe(backup.vaultId);
    expect(data.bindings).toBe("cleared");
    expect(data.projects).toBe(1);

    // The restored vault opens under the key this machine minted, and its
    // state carries the project and no binding.
    const key = storedKey(restored);
    expect(data.vaultId).toBe(restored.header()?.vaultId as string);
    const state = restored.state(key);
    expect(state.projects.map((project) => project.id)).toEqual([projectId]);
    expect(state.localBindings).toEqual([]);
    // T21: the key is fresh, not the original, and the original is untouched.
    expect([...key]).not.toEqual([...storedKey(origin)]);
    expect(origin.header()?.vaultId).toBe(backup.vaultId as string);
  });

  test("the restored checkout registers again instead of inheriting its binding", async () => {
    const { checkout, path } = await backedUp();
    const restored = machine();
    expect(
      (
        await runWard(
          ["restore", "--input", path, "--json"],
          restored.options(checkout),
        )
      ).exitCode,
    ).toBe(exitCodes.success);

    // T21's "bindings absent pending review": the checkout the backup was
    // taken from is not bound on the restored machine, and registering it is
    // asked for again rather than granted.
    const asked: string[] = [];
    const init = await runWard(["init", "--json"], {
      ...restored.options(checkout),
      approver: {
        available: () => true,
        ask: (request: { projectId: string }) => {
          asked.push(request.projectId);
          return "approved" as const;
        },
      },
    });
    expect(init.exitCode).toBe(exitCodes.success);
    expect(json(init.stdout).data.registration).toBe("registered");
    expect(asked).toHaveLength(1);
  });

  test("a wrong passphrase is refused and the destination stays empty", async () => {
    const { path } = await backedUp();
    const restored = machine();
    restored.passphrases.read = () =>
      new TextEncoder().encode("not the passphrase at all");
    const result = await runWard(
      ["restore", "--input", path, "--json"],
      restored.options(worktree()),
    );
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(errorCode(result.stderr)).toBe("backup_open_failed");
    expect(restored.header()).toBeUndefined();
    expect(restored.keychain.items.size).toBe(0);
  });

  test("a changed byte is refused, in the ciphertext and in the header", async () => {
    const { path } = await backedUp();
    for (const [label, mutate] of [
      [
        "ciphertext",
        (document: Record<string, unknown>) => {
          const sealed = document.ciphertext as string;
          document.ciphertext =
            (sealed[0] === "A" ? "B" : "A") + sealed.slice(1);
        },
      ],
      [
        "header",
        (document: Record<string, unknown>) => {
          document.revision = (document.revision as number) + 1;
        },
      ],
      [
        "parameter set",
        (document: Record<string, unknown>) => {
          (document.kdf as Record<string, unknown>).r = 16;
        },
      ],
    ] as [string, (document: Record<string, unknown>) => void][]) {
      const damaged = backupPath();
      const document = JSON.parse(readFileSync(path, "utf8")) as Record<
        string,
        unknown
      >;
      mutate(document);
      writeFileSync(damaged, `${JSON.stringify(document, null, 2)}\n`);
      const restored = machine();
      const result = await runWard(
        ["restore", "--input", damaged, "--json"],
        restored.options(worktree()),
      );
      expect(result.exitCode, label).toBe(exitCodes.validation);
      expect(
        ["backup_open_failed", "backup_unsupported", "backup_malformed"],
        label,
      ).toContain(errorCode(result.stderr));
      expect(restored.header(), label).toBeUndefined();
    }
  });

  test("a hostile parameter set is refused before anything is derived", async () => {
    // A weak set would derive quickly and open nothing; a huge one would ask
    // for gigabytes. Both are refused by name, from the file, before the KDF
    // runs at all — which is what the elapsed bound below is measuring.
    for (const parameters of [
      { N: 2, r: 1, p: 1 },
      { N: 1_073_741_824, r: 8, p: 1 },
    ]) {
      const { path } = await backedUp();
      const hostile = backupPath();
      const document = JSON.parse(readFileSync(path, "utf8")) as Record<
        string,
        unknown
      >;
      Object.assign(document.kdf as Record<string, unknown>, parameters);
      writeFileSync(hostile, `${JSON.stringify(document, null, 2)}\n`);
      const restored = machine();
      const started = Date.now();
      const result = await runWard(
        ["restore", "--input", hostile, "--json"],
        restored.options(worktree()),
      );
      expect(result.exitCode).toBe(exitCodes.validation);
      expect(errorCode(result.stderr)).toBe("backup_unsupported");
      // Deriving under the huge set would take far longer than this, and
      // deriving under the weak one would not be refused as unsupported.
      expect(Date.now() - started).toBeLessThan(2_000);
      expect(restored.keychain.items.size).toBe(0);
    }
  });

  test("an oversized file is refused without being read into the vault", async () => {
    const restored = machine();
    const oversized = backupPath();
    writeFileSync(oversized, "x".repeat(backupLimits.maxContainerBytes + 1));
    const result = await runWard(
      ["restore", "--input", oversized, "--json"],
      restored.options(worktree()),
    );
    expect(result.exitCode).toBe(exitCodes.validation);
    expect(errorCode(result.stderr)).toBe("backup_too_large");
    expect(restored.header()).toBeUndefined();
  });

  test("without a terminal, the credential store is never reached", async () => {
    const origin = machine();
    const checkout = worktree();
    expect(
      (await runWard(["setup", "--json"], origin.options(checkout))).exitCode,
    ).toBe(exitCodes.success);
    origin.passphrases.interactive = false;
    const reads = origin.keychain.readAttempts;

    const backup = await runWard(
      ["backup", "--output", backupPath(), "--json"],
      origin.options(checkout),
    );
    expect(backup.exitCode).toBe(exitCodes.denied);
    expect(errorCode(backup.stderr)).toBe("backup_requires_terminal");
    expect(origin.keychain.readAttempts).toBe(reads);

    // Restore is checked on a machine with no vault: a destination that
    // already exists is refused before the terminal is even consulted, which
    // is its own test below.
    const added = machine();
    added.passphrases.interactive = false;
    const restore = await runWard(
      ["restore", "--input", backupPath(), "--json"],
      added.options(checkout),
    );
    expect(restore.exitCode).toBe(exitCodes.denied);
    expect(errorCode(restore.stderr)).toBe("backup_requires_terminal");
    expect(added.keychain.readAttempts).toBe(0);
  });

  test("an existing file is never replaced, and no vault means no backup", async () => {
    const { origin, checkout, path } = await backedUp();
    const existing = "do not replace me\n";
    writeFileSync(path, existing);
    const refused = await runWard(
      ["backup", "--output", path, "--json"],
      origin.options(checkout),
    );
    expect(refused.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(refused.stderr)).toBe("backup_file_exists");
    expect(readFileSync(path, "utf8")).toBe(existing);

    const empty = machine();
    const missing = await runWard(
      ["backup", "--output", backupPath(), "--json"],
      empty.options(worktree()),
    );
    expect(missing.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(missing.stderr)).toBe("vault_not_found");
  });

  test("a restore never lands in a vault that already exists", async () => {
    const { path } = await backedUp();
    const destination = machine();
    const checkout = worktree();
    expect(
      (await runWard(["setup", "--json"], destination.options(checkout)))
        .exitCode,
    ).toBe(exitCodes.success);
    const before = destination.header();
    const keyBefore = [...storedKey(destination)];

    const result = await runWard(
      ["restore", "--input", path, "--json"],
      destination.options(checkout),
    );
    expect(result.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(result.stderr)).toBe("vault_exists");
    expect(destination.header()?.vaultId).toBe(before?.vaultId);
    expect(destination.header()?.revision).toBe(before?.revision);
    expect([...storedKey(destination)]).toEqual(keyBefore);
  });
});
