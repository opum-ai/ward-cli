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
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBackupFiles } from "../src/adapters/backup-file.ts";
import { createKeychainKeyProvider } from "../src/adapters/keychain.ts";
import { createSqliteVaultStore } from "../src/adapters/sqlite-vault-store.ts";
import type { PassphraseSource } from "../src/application/backup.ts";
import { runWard, type RunOptions } from "../src/cli/main.ts";
import { profileSnapshotVersion } from "../src/domain/profile.ts";
import { exitCodes } from "../src/contract/envelope.ts";
import {
  backupAssociatedData,
  backupLimits,
  deriveBackupKey,
  encodeBackup,
  newBackupKdf,
  sealBackup,
} from "../src/domain/backup.ts";
import { generateVaultKey } from "../src/domain/envelope.ts";
import { decodeSecretValue } from "../src/domain/secret.ts";
import {
  emptyVaultState,
  parseVaultState,
  serializeVaultState,
  type VaultState,
} from "../src/domain/vault-state.ts";
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
const codeOf = (run: () => unknown): string | undefined => {
  try {
    run();
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
};

// A machine with a vault, a registered checkout, and a backup of it. When a
// secret is asked for, it is stored before the backup is taken, so the file
// carries it.
async function backedUp(
  options: { secret?: { alias: string; value: Uint8Array } } = {},
) {
  const origin = machine();
  const checkout = worktree();
  const setup = await runWard(["setup", "--json"], origin.options(checkout));
  expect(setup.exitCode).toBe(exitCodes.success);
  const init = await runWard(["init", "--json"], {
    ...origin.options(checkout),
    approver,
  });
  expect(init.exitCode).toBe(exitCodes.success);
  if (options.secret !== undefined) {
    const stored = await runWard(
      ["secret", "set", options.secret.alias, "--stdin", "--json"],
      {
        ...origin.options(checkout),
        secrets: {
          available: () => false,
          readHidden: () => undefined,
          readStdin: () => options.secret!.value.slice(),
          confirmReplace: () => false,
        },
      },
    );
    expect(stored.exitCode).toBe(exitCodes.success);
  }
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

// A machine whose vault holds `document` verbatim, with its key in the
// memory credential store. The bytes are the ones given — nothing here goes
// through `ward setup` — so this is the fixture for a state document that
// decrypts and does not parse (WCLI-52).
async function machineHolding(document: Uint8Array) {
  const vault = machine();
  const vaultId = randomUUID();
  const key = generateVaultKey();
  await vault.keyProvider.create(vaultId, key);
  vault.store.create(vaultId, key, document);
  key.fill(0);
  return vault;
}

describe("T20: a backup opens with only its passphrase", () => {
  test("restoring into a fresh machine keeps projects and clears bindings", async () => {
    const { origin, path, projectId, backup } = await backedUp();

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

  test("a restore keeps secret records and clears only bindings", async () => {
    const secretBytes = new TextEncoder().encode("restored-sentinel-9d2f");
    const { path } = await backedUp({
      secret: { alias: "kept-alias", value: secretBytes },
    });

    const restored = machine();
    const result = await runWard(
      ["restore", "--input", path, "--json"],
      restored.options(worktree()),
    );
    expect(result.exitCode).toBe(exitCodes.success);

    const state = restored.state(storedKey(restored));
    expect(state.localBindings).toEqual([]);
    expect(state.secrets).toHaveLength(1);
    const record = state.secrets[0];
    if (record === undefined) throw new Error("no record");
    expect(record.alias).toBe("kept-alias");
    // The value bytes survive the container and the fresh key exactly.
    expect(decodeSecretValue(record.value)).toEqual(secretBytes);
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
    // Three shapes: a weak set that would derive quickly and open nothing, a
    // huge one that would ask for gigabytes, and the canonical N and r with
    // another p, which needs no extra memory at all and only costs time —
    // measured at 540 ms per derivation under the same bound. The exact
    // match is what stops all three, and the assertion that discriminates is
    // the code: without it a weak set derives and fails differently, and the
    // other two are stopped by Node's own maxmem, not by Ward.
    for (const parameters of [
      { N: 2, r: 1, p: 1 },
      { N: 1_073_741_824, r: 8, p: 1 },
      { N: 131_072, r: 8, p: 4 },
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
      const result = await runWard(
        ["restore", "--input", hostile, "--json"],
        restored.options(worktree()),
      );
      expect(result.exitCode, JSON.stringify(parameters)).toBe(
        exitCodes.validation,
      );
      expect(errorCode(result.stderr), JSON.stringify(parameters)).toBe(
        "backup_unsupported",
      );
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

    // A directory at the path is the same refusal. What is there is not a
    // file, so the message names both shapes rather than claiming a file.
    const directory = mkdtempSync(join(root, `occupied-${++cases}-`));
    const asDirectory = await runWard(
      ["backup", "--output", directory, "--json"],
      origin.options(checkout),
    );
    expect(asDirectory.exitCode).toBe(exitCodes.conflict);
    expect(errorCode(asDirectory.stderr)).toBe("backup_file_exists");
    expect(readdirSync(directory)).toEqual([]);

    const empty = machine();
    const missing = await runWard(
      ["backup", "--output", backupPath(), "--json"],
      empty.options(worktree()),
    );
    expect(missing.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(missing.stderr)).toBe("vault_not_found");
  });

  test("a path that cannot be read as a backup is refused on the read path", async () => {
    const { path } = await backedUp();

    // A directory, a FIFO and a link: none is a file Ward will read, and
    // Ward attempted neither a create nor a write, so the refusal does not
    // claim to be one.
    const directory = mkdtempSync(join(root, `read-dir-${++cases}-`));
    const fifo = join(root, `read-fifo-${++cases}`);
    expect(spawnSync("/usr/bin/mkfifo", [fifo]).status).toBe(0);
    const link = join(root, `read-link-${++cases}`);
    symlinkSync(path, link);

    for (const [label, input] of [
      ["a directory", directory],
      ["a FIFO", fifo],
      ["a link", link],
    ] as [string, string][]) {
      const destination = machine();
      const result = await runWard(
        ["restore", "--input", input, "--json"],
        destination.options(worktree()),
      );
      expect(result.exitCode, label).toBe(exitCodes.denied);
      expect(errorCode(result.stderr), label).toBe("backup_file_unreadable");
      expect(destination.header(), label).toBeUndefined();
    }
  });

  test("a missing path is still its own answer", async () => {
    const destination = machine();
    const absent = await runWard(
      ["restore", "--input", join(root, `absent-${++cases}`), "--json"],
      destination.options(worktree()),
    );
    expect(absent.exitCode).toBe(exitCodes.notFound);
    expect(errorCode(absent.stderr)).toBe("backup_not_found");
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

    // The guard is the *early* refusal, and it is load-bearing for more than
    // the exit code: without it the same conflict is reached only after the
    // developer is prompted, the backup is opened, and a key is created for
    // a vault id that will never exist. `store.create` refuses with the same
    // code, so the count of readings and items is what distinguishes the two
    // — and the key check above reads the first item only, which is why the
    // size is asserted separately.
    expect(destination.passphrases.reads).toBe(0);
    expect(destination.keychain.items.size).toBe(1);
    expect(destination.keychain.writeAttempts).toBe(1);
  });
});

// WCLI-52: a state document that decrypts and does not parse is refused
// before a backup exists.
//
// The envelope half of this path already refused before a file was created:
// `store.read` authenticates the latest snapshot, so a vault this build
// cannot open never reaches `files.create`. The document half did not —
// `runBackup` sealed the plaintext it had opened without parsing it, so a
// document this build cannot read backed up with exit 0 and a file that
// `ward restore` then refused, under text promising that "recovery from a
// lost key or a damaged vault needs this file and its passphrase". It is
// refused now, for the reason ADR 0010 gives: Ward has no recovery surface,
// so a file restore refuses has no defined use.
describe("WCLI-52: a document that does not parse is refused before a backup exists", () => {
  const encoder = new TextEncoder();

  test("no file is written, and no success output, for a document this build cannot read", async () => {
    // Two shapes of "does not parse", both of which `ward restore` refuses:
    // bytes that are not JSON, and JSON whose key set is not this build's
    // (ADR 0010's exact comparison, not a version gate).
    for (const [label, text] of [
      ["bytes that are not JSON", "{not a state document"],
      [
        "a key set this build does not write",
        '{"formatVersion":1,"fromAnotherBuild":[]}',
      ],
    ] as [string, string][]) {
      const origin = await machineHolding(encoder.encode(text));
      const path = backupPath();
      // Run without `--json`, so the human success text is this mode's
      // stdout: a build that still wrote the file would print "Backup
      // written." and the recovery sentence, which is what the absence
      // below measures. The same assertion under `--json` would be vacuous
      // twice over — a refusal's stdout is empty whatever its code
      // (main.ts `failure()`), and this text is not printed in that mode at
      // all.
      const attempted = await runWard(
        ["backup", "--output", path],
        origin.options(worktree()),
      );
      expect(attempted.exitCode, label).toBe(exitCodes.validation);
      // The catalogue's sentence, written out rather than imported: the
      // point is that the shipped text is this text, and an assertion that
      // read the catalogue would pass on any wording at all.
      expect(JSON.parse(attempted.stderr), label).toEqual({
        error_type: "validation",
        code: "vault_state_malformed",
        message:
          "The vault's contents are not a state document this Ward can read.",
        principal: null,
      });
      expect(existsSync(path), label).toBe(false);
      expect(attempted.stdout, label).not.toContain("Backup written");
    }
  });

  test("a stored approval this build cannot interpret is refused with its own code, and no file", async () => {
    // The same call gives one other answer, and `ward restore` gives the
    // same one for this document: a stored approval whose snapshot version
    // this build does not implement is `vault_format_unsupported` rather
    // than a damaged record (vault-state.ts, the second site DEC-38 left
    // standing beside the envelope). The record below is otherwise one this
    // build would write — only the version differs, which is the shape the
    // check exists for.
    const approval = {
      approvedAt: "2026-09-29T00:00:00.000Z",
      expiresAt: "2026-09-30T00:00:00.000Z",
      device: "1",
      inode: "2",
      profile: "example-profile",
      projectId: "33b05c92-8a6e-4f15-9dcb-65ae5d371123",
      root: "/tmp/wcli-52-checkout",
      snapshot: {
        adapter: "http",
        method: "GET",
        url: "https://api.example.invalid/rate_limit",
        auth: { type: "bearer", secret: "example.token" },
        headers: { Accept: "application/json" },
        requestBody: "none",
        output: "status",
      },
      snapshotVersion: profileSnapshotVersion + 1,
    };
    const document = encoder.encode(
      JSON.stringify({
        formatVersion: 1,
        projects: [],
        localBindings: [],
        secrets: [],
        auditRecords: [],
        profileApprovals: [approval],
      }),
    );
    const DEC_30 =
      "This vault was written by a different version of Ward, and this build cannot read it. Ward did not change it.";
    const origin = await machineHolding(document);
    const path = backupPath();
    const attempted = await runWard(
      ["backup", "--output", path],
      origin.options(worktree()),
    );
    expect(attempted.exitCode).toBe(exitCodes.validation);
    // The DEC-30 sentence, verbatim for the same reason as above.
    expect(JSON.parse(attempted.stderr)).toEqual({
      error_type: "validation",
      code: "vault_format_unsupported",
      message: DEC_30,
      principal: null,
    });
    expect(existsSync(path)).toBe(false);
    expect(attempted.stdout).not.toContain("Backup written");

    // And the symmetry is measured rather than claimed from the shared call:
    // a container holding this same document and sealed by the domain is
    // what `ward restore` refuses, with the same code and the same sentence.
    const kdf = newBackupKdf();
    const container = join(root, `wcli52-approval-${++cases}.json`);
    writeFileSync(
      container,
      encodeBackup(
        sealBackup(
          deriveBackupKey(encoder.encode(PASSPHRASE), kdf),
          { vaultId: randomUUID(), revision: 1, kdf },
          document,
        ),
      ),
    );
    const destination = machine();
    const restored = await runWard(
      ["restore", "--input", container, "--json"],
      destination.options(worktree()),
    );
    expect(restored.exitCode).toBe(exitCodes.validation);
    expect(JSON.parse(restored.stderr)).toEqual({
      error_type: "validation",
      code: "vault_format_unsupported",
      message: DEC_30,
      principal: null,
    });
    expect(destination.header()).toBeUndefined();
  });

  test("the same construction over a parseable document still writes, and it restores", async () => {
    // The control: identical fixture and command, only the document's bytes
    // differ, so a refusal coming from the fixture rather than from the
    // parse would show up here. The restore is the property the refusal
    // protects: every file `ward backup` writes, `ward restore` honours.
    const origin = await machineHolding(serializeVaultState(emptyVaultState()));
    const path = backupPath();
    const written = await runWard(
      ["backup", "--output", path, "--json"],
      origin.options(worktree()),
    );
    expect(written.exitCode).toBe(exitCodes.success);
    expect(existsSync(path)).toBe(true);

    const destination = machine();
    const restored = await runWard(
      ["restore", "--input", path, "--json"],
      destination.options(worktree()),
    );
    expect(restored.exitCode).toBe(exitCodes.success);
    expect(destination.header()).toBeDefined();
  });
});

describe("the backup file adapter", () => {
  test("a read bound is the adapter's own, whatever the caller asks for", () => {
    // The domain applies the same limit to the same number, so a
    // command-level test cannot tell the two apart: this is the descriptor
    // path, where a genuinely huge file would otherwise be loaded before
    // anything checked it.
    const path = join(root, `bound-${++cases}`);
    writeFileSync(path, "x".repeat(64));
    const files = createBackupFiles();
    expect(codeOf(() => files.read(path, 63))).toBe("backup_too_large");
    expect(files.read(path, 64).length).toBe(64);
  });

  test("a FIFO is refused without blocking", () => {
    // Without O_NONBLOCK, opening a writer-less FIFO does not return —
    // measured here, the open never comes back. The refusal itself comes
    // from the non-regular check either side of the open; the elapsed bound
    // is what would catch a blocking open returning to this path, and a
    // regression hangs the test rather than failing it quietly.
    const fifo = join(root, `fifo-${++cases}`);
    expect(spawnSync("/usr/bin/mkfifo", [fifo]).status).toBe(0);
    const files = createBackupFiles();
    const started = Date.now();
    expect(codeOf(() => files.read(fifo, 64))).toBe("backup_file_unreadable");
    // Measured for WCLI-53: 0-1 ms idle and under 2x- and 6x-overcommitted
    // CPU load, so this ceiling sits three orders of magnitude above the cost
    // it bounds. What a blocking open does instead is never return, and the
    // harness timeout is what ends that case; this ceiling's own band is a
    // return that took an implausibly long time.
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  test("a create never replaces what is there, whichever shape it is", () => {
    const files = createBackupFiles();
    const file = join(root, `no-replace-${++cases}`);
    writeFileSync(file, "mine\n");
    expect(codeOf(() => files.create(file, new Uint8Array([1])))).toBe(
      "backup_file_exists",
    );
    expect(readFileSync(file, "utf8")).toBe("mine\n");

    const directory = mkdtempSync(join(root, `no-replace-dir-${++cases}-`));
    expect(codeOf(() => files.create(directory, new Uint8Array([1])))).toBe(
      "backup_file_exists",
    );
    expect(readdirSync(directory)).toEqual([]);

    const link = join(root, `no-replace-link-${++cases}`);
    symlinkSync(file, link);
    expect(codeOf(() => files.create(link, new Uint8Array([1])))).toBe(
      "backup_file_unwritable",
    );
    expect(readFileSync(file, "utf8")).toBe("mine\n");
  });
});

describe("the container's authenticated header", () => {
  test("every field a reader relies on is bound by the tag", () => {
    // The AAD is what makes a relabelled container fail to open rather than
    // be interpreted, so each field it covers is asserted here directly:
    // changing any one of them changes the bytes the tag authenticates.
    const kdf = newBackupKdf();
    const header = {
      formatVersion: 1,
      vaultId: "33b05c92-8a6e-4f15-9dcb-65ae5d371123",
      revision: 1,
      kdf,
    };
    const base = backupAssociatedData(header);
    const changes = {
      vaultId: { ...header, vaultId: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d" },
      revision: { ...header, revision: 2 },
      "kdf salt": {
        ...header,
        kdf: { ...kdf, salt: new Uint8Array(32).fill(7) },
      },
    };
    for (const [label, changed] of Object.entries(changes)) {
      expect(
        Buffer.from(backupAssociatedData(changed)).toString("base64"),
        label,
      ).not.toBe(Buffer.from(base).toString("base64"));
    }

    // A parameter outside the v1 set is not merely authenticated, it cannot
    // be encoded at all: the same exact match that stops a derivation stops
    // the header first, so no code path can build a header a reader would
    // refuse to interpret.
    expect(
      codeOf(() => backupAssociatedData({ ...header, kdf: { ...kdf, p: 4 } })),
    ).toBe("backup_unsupported");
  });
});
