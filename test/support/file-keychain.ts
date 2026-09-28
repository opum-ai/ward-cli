// A file-backed stand-in for the credential store, for tests that kill a
// setup process and rerun it: the key must survive the kill, which the
// in-memory MemoryKeychain cannot. Each item is a 0600 file whose content
// is the stored bytes. Never used outside tests.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { EntryFactory, SecretEntry } from "../../src/adapters/keychain.ts";

export class FileKeychain {
  readonly writes = new Map<string, number>();

  constructor(private readonly directory: string) {}

  entry: EntryFactory = (service, account): SecretEntry => {
    const id = createHash("sha256")
      .update(`${service}\u0000${account}`)
      .digest("hex")
      .slice(0, 16);
    const path = join(this.directory, id);
    return {
      getSecret: async () => {
        try {
          return [...readFileSync(path)];
        } catch (error) {
          if (
            typeof error === "object" &&
            error !== null &&
            (error as { code?: unknown }).code === "ENOENT"
          )
            return null;
          throw error;
        }
      },
      setSecret: async (secret) => {
        this.writes.set(id, (this.writes.get(id) ?? 0) + 1);
        writeFileSync(path, Buffer.from(secret), { mode: 0o600 });
      },
    };
  };
}
