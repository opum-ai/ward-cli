// An in-memory stand-in for the credential store behind @napi-rs/keyring.
// It reproduces the binding's measured shape (WCLI-5): secrets resolve as a
// plain number[], and an absent item as null. Attempts are counted before
// any failure mode applies, so a test can see a write that was tried even
// when the store then refuses it.
import type { EntryFactory, SecretEntry } from "../../src/adapters/keychain.ts";

export type StoreMode =
  | "normal"
  // Reads and writes reject, as a locked keychain does.
  | "locked"
  // Reads and writes never settle.
  | "hang"
  // Reads reject; writes succeed.
  | "reads-fail"
  // Writes store different bytes from the ones given.
  | "write-corrupt"
  // Writes land, but only confirm after lateMs.
  | "late-write";

export class MemoryKeychain {
  readonly items = new Map<string, unknown>();
  mode: StoreMode = "normal";
  lateMs = 0;
  readAttempts = 0;
  writeAttempts = 0;

  entry: EntryFactory = (service, account): SecretEntry => {
    const id = `${service}\u0000${account}`;
    const refused = () =>
      Promise.reject(
        new Error("Platform failure: User interaction is not allowed."),
      );
    return {
      getSecret: async () => {
        this.readAttempts += 1;
        if (this.mode === "locked" || this.mode === "reads-fail")
          return refused();
        if (this.mode === "hang") return new Promise<never>(() => {});
        const stored = this.items.get(id);
        if (stored === undefined) return null;
        return Array.isArray(stored) ? [...stored] : stored;
      },
      setSecret: async (secret) => {
        this.writeAttempts += 1;
        if (this.mode === "locked") return refused();
        if (this.mode === "hang") return new Promise<never>(() => {});
        const bytes = [...secret];
        if (this.mode === "write-corrupt") bytes[0] = (bytes[0] ?? 0) ^ 0xff;
        this.items.set(id, bytes);
        if (this.mode === "late-write")
          await new Promise((resolve) => setTimeout(resolve, this.lateMs));
      },
    };
  };
}
