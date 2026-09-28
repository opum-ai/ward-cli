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
  | "late-write"
  // Reads resolve, but only after lateMs.
  | "late-read"
  // Writes reject.
  | "writes-fail"
  // Reads succeed until the first write attempt, then reject.
  | "fail-after-write"
  // Reads succeed until the first write attempt, then never settle.
  | "hang-after-write";

export class MemoryKeychain {
  readonly items = new Map<string, unknown>();
  mode: StoreMode = "normal";
  lateMs = 0;
  readAttempts = 0;
  writeAttempts = 0;
  // Every value getSecret handed out, so a test can see whether it was
  // overwritten afterwards.
  readonly handedOut: unknown[] = [];

  entry: EntryFactory = (service, account): SecretEntry => {
    const id = `${service}\u0000${account}`;
    const refused = () =>
      Promise.reject(
        new Error("Platform failure: User interaction is not allowed."),
      );
    return {
      getSecret: async () => {
        this.readAttempts += 1;
        const afterWrite = this.writeAttempts > 0;
        if (
          this.mode === "locked" ||
          this.mode === "reads-fail" ||
          (this.mode === "fail-after-write" && afterWrite)
        )
          return refused();
        if (
          this.mode === "hang" ||
          (this.mode === "hang-after-write" && afterWrite)
        )
          return new Promise<never>(() => {});
        if (this.mode === "late-read")
          await new Promise((resolve) => setTimeout(resolve, this.lateMs));
        const stored = this.items.get(id);
        if (stored === undefined) return null;
        const value = Array.isArray(stored) ? [...stored] : stored;
        this.handedOut.push(value);
        return value;
      },
      setSecret: async (secret) => {
        this.writeAttempts += 1;
        if (this.mode === "locked" || this.mode === "writes-fail")
          return refused();
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
