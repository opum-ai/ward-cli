// An in-memory stand-in for the credential store behind @napi-rs/keyring.
// It reproduces the binding's measured shape (WCLI-5): secrets resolve as a
// plain number[], and an absent item as null.
import type { EntryFactory, SecretEntry } from "../../src/adapters/keychain.ts";

export type StoreMode = "normal" | "locked" | "hang";

export class MemoryKeychain {
  readonly items = new Map<string, number[]>();
  mode: StoreMode = "normal";
  writes = 0;

  entry: EntryFactory = (service, account): SecretEntry => {
    const id = `${service}\u0000${account}`;
    const gate = () => {
      if (this.mode === "locked")
        return Promise.reject(
          new Error("Platform failure: User interaction is not allowed."),
        );
      if (this.mode === "hang") return new Promise<never>(() => {});
      return Promise.resolve();
    };
    return {
      getSecret: async () => {
        await gate();
        const stored = this.items.get(id);
        return stored === undefined ? null : [...stored];
      },
      setSecret: async (secret) => {
        await gate();
        this.writes += 1;
        this.items.set(id, [...secret]);
      },
    };
  };
}
