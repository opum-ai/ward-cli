// Replaces @napi-rs/keyring so that constructing a real credential-store
// entry fails loudly instead of reaching the developer's keychain. It is
// preloaded by bunfig.toml when `bun test` runs from the repository root,
// and every test that can reach the adapter imports it first as well, since
// Bun reads bunfig.toml from the working directory only. Compiled fixtures
// are separate processes and are not covered; none of them calls the store.
import { mock } from "bun:test";

export const realKeychainRefusal =
  "test processes must not reach the real credential store";

class Refused {
  constructor() {
    throw new Error(realKeychainRefusal);
  }
}

mock.module("@napi-rs/keyring", () => ({
  AsyncEntry: Refused,
  Entry: Refused,
}));
