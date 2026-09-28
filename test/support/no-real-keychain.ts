// Preloaded into every `bun test` process by bunfig.toml. Any attempt to
// construct a real credential-store entry fails loudly instead of reaching
// the developer's keychain. Compiled fixtures are separate processes and
// are not covered; none of them calls the store.
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
