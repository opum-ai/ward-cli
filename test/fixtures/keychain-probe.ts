// Built by test/key-provider.test.ts through scripts/build.ts: proves the
// native binding embeds in, and loads from, the shipped kind of executable.
// It never calls the credential store.
import {
  createKeychainKeyProvider,
  keychainService,
} from "../../src/adapters/keychain.ts";

const provider = createKeychainKeyProvider();
process.stdout.write(
  `${JSON.stringify({ service: keychainService, load: typeof provider.load })}\n`,
);
