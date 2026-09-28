// Built by test/key-provider.test.ts through scripts/build.ts. It imports
// the guard first, as src/cli/ward.ts does, then the adapter, which loads
// the native binding. It never calls the credential store.
import "../../src/cli/guard.ts";
import {
  createKeychainKeyProvider,
  keychainService,
} from "../../src/adapters/keychain.ts";

const provider = createKeychainKeyProvider({ service: keychainService });
process.stdout.write(
  `${JSON.stringify({ service: keychainService, load: typeof provider.load })}\n`,
);
