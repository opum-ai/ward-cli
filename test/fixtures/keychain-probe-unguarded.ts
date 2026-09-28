// The control for keychain-probe.ts: the same adapter import without the
// guard, so a native-binding override is expected to load.
import { keychainService } from "../../src/adapters/keychain.ts";

process.stdout.write(`${JSON.stringify({ service: keychainService })}\n`);
