import { exitCodes } from "../contract/envelope.ts";
import { errorEnvelope, WardError } from "../contract/errors.ts";

// Registered at module evaluation, and ward.ts imports this module first, so
// the handlers are live before any other Ward module runs. A handler that
// arrived later would leave a window in which Bun prints an error's message
// and stack, which could carry argv.
function emitUncaughtAndExit(): never {
  process.stderr.write(
    `${JSON.stringify(errorEnvelope(new WardError("uncaught")))}\n`,
  );
  process.exit(exitCodes.uncaught);
}

// @napi-rs/keyring loads whatever module this variable names in place of its
// native binding, and it reads the variable only when the binding is first
// imported, after this module has run. Deleting it here closes that path;
// measured under WCLI-5. BUN_OPTIONS and BUN_BE_BUN act before any Ward code
// and cannot be closed this way (WCLI-19).
delete process.env.NAPI_RS_NATIVE_LIBRARY_PATH;

process.on("uncaughtException", emitUncaughtAndExit);
process.on("unhandledRejection", emitUncaughtAndExit);
