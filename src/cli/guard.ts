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

// @napi-rs/keyring's loader reads NAPI_RS_* variables when the binding is
// first imported, after this module has run. NAPI_RS_NATIVE_LIBRARY_PATH
// loads any module in place of the binding; NAPI_RS_FORCE_WASI=error and
// NAPI_RS_WASI_FLAVOR make the import throw. All measured under WCLI-5.
// Deleting every NAPI_RS_ key here closes them. BUN_OPTIONS and BUN_BE_BUN
// act before any Ward code and cannot be closed this way (WCLI-19).
for (const name of Object.keys(process.env))
  if (name.startsWith("NAPI_RS_")) delete process.env[name];

process.on("uncaughtException", emitUncaughtAndExit);
process.on("unhandledRejection", emitUncaughtAndExit);
