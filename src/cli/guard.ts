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

process.on("uncaughtException", emitUncaughtAndExit);
process.on("unhandledRejection", emitUncaughtAndExit);
