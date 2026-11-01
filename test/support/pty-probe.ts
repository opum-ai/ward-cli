// The probe the real-PTY test runs (WCLI-97, W-2).
//
// It is a separate process so the readers see a genuine terminal: `script(1)`
// puts it behind a pty slave, which is what makes `process.stdin.isTTY` true
// and tcflush(2) meaningful. It drives the shipped adapters with their
// defaults, so the path exercised is the one a user gets — only `setRaw` is
// wrapped, to announce readiness once echo is off and the read is about to
// block. The bytes read are never printed; only their length, so a leaked
// value in the transcript is an immediate, visible failure.
import { createTerminalPassphrase } from "../../src/adapters/passphrase.ts";
import { createTerminalSecretValues } from "../../src/adapters/secret-value.ts";
import { WardError } from "../../src/contract/errors.ts";

const mode = process.argv[2];

function out(text: string): void {
  process.stdout.write(`${text}\n`);
}

// Announce readiness only once raw mode is on: the harness writes the paste
// strictly after echo is off and the read is waiting on it.
function setRaw(on: boolean): void {
  const stdin = process.stdin as { setRawMode?: (mode: boolean) => void };
  stdin?.setRawMode?.(on);
  if (on) out("PROBE-READY");
}

function codeOf(error: unknown): string {
  return error instanceof WardError ? error.code : "not-a-ward-error";
}

if (mode === "secret") {
  const values = createTerminalSecretValues({ setRaw });
  try {
    const read = values.readHidden();
    out(read === undefined ? "NONE" : `LEN:${read.length}`);
  } catch (error) {
    out(`REFUSED:${codeOf(error)}`);
  }
} else if (mode === "passphrase") {
  const source = createTerminalPassphrase({ setRaw });
  try {
    const read = source.read({ confirm: false });
    out(read === undefined ? "NONE" : `LEN:${read.length}`);
  } catch (error) {
    out(`REFUSED:${codeOf(error)}`);
  }
} else {
  out(`UNKNOWN-MODE:${mode}`);
}

out("PROBE-DONE");
