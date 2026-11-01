// WCLI-97 / W-2: a paste that carries more than a hidden read consumes must
// not be left for the shell.
//
// A hidden read ends on the newline that terminates the value. Any bytes a
// paste carried after it stay in the terminal's input queue, and when Ward
// restores echo and exits the shell reads them as its own input — and can run
// them. The adapters drain until the terminal is quiet and call tcflush(TCIFLUSH)
// on every exit path; these cases prove it on a real pty rather than over the
// descriptor seam.
//
// The harness runs the probe under `script(1)`, so the probe's stdin really is
// a terminal. After the probe exits, the shell running it (`sh`) performs the
// next read on the same terminal — exactly what a prompt would do — and
// prints what it got. A leak shows up as the shell reading a pasted line
// before the harness has sent one.
import "./support/no-real-keychain.ts";
import { expect, test } from "bun:test";
import { join } from "node:path";

const probe = join(import.meta.dir, "support", "pty-probe.ts");

// Qualified on darwin, the ship target. Linux CI would run util-linux's
// script(1) instead, whose stdin relay and exit semantics were not measurable
// from here; skipping with this reason beats a test that silently proves
// nothing. The tcflush selector is per-platform regardless
// (src/adapters/terminal-input.ts). To qualify the harness on Linux, run this
// file there and delete the skip.
const ptySupported = (): boolean => process.platform === "darwin";

// Register the case, or a skipped case whose NAME carries the reason: Bun
// reports a skipped test without a reason, and a silently skipped PTY test
// would read as a passing one.
function scenario(
  name: string,
  run: () => Promise<void>,
  timeout: number,
): void {
  if (ptySupported()) {
    test(name, run, timeout);
    return;
  }
  test.skip(`${name} [skipped: the pty harness is qualified on darwin only; to qualify it on Linux, run this file there and remove the skip]`, () => {});
}

// Drive one probe scenario. The paste is written only once the probe reports
// its read is waiting with echo off, and the harness's own line is written
// only once the probe is done, so a leftover byte can only be one the flush
// failed to discard.
async function runScenario(mode: string, paste: string): Promise<string> {
  // PTY_PROBE_BINARY names a `bun build --compile` of the probe, so the same
  // cases can run against compiled code (WCLI-97 AC4); the default is the source.
  const command = process.env.PTY_PROBE_BINARY
    ? JSON.stringify(process.env.PTY_PROBE_BINARY)
    : `bun run ${JSON.stringify(probe)}`;
  const inner = `${command} ${mode}; read line; printf 'RESULT:%s\\n' "$line"`;
  // `cat` is load-bearing: Bun's stdio pipe is a socket on macOS, and
  // script(1) refuses a socket on its stdin while it accepts the shell pipe
  // cat's stdout creates.
  const wrapper =
    process.platform === "darwin"
      ? `cat | script -q /dev/null sh -c "$PTY_INNER"`
      : `cat | script -q -c "$PTY_INNER" /dev/null`;

  const child = Bun.spawn(["sh", "-c", wrapper], {
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, PTY_INNER: inner },
  });

  const decoder = new TextDecoder();
  let output = "";
  let phase: "ready" | "paste" | "done" | "after" = "ready";
  const pump = (async () => {
    for await (const chunk of child.stdout as ReadableStream<Uint8Array>) {
      output += decoder.decode(chunk, { stream: true });
      if (phase === "ready" && output.includes("PROBE-READY")) {
        phase = "paste";
        child.stdin.write(paste);
      }
      if (phase === "paste" && output.includes("PROBE-DONE")) {
        phase = "done";
        child.stdin.write("AFTER\n");
      }
      // Close only once the shell has reported what its read received:
      // closing sooner can deliver the end-of-input byte ahead of the line,
      // and the shell then reads EOF instead of the harness's line.
      if (phase === "done" && output.includes("RESULT:")) {
        phase = "after";
        child.stdin.end();
      }
    }
  })();
  const errPump = (async () => {
    const text = await new Response(
      child.stderr as ReadableStream<Uint8Array>,
    ).text();
    if (text.trim() !== "") output += `\nSTDERR:${text}`;
  })();

  let fire: () => void = () => {};
  const timeout = new Promise<"timeout">((resolve) => {
    fire = () => resolve("timeout");
  });
  const timer = setTimeout(fire, 8_000);
  const finished = await Promise.race([
    child.exited.then(() => "exit" as const),
    timeout,
  ]);
  clearTimeout(timer);
  if (finished === "timeout") {
    child.kill();
    throw new Error(
      `PTY scenario "${mode}" timed out: ${JSON.stringify(output)}`,
    );
  }
  await pump.catch(() => {});
  await errPump.catch(() => {});
  return output;
}

function expectNothingReachedTheShell(output: string, marker: string): void {
  expect(output).toContain("PROBE-READY");
  expect(output).toContain("PROBE-DONE");
  expect(output).toContain(marker);
  // The shell's next read is the harness line, not a byte of the paste.
  expect(output).toContain("RESULT:AFTER");
  expect(output).not.toContain("RESULT:LEAK");
  // The paste's own marker never appears anywhere: not echoed, not read.
  expect(output).not.toContain("LEAK-ONE");
  expect(output).not.toContain("LEAK-TWO");
}

scenario(
  "a multiline paste leaves nothing queued for the shell",
  async () => {
    const output = await runScenario("secret", "s3cret\nLEAK-ONE\nLEAK-TWO\n");
    // Six bytes read, and the two lines after the terminator are gone.
    expectNothingReachedTheShell(output, "LEN:6");
  },
  20_000,
);

scenario(
  "a Ctrl-C cancel leaves nothing queued for the shell",
  async () => {
    const output = await runScenario(
      "secret",
      "half\u0003LEAK-ONE\nLEAK-TWO\n",
    );
    // Cancelling abandons the read; the queue is still discarded.
    expectNothingReachedTheShell(output, "LEN:0");
  },
  20_000,
);

scenario(
  "a passphrase reading leaves nothing queued for the shell",
  async () => {
    const output = await runScenario(
      "passphrase",
      "pass\nLEAK-ONE\nLEAK-TWO\n",
    );
    expectNothingReachedTheShell(output, "LEN:4");
  },
  20_000,
);

scenario(
  "a passphrase past its bound refuses and leaves nothing queued",
  async () => {
    // One byte past 1024, then the lines a paste would have carried after it.
    // The old reader truncated and returned; this one refuses, and whatever
    // remains queued is discarded before the shell gets a chance at it.
    const paste = `${"a".repeat(1025)}\nLEAK-ONE\nLEAK-TWO\n`;
    const output = await runScenario("passphrase", paste);
    expectNothingReachedTheShell(output, "REFUSED:backup_passphrase_too_large");
  },
  20_000,
);

// A paste larger than the tty input queue: a pty applies flow control to the
// master's writes once the slave's queue nears its high-water mark, so part of
// a long paste (a multi-line PEM key is 1.6 to 3.2 KB) can still be in the
// writer's buffer when the read returns on the first newline. A single
// tcflush would then unblock the writer and the tail would land after it.
const LONG_TAIL = Array.from(
  { length: 800 },
  (_, index) => `LEAK-${index}`,
).join("\n");

function expectNoTailReachedAnything(output: string): void {
  expect(output).toContain("PROBE-DONE");
  expect(output).toContain("RESULT:AFTER");
  expect(output).not.toContain("RESULT:LEAK");
  expect(output).not.toContain("LEAK-");
}

scenario(
  "a paste with a tail past the tty queue leaves nothing for the shell (secret)",
  async () => {
    const output = await runScenario("secret", `s3cret\n${LONG_TAIL}\n`);
    expect(output).toContain("LEN:6");
    expectNoTailReachedAnything(output);
  },
  20_000,
);

scenario(
  "a paste with a tail past the tty queue leaves nothing for the shell (passphrase)",
  async () => {
    const output = await runScenario("passphrase", `pass\n${LONG_TAIL}\n`);
    expect(output).toContain("LEN:4");
    expectNoTailReachedAnything(output);
  },
  20_000,
);

scenario(
  "a refused bound passphrase with a tail past the tty queue leaves nothing",
  async () => {
    const output = await runScenario(
      "passphrase",
      `${"a".repeat(1025)}\n${LONG_TAIL}\n`,
    );
    expect(output).toContain("REFUSED:backup_passphrase_too_large");
    expectNoTailReachedAnything(output);
  },
  20_000,
);
