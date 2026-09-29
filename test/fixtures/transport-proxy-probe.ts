// Does an ambient proxy move Ward's dial? Run as a subprocess with
// `HTTPS_PROXY` already in the environment, because that is the only way this
// question can be asked honestly: Bun reads the proxy variables when the
// process starts, so a test that set them in-process would be measuring a
// variable the runtime had already read — and would pass whether or not the
// transport honoured it.
//
// The invocation carries its own control. `https.request` is made first, to
// a host that cannot be reached, with the proxy pointed at the parent's
// listener; `node:https` in Bun honours the variable, so that request lands
// on the listener and the parent counts it. Only then is the real transport
// asked for a request to a local TLS server. The parent's assertion is the
// pair: the listener saw exactly one connection — the control's — and the
// transport still got its response. A run in which nothing reached the
// listener proves only that the variable was inert, and is reported as such
// rather than as a pass.
import { readFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import { createServer } from "node:tls";
import { createHttpsTransport } from "../../src/adapters/https-transport.ts";

const read = (name: string): string =>
  readFileSync(join(import.meta.dir, "tls", name), "utf8");

const control = (): Promise<string> =>
  new Promise((resolve) => {
    const request = https.request(
      { hostname: "control.invalid", port: 443, method: "GET", path: "/" },
      () => resolve("responded"),
    );
    request.on("error", (error: NodeJS.ErrnoException) =>
      resolve(`error:${error.code ?? "unknown"}`),
    );
    request.end();
    setTimeout(() => resolve("timeout"), 5_000);
  });

const server = createServer(
  {
    key: read("approved.example.invalid.key"),
    cert: read("approved.example.invalid.pem"),
  },
  (socket) => {
    socket.on("data", () =>
      socket.end("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
    );
  },
);
await new Promise<void>((resolve) =>
  server.listen(0, "127.0.0.1", () => resolve()),
);
const port = (server.address() as { port: number }).port;

const controlResult = await control();

const transport = createHttpsTransport({
  resolve: async () => [{ address: "127.0.0.1", family: 4 }],
  harness: { addressPolicy: () => true, ca: read("ca.pem") },
});
const outcome = await transport.send({
  url: `https://approved.example.invalid:${port}/rate_limit`,
  method: "GET",
  headers: [],
  authorization: {
    name: "Authorization",
    value: new TextEncoder().encode("Bearer synthetic"),
  },
  body: undefined,
});

server.close();
console.log(JSON.stringify({ control: controlResult, outcome }));
// The caller runs this synchronously and reads stdout, so a lingering
// handle — a socket, the control's fallback timer — must not keep the
// process alive. Exiting explicitly is the difference between a measurement
// and a timeout.
process.exit(0);
