// T16's TLS-disable attempt. Run as a subprocess with
// NODE_TLS_REJECT_UNAUTHORIZED=0 already in the environment: Bun reads the
// variable when the process starts, so an in-process assignment would be
// measuring a variable the runtime had already read and would pass whether or
// not the transport honoured it.
//
// The invocation carries its own control. A plain `https.request` to a server
// whose certificate neither chains to a trusted root nor names the host is made
// first; with verification switched off by the variable it is answered, which
// shows the variable is live in this process. Only then is Ward's transport
// asked for a request to the same server with a certificate for the WRONG
// name. The parent's assertion is the pair: the control responded, and the
// transport refused and the server received no request. A run whose control
// did not respond proves only that the variable was inert, and is reported as
// that rather than as a pass.
import { readFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import { createServer } from "node:tls";
import { createHttpsTransport } from "../../src/adapters/https-transport.ts";

const read = (name: string): string =>
  readFileSync(join(import.meta.dir, "tls", name), "utf8");

let requests = 0;
const server = createServer(
  {
    key: read("other.example.invalid.key"),
    cert: read("other.example.invalid.pem"),
  },
  (socket) => {
    socket.on("data", () => {
      requests++;
      socket.end("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    });
  },
);
await new Promise<void>((resolve) =>
  server.listen(0, "127.0.0.1", () => resolve()),
);
const port = (server.address() as { port: number }).port;

const control = await new Promise<string>((resolve) => {
  const request = https.request(
    { hostname: "127.0.0.1", port, method: "GET", path: "/" },
    (response) => {
      response.resume();
      resolve("responded");
    },
  );
  request.on("error", (error: NodeJS.ErrnoException) =>
    resolve(`error:${error.code ?? "unknown"}`),
  );
  request.end();
  setTimeout(() => resolve("timeout"), 5_000);
});
const afterControl = requests;

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
console.log(
  JSON.stringify({
    control,
    outcome,
    requestsFromTransport: requests - afterControl,
  }),
);
process.exit(0);
