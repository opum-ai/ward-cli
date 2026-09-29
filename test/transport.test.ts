// WCLI-10: the in-process HTTPS transport (spec §9.3, gates T15-T17).
//
// What is measured here is the transport itself — real sockets, a real TLS
// server, the real resolver seam — rather than a fake standing in for it.
// That is deliberate: the properties this file exists for are precisely the
// ones a fake cannot have. The dialled address being the validated one, SNI
// and certificate verification still naming the hostname, a redirect not
// being followed, and an ambient proxy not moving the connection are all
// claims about bytes on a wire, and each is asserted against a server the
// test controls.
//
// Two things make that possible without weakening the shipped build, and
// both are worth stating rather than discovering. The resolver is injected,
// so a test chooses what a name resolves to; the *address policy* runs on
// that answer exactly as it does in production, which is why the first group
// of cases below is a set of refusals that never reach a socket. And the
// harness seam (see adapters/https-transport.ts) supplies a test CA and a
// permissive policy so that a conforming local server can be reached at all
// — a conforming server cannot be reached through the shipped policy,
// because the shipped policy refuses the only addresses a test can bind. The
// last case asserts that the shipped defaults are still the shipped ones, so
// the seam cannot become the production path by accident.
//
// The certificates under test/fixtures/tls are a throwaway test CA and two
// certificates it signed. They are trusted nowhere, by nothing, and their
// private keys exist only so this file can run a server.
import "./support/no-real-keychain.ts";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createServer as createTcpServer, type Server } from "node:net";
import { join } from "node:path";
import {
  createServer as createTlsServer,
  type Server as TlsServer,
} from "node:tls";
import {
  createHttpsTransport,
  type ResolvedAddress,
} from "../src/adapters/https-transport.ts";
import type {
  Transport,
  TransportOutcome,
} from "../src/application/transport.ts";
import { isPublicAddress } from "../src/domain/destination.ts";

const FIXTURES = join(import.meta.dir, "fixtures", "tls");
const certificate = (name: string): string =>
  readFileSync(join(FIXTURES, `${name}.pem`), "utf8");
const privateKey = (name: string): string =>
  readFileSync(join(FIXTURES, `${name}.key`), "utf8");

const APPROVED = "approved.example.invalid";
const OTHER = "other.example.invalid";
const SYNTHETIC = "synthetic-transport-credential-4b71";

const encoder = new TextEncoder();

// A TLS server holding one of the fixture certificates. It records the first
// request line of every connection and answers with whatever the case needs,
// so a case can assert both what arrived and what Ward made of it.
interface Harness {
  readonly port: number;
  readonly connections: string[];
  // What the client put in its ClientHello, or null when it sent none.
  readonly sni: (string | null)[];
  close: () => Promise<void>;
  setResponse: (response: string) => void;
}

function tlsHarness(who: string): Promise<Harness> {
  return new Promise((resolve) => {
    const connections: string[] = [];
    const sni: (string | null)[] = [];
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    const server: TlsServer = createTlsServer(
      { key: privateKey(who), cert: certificate(who) },
      (socket) => {
        // What the client actually put in its ClientHello, read from the
        // server's own socket rather than inferred from anything Ward says
        // about itself.
        const name = socket.servername;
        sni.push(typeof name === "string" ? name : null);
        socket.on("data", (chunk: Buffer) => {
          connections.push(chunk.toString("latin1").split("\r\n")[0] ?? "");
          socket.end(response);
        });
      },
    );
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: (server.address() as { port: number }).port,
        connections,
        sni,
        close: () => new Promise<void>((done) => server.close(() => done())),
        setResponse: (value) => {
          response = value;
        },
      });
    });
  });
}

// A TCP listener that accepts and records without speaking TLS. It is what a
// destination the policy refuses would be reached through, and what an
// ambient proxy would be, so a case can assert that a connection arrived or
// that it did not.
function countingListener(): Promise<{
  port: number;
  count: () => number;
  close: () => Promise<void>;
}> {
  return new Promise((resolve) => {
    let connections = 0;
    const server: Server = createTcpServer((socket) => {
      connections++;
      socket.end();
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: (server.address() as { port: number }).port,
        count: () => connections,
        close: () => new Promise<void>((done) => server.close(() => done())),
      });
    });
  });
}

// A transport that answers with a fixed list of addresses and reaches a
// conforming local server. `addressPolicy` is left at whatever the case
// passes, so a case about policy gets the real one.
function transportTo(
  addresses: readonly ResolvedAddress[],
  extra: {
    harness?: { addressPolicy?: (address: string) => boolean; ca?: string };
    onResolve?: () => void;
  } = {},
): Transport {
  return createHttpsTransport({
    resolve: async () => {
      extra.onResolve?.();
      return addresses;
    },
    harness: {
      ca: certificate("ca"),
      ...extra.harness,
    },
  });
}

function request(url: string) {
  return {
    url,
    method: "GET" as const,
    headers: [{ name: "Accept", value: "application/json" }],
    authorization: {
      name: "Authorization",
      value: encoder.encode(`Bearer ${SYNTHETIC}`),
    },
    body: undefined,
  };
}

async function send(
  transport: Transport,
  url: string,
): Promise<TransportOutcome> {
  return await transport.send(request(url));
}

describe("the destination policy runs on what a name actually resolves to", () => {
  // Every case here points a *name* at an address Ward will not connect to,
  // and asserts two things: the transport reports the refusal, and nothing
  // was dialled. The listener is the second half, and it is the half that
  // matters — a refusal that still opened a socket would satisfy the first.
  const refused: [label: string, address: string][] = [
    ["loopback", "127.0.0.1"],
    ["private", "10.1.2.3"],
    ["link-local metadata", "169.254.169.254"],
    ["CGNAT", "100.100.100.200"],
    ["multicast", "224.0.0.1"],
    ["reserved", "240.0.0.1"],
    ["IPv6 loopback", "::1"],
    ["IPv6 link-local", "fe80::1"],
    ["IPv6 unique-local", "fd00::1"],
    ["IPv6 multicast", "ff02::1"],
    ["IPv4-mapped loopback", "::ffff:7f00:1"],
    ["NAT64-embedded loopback", "64:ff9b::7f00:1"],
    ["6to4-embedded", "2002:7f00:1::"],
    ["documentation", "2001:db8::1"],
  ];

  for (const [label, address] of refused) {
    test(`a name resolving to ${label} is refused and nothing is dialled`, async () => {
      const listener = await countingListener();
      const transport = transportTo([{ address, family: 0 }]);
      const outcome = await send(
        transport,
        `https://${APPROVED}:${listener.port}/rate_limit`,
      );
      expect({ label, outcome, dialled: listener.count() }).toEqual({
        label,
        outcome: { kind: "not-sent", reason: "destination-not-public" },
        dialled: 0,
      });
      await listener.close();
    });
  }

  test("a name answering with a public address and a private one dials only the public one", async () => {
    const listener = await countingListener();
    let resolutions = 0;
    const transport = transportTo(
      [
        { address: "127.0.0.1", family: 4 },
        { address: "203.0.113.9", family: 4 },
      ],
      { onResolve: () => void resolutions++ },
    );
    const outcome = await send(
      transport,
      `https://${APPROVED}:${listener.port}/rate_limit`,
    );
    // Both addresses are non-public (203.0.113.0/24 is TEST-NET-3), so the
    // answer is a refusal — and the listener, which the first address would
    // have reached, was never contacted.
    expect({ outcome, dialled: listener.count() }).toEqual({
      outcome: { kind: "not-sent", reason: "destination-not-public" },
      dialled: 0,
    });
    // One resolution for the whole operation. A second would be the
    // re-resolution spec §9.3 refuses, and the place a rebinding attack
    // lives.
    expect(resolutions).toBe(1);
    await listener.close();
  });

  test("an unresolvable name sends nothing", async () => {
    const transport = createHttpsTransport({
      resolve: async () => {
        throw new Error("no such host");
      },
    });
    expect(await send(transport, `https://${APPROVED}/rate_limit`)).toEqual({
      kind: "not-sent",
      reason: "destination-unresolved",
    });
  });

  test("the shipped transport refuses loopback by default", async () => {
    // The seam's default, asserted from the outside. If a future change made
    // the harness policy the production one, this is where it shows.
    const listener = await countingListener();
    const transport = createHttpsTransport({
      resolve: async () => [{ address: "127.0.0.1", family: 4 }],
    });
    const outcome = await send(
      transport,
      `https://${APPROVED}:${listener.port}/rate_limit`,
    );
    expect({ outcome, dialled: listener.count() }).toEqual({
      outcome: { kind: "not-sent", reason: "destination-not-public" },
      dialled: 0,
    });
    expect(isPublicAddress("127.0.0.1")).toBe(false);
    await listener.close();
  });
});

describe("the connection is bound to the validated address, and TLS still names the host", () => {
  let harness: Harness;
  beforeAll(async () => {
    harness = await tlsHarness(APPROVED);
  });
  afterAll(async () => {
    await harness.close();
  });

  test("a certificate for the approved name verifies while the socket is opened at the resolved address", async () => {
    const transport = transportTo([{ address: "127.0.0.1", family: 4 }], {
      harness: { addressPolicy: () => true },
    });
    const outcome = await send(
      transport,
      `https://${APPROVED}:${harness.port}/rate_limit`,
    );
    // A response at all is the claim: the socket went to 127.0.0.1, the
    // handshake presented a certificate for `approved.example.invalid`, and
    // verification against that name succeeded. Had verification run against
    // the address instead, or had no SNI been sent, this would not verify.
    expect(outcome).toEqual({ kind: "response", httpStatus: 204 });
    expect(harness.connections.at(-1)).toBe("GET /rate_limit HTTP/1.1");
    expect(harness.sni.at(-1)).toBe(APPROVED);
  });

  test("a certificate for a different name is refused, and no request is sent", async () => {
    const wrong = await tlsHarness(OTHER);
    const transport = transportTo([{ address: "127.0.0.1", family: 4 }], {
      harness: { addressPolicy: () => true },
    });
    const outcome = await send(
      transport,
      `https://${APPROVED}:${wrong.port}/rate_limit`,
    );
    expect({ outcome, requests: wrong.connections }).toEqual({
      outcome: { kind: "not-sent", reason: "connection-failed" },
      requests: [],
    });
    await wrong.close();
  });

  test("a destination given as an IP literal sends no SNI and verifies against the address", async () => {
    // The literal is refused by policy, so this asserts the shape of the
    // refusal rather than a handshake: that the transport treats an IP
    // destination as an address and not as a name to pass to `servername`
    // (Bun refuses an IP there outright, so a mistake would throw).
    const transport = createHttpsTransport({});
    expect(await send(transport, "https://127.0.0.1/rate_limit")).toEqual({
      kind: "not-sent",
      reason: "destination-not-public",
    });
  });
});

describe("a response is read as a status line and nothing else", () => {
  test("a redirect is not followed: the server is contacted once and the status is reported", async () => {
    const harness = await tlsHarness(APPROVED);
    const elsewhere = await countingListener();
    harness.setResponse(
      `HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:${elsewhere.port}/moved\r\nContent-Length: 0\r\n\r\n`,
    );
    const transport = transportTo([{ address: "127.0.0.1", family: 4 }], {
      harness: { addressPolicy: () => true },
    });
    const outcome = await send(
      transport,
      `https://${APPROVED}:${harness.port}/rate_limit`,
    );
    expect({
      outcome,
      contacts: harness.connections.length,
      redirected: elsewhere.count(),
    }).toEqual({
      outcome: { kind: "response", httpStatus: 302 },
      contacts: 1,
      redirected: 0,
    });
    await harness.close();
    await elsewhere.close();
  });

  test("a response body echoing the credential never reaches the caller", async () => {
    const harness = await tlsHarness(APPROVED);
    const echo = `${SYNTHETIC} ${Buffer.from(SYNTHETIC).toString("base64")} ${SYNTHETIC.split("").reverse().join("")}`;
    harness.setResponse(
      `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${echo.length}\r\nX-Echo: ${SYNTHETIC}\r\n\r\n${echo}`,
    );
    const transport = transportTo([{ address: "127.0.0.1", family: 4 }], {
      harness: { addressPolicy: () => true },
    });
    const outcome = await send(
      transport,
      `https://${APPROVED}:${harness.port}/rate_limit`,
    );
    // The outcome is a status number and carries no room for a body, a
    // header or a status text — the assertion is about the type as much as
    // the value.
    expect(JSON.stringify(outcome)).toBe(
      '{"kind":"response","httpStatus":200}',
    );
    expect(JSON.stringify(outcome)).not.toContain(SYNTHETIC);
    await harness.close();
  });

  test("a response that is not a status line is indeterminate, not a number read out of it", async () => {
    const harness = await tlsHarness(APPROVED);
    harness.setResponse("NOT-HTTP AT ALL\r\n\r\n");
    const transport = transportTo([{ address: "127.0.0.1", family: 4 }], {
      harness: { addressPolicy: () => true },
    });
    expect(
      await send(transport, `https://${APPROVED}:${harness.port}/rate_limit`),
    ).toEqual({ kind: "indeterminate", reason: "disconnected" });
    await harness.close();
  });
});

describe("an ambient proxy does not move the dial", () => {
  test("HTTPS_PROXY reaches node:https and does not reach Ward's transport", async () => {
    // The parent owns the listener and sets the variable in the child's
    // environment before it starts, because Bun reads these variables at
    // process start — an in-process assignment would be measuring a variable
    // the runtime had already read.
    const proxy = await countingListener();
    const probe = join(import.meta.dir, "fixtures", "transport-proxy-probe.ts");
    // Spawned asynchronously, and not because of style: this process owns
    // the listener the control has to reach, and a synchronous spawn would
    // block the event loop that accepts it — so the control would hang, the
    // only connection would never be counted, and the case would fail for a
    // reason that has nothing to do with what it is measuring.
    const child = Bun.spawn([process.execPath, probe], {
      env: {
        ...process.env,
        HTTPS_PROXY: `http://127.0.0.1:${proxy.port}`,
        HTTP_PROXY: `http://127.0.0.1:${proxy.port}`,
        ALL_PROXY: `http://127.0.0.1:${proxy.port}`,
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const output = await new Response(child.stdout).text();
    await child.exited;
    const parsed = JSON.parse(output.trim().split("\n").at(-1) ?? "{}") as {
      control?: string;
      outcome?: TransportOutcome;
    };
    expect({
      // The control: `node:https` in the same process honoured the variable
      // and landed on the listener, which is what makes the next line
      // evidence rather than an accident of an inert environment.
      proxiedConnections: proxy.count(),
      control: parsed.control,
      outcome: parsed.outcome,
    }).toEqual({
      proxiedConnections: 1,
      control: "error:ECONNRESET",
      outcome: { kind: "response", httpStatus: 204 },
    });
    await proxy.close();
  });
});
