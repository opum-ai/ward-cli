// The in-process HTTPS transport (spec §9.3, gates T14-T18).
//
// Why this is not `https.request`, which is what a reader will ask first,
// and the answer is measured rather than a preference. Bun 1.3.14's
// `node:https` honours `HTTPS_PROXY` and `HTTP_PROXY` from the environment.
// With `HTTPS_PROXY` pointed at a local listener, the connection went to the
// listener while the `lookup` hook still ran for the destination's hostname:
// the hook reported a binding that was not the one used, so a preflight that
// validated addresses would have been satisfied by a request that went
// somewhere else. `agent.createConnection` is never called at all — Bun
// short-circuits that path to its own fetch layer — and `proxy: ""`,
// `proxy: false`, an explicit `https.Agent`, and deleting the variables from
// `process.env` in-process all failed to change the dial. Spec §9.3 requires
// Ward to "ignore ambient proxy configuration", so a primitive that cannot be
// made to do that is not usable here, however much less code it would be.
//
// `tls.connect` is unaffected by the ambient proxy, because it dials the
// address it is given and consults nothing else. That makes the property
// structural rather than a setting someone has to get right: this file
// resolves once, validates every address it was given, and then opens a
// socket to one of those literals with the hostname supplied separately as
// the SNI name. There is no second resolution for an attacker to answer
// differently, and nothing between the validated address and the socket.
//
// HTTP is written by hand here, and that is the cost of the paragraph above.
// The surface is deliberately as small as the job allows: one request line,
// a Host header, the approved headers, the credential, and `Connection:
// close`; then the status line, and the body is never read at all. Ward
// reports a status code and nothing else (spec §9.4), so nothing here needs
// to parse a response body, and not reading one is a stronger guarantee than
// reading and discarding it. What is *not* attempted is anything that would
// need real framing care — there is no chunked decoding, no redirect
// handling, no connection reuse — because none of it is needed to learn a
// status code, and each would be a parser to review.

import { lookup } from "node:dns/promises";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import type {
  NotSentReason,
  Transport,
  TransportOutcome,
  TransportRequest,
} from "../application/transport.ts";
import { isFieldValue } from "../domain/authorization.ts";
import {
  isPublicAddress,
  literalAddress,
  transportLimits,
} from "../domain/destination.ts";

export interface ResolvedAddress {
  readonly address: string;
  readonly family: number;
}

export interface HttpsTransportLimits {
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly maxResponseHeaderBytes: number;
  readonly maxConnectAttempts: number;
}

export interface HttpsTransportOptions {
  // How a hostname becomes addresses. Defaults to the OS resolver, which is
  // the one a connection would have used; tests substitute it so that the
  // address policy can be exercised against a name whose answer they chose,
  // without a network and without a switch that would weaken the policy in
  // the shipped build. There is no such switch.
  readonly resolve?: (hostname: string) => Promise<readonly ResolvedAddress[]>;
  readonly limits?: HttpsTransportLimits;
  // The seams a controlled local-network test harness composes the transport
  // through. Spec §14 names that harness — "use transport injection or a
  // separate test harness for controlled TLS/local-network tests" — and
  // forbids the thing this is not: there is no user-accessible switch, and
  // no command, option, configuration key or environment variable reaches
  // this object. `cli/main.ts` calls `createHttpsTransport()` with no
  // arguments at all, and a test asserts that the defaults are the shipped
  // policy and the system trust store.
  //
  // They exist because three of the four properties the transport is
  // reviewed for — that the dialled address is the validated one, that SNI
  // and certificate verification still name the hostname, and that an
  // ambient proxy does not move the connection — can only be measured
  // against a server the test controls, and a conforming server cannot be
  // reached through the shipped destination policy or trusted by the system
  // store. Without these the properties would be asserted about code no test
  // can drive, which is the weaker half of the trade.
  readonly harness?: {
    readonly addressPolicy?: (address: string) => boolean;
    readonly ca?: string;
  };
}

async function defaultResolve(
  hostname: string,
): Promise<readonly ResolvedAddress[]> {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map(({ address, family }) => ({ address, family }));
}

// A status line is `HTTP-version SP status-code`, optionally followed by a
// reason phrase (RFC 9112 §4). Anything that is not that shape is not a
// status, and Ward says so rather than reading a number out of it.
const statusLinePattern = /^HTTP\/1\.[01] ([0-9]{3})(?: |$)/;

function parseStatus(head: Uint8Array): number | undefined {
  const end = head.indexOf(0x0a);
  if (end === -1) return undefined;
  const line = Buffer.from(head.subarray(0, end))
    .toString("latin1")
    .replace(/\r$/, "");
  const match = statusLinePattern.exec(line);
  return match === null ? undefined : Number(match[1]);
}

// The request, as bytes (RFC 9112 §3). Assembled into one buffer rather than
// written in pieces so there is no interleaving to reason about, and so there
// is one buffer holding the credential that the caller has to zero. That
// buffer is the concatenation — the credential is also copied into the line
// list on the way, and that intermediate copy is not zeroed. It is inside the
// non-guarantee ADR 0002 already states (no reliable wiping of
// garbage-collected memory) and is recorded here rather than left for a
// reader to notice.
function requestBytes(request: TransportRequest): Buffer | undefined {
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:") return undefined;
  // `pathname` and `search` are already percent-encoded by the parser, and a
  // fragment is never sent on the wire.
  const target = `${url.pathname === "" ? "/" : url.pathname}${url.search}`;
  const lines: Buffer[] = [];
  // Encode once, check that encoding, then append the very buffer that was
  // checked. The bytes validated are therefore the bytes written, which is
  // the property this function depends on: validating an encoding the socket
  // never sees is how a value that reads as one line here is two requests by
  // the time a server has parsed it (WCLI-10 review, F1).
  const push = (text: string): boolean => {
    const line = Buffer.from(`${text}\r\n`, "latin1");
    if (!isFieldValue(line.subarray(0, line.length - 2))) return false;
    lines.push(line);
    return true;
  };

  if (!push(`${request.method} ${target} HTTP/1.1`)) return undefined;
  // `URL.host` is the authority as written: the name or bracketed literal,
  // with the port present only when it is not the scheme's default. It is
  // also what the request is *for*, which is not necessarily the address
  // being dialled — a distinction this header exists to preserve.
  if (!push(`Host: ${url.host}`)) return undefined;
  for (const header of request.headers) {
    // The snapshot this came from was re-normalized on read, so these are
    // already known to be one line of text. Asserted anyway: this is the
    // function that writes them to a socket, and a header value that could
    // end its own line is a request split in two.
    if (!push(`${header.name}: ${header.value}`)) return undefined;
  }
  if (!isFieldValue(request.authorization.value)) return undefined;
  lines.push(
    Buffer.from(`${request.authorization.name}: `, "latin1"),
    Buffer.from(request.authorization.value),
    Buffer.from("\r\n", "latin1"),
  );
  if (request.body !== undefined) {
    if (!push(`Content-Length: ${request.body.length}`)) return undefined;
  }
  // Ward reads one status line and closes. Saying so lets a server close
  // rather than wait, and leaves no pooled connection that could carry a
  // second request.
  if (!push("Connection: close")) return undefined;
  // The blank line that ends the header block. Written directly rather than
  // through `push`, which refuses an empty field and is right to.
  lines.push(Buffer.from("\r\n", "latin1"));
  if (request.body !== undefined) lines.push(Buffer.from(request.body));
  return Buffer.concat(lines);
}

type HeadResult =
  | { readonly kind: "head"; readonly head: Uint8Array }
  | { readonly kind: "ended" }
  | { readonly kind: "too-large" };

// Reads until the end of the response's header block and stops there. The
// body is left unread on the socket, which is then destroyed — so a response
// body never reaches Ward's memory at all, let alone its output (spec §9.4).
// The listener is attached before the request is written, so a response that
// arrives while the write is still completing is buffered by the stream
// rather than missed.
function readHead(socket: TLSSocket, maxBytes: number): Promise<HeadResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let length = 0;
    let settled = false;
    const finish = (result: HeadResult): void => {
      if (settled) return;
      settled = true;
      socket.removeListener("data", onData);
      resolve(result);
    };
    const onData = (chunk: Buffer): void => {
      chunks.push(chunk);
      length += chunk.length;
      const head = Buffer.concat(chunks, length);
      const end = head.indexOf("\r\n\r\n");
      if (end !== -1) finish({ kind: "head", head: head.subarray(0, end) });
      else if (length > maxBytes) finish({ kind: "too-large" });
    };
    socket.on("data", onData);
    socket.once("end", () => finish({ kind: "ended" }));
    socket.once("close", () => finish({ kind: "ended" }));
  });
}

// One address, one socket. `next-address` is the only result that means the
// bytes never left, so it is the only one the caller may follow with another
// attempt; every other outcome is terminal.
type Attempt =
  | { readonly kind: "response"; readonly httpStatus: number }
  | {
      readonly kind: "indeterminate";
      readonly reason: "timeout" | "disconnected";
    }
  | { readonly kind: "not-sent"; readonly reason: NotSentReason }
  | { readonly kind: "next-address"; readonly reason: NotSentReason };

function attempt(
  address: string,
  port: number,
  servername: string | undefined,
  bytes: Buffer,
  limits: HttpsTransportLimits,
  ca: string | undefined,
): Promise<Attempt> {
  return new Promise((resolve) => {
    let settled = false;
    let sent = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let socket: TLSSocket | undefined;
    const finish = (result: Attempt): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      // Cleared as well as destroyed: the socket's own error and close
      // handlers are what would otherwise settle this promise a second time
      // from a path that no longer has anything to say.
      if (socket !== undefined) {
        socket.removeAllListeners();
        socket.destroy();
      }
      resolve(result);
    };
    const connectExpired = (): void =>
      finish(
        sent
          ? { kind: "indeterminate", reason: "timeout" }
          : { kind: "next-address", reason: "connection-failed" },
      );

    try {
      socket = tlsConnect({
        // The literal Ward validated. Not the hostname: resolving again here
        // is the second resolution spec §9.3 refuses.
        host: address,
        port,
        // Undefined for an IP-literal destination, which sends no SNI and
        // verifies the certificate against the address instead. Bun refuses
        // an IP passed as `servername` outright, so this is not a choice
        // being made silently in either direction.
        servername,
        // Stated rather than left to the default; the assertion below is
        // what makes it a check rather than a setting.
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        // Absent in the shipped build, where the system trust store is the
        // only one there is. A harness supplies the CA it generated.
        ...(ca === undefined ? {} : { ca }),
      });
    } catch {
      finish({ kind: "next-address", reason: "connection-failed" });
      return;
    }

    timer = setTimeout(connectExpired, limits.connectTimeoutMs);

    socket.once("error", () => {
      // Before a write, nothing left this process, so the next address is
      // worth trying and a retry is safe. After a write, whether the server
      // read the request is not knowable from here.
      finish(
        sent
          ? { kind: "indeterminate", reason: "disconnected" }
          : { kind: "next-address", reason: "connection-failed" },
      );
    });

    socket.once("secureConnect", () => {
      const connected = socket as TLSSocket;
      // The check, not the setting. With `rejectUnauthorized: true` a
      // certificate the runtime rejects arrives as an error instead of this
      // event, so this assertion is a second line behind the maintained one
      // rather than the mechanism itself — it is here because "the option was
      // passed" and "the connection was verified" are different claims, and
      // only the second one is what Ward is relying on.
      //
      // Measured, so it is not mistaken for the enforcement: no test reaches
      // this branch, and none can while `rejectUnauthorized` holds — the
      // wrong-name case above fails in the handshake and is reported as
      // `connection-failed`. The enforcement is the option plus the SNI name;
      // this is a second line that would hold if the option's behaviour
      // changed underneath it (WCLI-10 review, F4).
      if (connected.authorized !== true) {
        finish({ kind: "next-address", reason: "tls-failed" });
        return;
      }
      if (timer !== undefined) clearTimeout(timer);
      timer = setTimeout(connectExpired, limits.requestTimeoutMs);

      const head = readHead(connected, limits.maxResponseHeaderBytes);
      // From the first write onwards the outcome is ambiguous if anything
      // goes wrong: the server may have read part or all of the request.
      sent = true;
      connected.write(bytes);
      head.then((result) => {
        if (result.kind !== "head")
          finish({ kind: "indeterminate", reason: "disconnected" });
        else {
          const httpStatus = parseStatus(result.head);
          finish(
            httpStatus === undefined
              ? { kind: "indeterminate", reason: "disconnected" }
              : { kind: "response", httpStatus },
          );
        }
      });
    });
  });
}

export function createHttpsTransport(
  options: HttpsTransportOptions = {},
): Transport {
  const limits: HttpsTransportLimits = {
    ...transportLimits,
    ...options.limits,
  };
  const resolve = options.resolve ?? defaultResolve;
  // The shipped defaults, named once so a test can assert that the
  // composition root reaches them.
  const addressPolicy = options.harness?.addressPolicy ?? isPublicAddress;
  const ca = options.harness?.ca;

  return {
    async send(request: TransportRequest): Promise<TransportOutcome> {
      const bytes = requestBytes(request);
      if (bytes === undefined)
        return { kind: "not-sent", reason: "request-invalid" };
      try {
        let url: URL;
        try {
          url = new URL(request.url);
        } catch {
          return { kind: "not-sent", reason: "request-invalid" };
        }
        const port = url.port === "" ? 443 : Number.parseInt(url.port, 10);
        const literal = literalAddress(url.hostname);

        let addresses: readonly ResolvedAddress[];
        if (literal !== undefined)
          addresses = [{ address: literal, family: 0 }];
        else {
          try {
            addresses = await resolve(url.hostname);
          } catch {
            return { kind: "not-sent", reason: "destination-unresolved" };
          }
        }
        if (addresses.length === 0)
          return { kind: "not-sent", reason: "destination-unresolved" };

        // Every address is judged, and only the ones that pass are ever
        // dialled. A name answering with both a public address and a private
        // one therefore cannot be steered onto the private one by ordering,
        // and a name answering with nothing but private ones has nothing
        // left to connect to — which is the point.
        const allowed = addresses.filter((entry) =>
          addressPolicy(entry.address),
        );
        if (allowed.length === 0)
          return { kind: "not-sent", reason: "destination-not-public" };

        const servername = literal === undefined ? url.hostname : undefined;
        let lastReason: NotSentReason = "connection-failed";
        for (const entry of allowed.slice(0, limits.maxConnectAttempts)) {
          const outcome = await attempt(
            entry.address,
            port,
            servername,
            bytes,
            limits,
            ca,
          );
          // Only a failure that provably sent nothing moves to the next
          // address. Spec §9.3's "do not automatically retry an operation
          // after an ambiguous network failure" is enforced by the shape of
          // this result rather than by a rule to remember: there is no
          // branch from `indeterminate` or from a response back into this
          // loop.
          if (outcome.kind === "next-address" || outcome.kind === "not-sent") {
            lastReason = outcome.reason;
            continue;
          }
          return outcome;
        }
        return { kind: "not-sent", reason: lastReason };
      } finally {
        // The one buffer in this file that held the credential, zeroed on
        // every path out of `send`, including the ones that threw.
        bytes.fill(0);
      }
    },
  };
}
