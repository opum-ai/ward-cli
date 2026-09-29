---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: Hand-rolled status-only HTTPS transport
tags:
  - security
  - network
  - transport
summary: Ward dials with tls.connect and writes one HTTP/1.1 request by hand, reading only the status line, because the runtime's own client cannot be made to ignore an ambient proxy.
status: stable
generated:
  by: lore/0.11.0
  at: 2026-09-29T06:10:05.567Z
---

# Hand-rolled status-only HTTPS transport

## Status

Accepted. It records the points spec §9.3-§9.4 leave to the implementation of
`ward run`: which primitive dials, what is and is not parsed on the way back,
and the shape of the destination policy. For WCLI-10 (opum-ai/ward-cli#67),
ruled execution rather than a design question by the orchestrator on
2026-09-29.

**Read this before "simplifying" the transport back to a library client.** The
code deviates from spec §9.3's own words — "Use an in-process HTTP client" —
and does so for a measured reason that is invisible from the source alone.

## Context

Spec §9.3 asks for several things at once: an in-process HTTP client, HTTPS
with certificate verification, no redirects followed, only public destinations
reached with DNS results bound to the connection, ambient proxy configuration
ignored, and bounded timeouts. On this runtime the first and the fifth are in
tension, and the fifth wins — it is the one an attacker can arrange without
touching Ward.

Bun 1.3.14's `node:https` honours `HTTPS_PROXY` and `HTTP_PROXY` from the
environment. With `HTTPS_PROXY` pointed at a local listener and a `lookup` hook
answering with a public address for the destination hostname, the connection
went to the listener while the hook still ran for the hostname — so a preflight
that validated addresses would have been satisfied by a request that went
somewhere else. What did **not** change the dial: `proxy: ""`, `proxy: false`,
an explicit `https.Agent`, `agent.createConnection` (never called at all; Bun
short-circuits that path to its own fetch layer), and deleting the variables
from `process.env` in-process. `NO_PROXY=*` did, which is a configuration
answer to a requirement that must not be configurable.

The measurement is re-testable rather than remembered:
`test/fixtures/transport-proxy-probe.ts`, with
`test/transport.test.ts`'s proxy case asserting the pair — the control
(`node:https`) must reach the listener, and Ward's transport must not.

## Decision

**The dial is `tls.connect` to an address literal that has already been
validated, with the hostname carried separately as the SNI name.** The name is
resolved once, every answer is classified, and only a literal that passed is
handed to the socket — so there is no second resolution for a rebinding answer
to reach, and nothing sits between the validated address and the connection.
The SNI name and the verification name stay the hostname, so verification
still means what it means for a name.

**The destination policy is default-deny and allow-lists rather than
deny-lists.** IPv6 is admitted only inside `2000::/3` and narrowed within it;
IPv4 is judged against the IANA special-purpose registry. IPv4-mapped, NAT64
and 6to4 forms are refused as a class rather than unwrapped — unwrapping means
writing the IPv6 parser spec §9.3 says not to build, and a class refusal is a
property of the allow-list instead of an enumeration someone has to keep
current.

**The request is written by hand and the response is read only to the end of
the status line.** One request line, a `Host` header, the approved headers, the
credential, `Connection: close`. The body is never read, so it is never in
Ward's memory — a stronger guarantee than reading it and discarding it
(spec §9.4). Redirects are not disabled; there is nothing that could follow
one, because a 3xx is simply a status like any other.

**Every check is made on the bytes that go on the wire.** A declared header
value is refused unless it can be written as the single line it was approved
as, which is why the declaration grammar rejects both a control byte and a
code point the wire encoding cannot carry: an encoding that truncates turns a
value that reads as one line into two requests (WCLI-10 review, F1). The
transport encodes a line once, checks that encoding, and writes the buffer it
checked.

## Consequences

- **What is deliberately not attempted:** chunked decoding, connection reuse,
  redirect handling, and body parsing. None is needed to learn a status code,
  and each would be a parser to review. The cost is that Ward cannot grow into
  a general HTTP client without revisiting this decision.
- **The hand-rolled path is the part to attack in review.** The redirect and
  status-line behaviour is Ward's own code rather than a maintained library's,
  so the tests around it are load-bearing in a way library-backed tests are
  not.
- **A value that mangles is refused alongside a value that injects.** The
  declaration grammar admits no code point above 0xff even where the wire
  encoding would produce a harmless byte, because the developer approved a
  value and the bytes sent have to be that value.
- **Revisit when the runtime changes, not when the code looks untidy.** If a
  future Bun stops honouring ambient proxy configuration in `node:https` — or
  gains a supported way to disable it — the reason for this decision is gone.
  Re-run the probe fixture before concluding that, and record the runtime
  version beside the result.
