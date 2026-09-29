// The port `ward run` sends through (spec §9.3), and the vocabulary it
// answers in.
//
// The application decides *what* is sent — one approved operation, its
// public headers, and the credential bytes in the one header that carries
// them — and the transport decides nothing about policy: it is handed an
// operation that has already been authorized, and its job is to deliver it
// or to report honestly that it did not. Everything a reader would want to
// review about the network lives behind this interface, and the tests that
// must not touch a network substitute for it, which is why the split is here
// rather than inside a single function.
//
// The outcome vocabulary is deliberately finer than the operation's public
// result, because the difference between "Ward did not send it" and "Ward
// sent it and cannot say what happened" is the difference between a safe
// error and spec §9.3's "report an indeterminate outcome without claiming
// that the server did or did not apply it" — and only the transport knows
// which one it is. The public result collapses these; this does not.
//
// A credential is bytes here and never a string. The request is assembled as
// bytes and written as bytes, so the value cannot reach a template literal,
// a log line, or an error message on the way through — the property gate T14
// asks for is a fact about the types rather than a rule someone has to
// remember. `Uint8Array` is also the one shape a caller can zero when it is
// done with it, which a string is not.
import type { ProfileMethod, ProfileHeader } from "../domain/profile.ts";

export interface TransportRequest {
  // The canonical URL from the approved snapshot. The transport is not
  // given the declaration and could not act on it: by the time a request is
  // built, the declared profile has been matched against the approval and
  // the approval is what is being executed (docs/adr/0003).
  readonly url: string;
  readonly method: ProfileMethod;
  // The profile's non-secret headers, exactly as approved.
  readonly headers: readonly ProfileHeader[];
  // The one header carrying the credential, already assembled by the caller
  // including its scheme. A separate field rather than one more entry in
  // `headers` so that the value's whole path is one line of this contract:
  // it is written into this header and nowhere else.
  readonly authorization: {
    readonly name: string;
    readonly value: Uint8Array;
  };
  // The body an approved profile permits, or undefined for the default. Its
  // length precedes it on the wire; its content is never interpreted here.
  readonly body: Uint8Array | undefined;
}

// Why Ward did not send anything. Each of these means the request was never
// written to a socket, so no external action can have been taken and a
// retry is safe to consider — which is exactly what `indeterminate` below
// cannot say.
export type NotSentReason =
  // The approved destination resolves to an address Ward will not connect
  // to (spec §9.3's public-destination rule, domain/destination.ts).
  | "destination-not-public"
  // The destination could not be resolved at all.
  | "destination-unresolved"
  | "connection-failed"
  | "tls-failed"
  // The operation could not be turned into a request Ward would send — a
  // URL it cannot express as a request target, or a header value that is
  // not one line of text.
  | "request-invalid";

// Why the outcome is unknown. The request bytes reached the socket; whether
// the server acted on them is not something Ward can establish from here,
// and it does not guess.
export type IndeterminateReason = "timeout" | "disconnected";

export type TransportOutcome =
  // A response's status line was read. The body was discarded unread.
  | { readonly kind: "response"; readonly httpStatus: number }
  | { readonly kind: "not-sent"; readonly reason: NotSentReason }
  | { readonly kind: "indeterminate"; readonly reason: IndeterminateReason };

export interface Transport {
  send(request: TransportRequest): Promise<TransportOutcome>;
}
