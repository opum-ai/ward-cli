// Where Ward may connect, and where it must not (spec §9.3, gate T16).
//
// The rule is default-deny over the address a connection would actually be
// made to, never over the name a declaration was written with. Spec §9.3:
// "Only connect to the approved destination. Block loopback, link-local,
// private, multicast, metadata-service, and other non-public destinations by
// default, including IPv6 and mapped-address forms." A name says nothing
// about where it points — anyone who can answer for it can change that
// between two lookups — so the classification here runs on the resolved
// address, and the transport dials the literal it classified.
//
// `node:net`'s `isIP` and `BlockList` are the maintained address-parsing and
// range facilities spec §9.3 asks for. Neither does I/O: this module is pure
// policy, and the resolution and the dial both belong to the adapter beside
// it. A hand-built string filter over address spellings is the thing the
// spec's sentence exists to refuse, and it is refused here by construction —
// there is no string comparison of an address in this file.
//
// Two address families, two rules, because the shapes of their registries
// differ and pretending otherwise is how a gap appears:
//
//   - IPv4 has no single covering range for "globally routable", so the
//     non-public ranges are listed. The list is IANA's special-purpose
//     registry (RFC 6890) plus the three documentation ranges and the
//     benchmarking range; `224.0.0.0/4` and `240.0.0.0/4` cover multicast
//     and the reserved tail, including the broadcast address.
//   - IPv6 DOES have one: global unicast is `2000::/3`. So IPv6 is
//     allow-listed into that range first and narrowed inside it, which
//     refuses `::1`, `fe80::/10`, `fc00::/7`, `ff00::/8`, `100::/64` and
//     every address a v4 destination can be spelled as — `::ffff:0:0/96`
//     and `64:ff9b::/96` both sit far outside `2000::/3`.
//
// That last point is a deliberate choice with a cost, stated rather than
// hidden. An IPv4-mapped or NAT64 address, or a 6to4/Teredo one, embeds a v4
// destination inside a v6 spelling, and the honest way to classify it is to
// extract the embedded address and judge that. Extraction means parsing the
// 8 groups of an IPv6 literal here, by hand — exactly the facility the spec
// says not to build — so this build refuses the whole class instead. What
// that costs is a legitimate public destination written as `[::ffff:8.8.8.8]`,
// which nobody writes and which has an IPv4 spelling that works; what it buys
// is that no address reaches the wire through a classification this file
// cannot fully justify. `2001::/23` and `2002::/16` are refused inside the
// allow range for the same reason rather than for a different one.

import { BlockList, isIP } from "node:net";

// Bounds the transport enforces. They live here rather than in the adapter so
// that the contract they are part of — bounded timeouts and bounded response
// bytes, spec §9.3 — is readable beside the policy they qualify.
export const transportLimits = {
  // Establishing TCP and completing the TLS handshake, per address tried.
  connectTimeoutMs: 10_000,
  // The whole exchange, until the response's header block has been read.
  requestTimeoutMs: 30_000,
  // The header block Ward will read before giving up on a response. The body
  // is never read at all, so this is not a body limit: it is the bound on
  // how long a server can keep Ward reading while it looks for the end of
  // the headers.
  maxResponseHeaderBytes: 16 * 1024,
  // How many of a name's validated addresses one operation will try before
  // reporting that it could not connect. Bounded because the number of
  // addresses a name resolves to is not Ward's to choose.
  maxConnectAttempts: 8,
} as const;

// The ranges an IPv4 destination may not be in. Written as the registry
// states them; the comment on each is the reason it is here.
const nonPublicV4 = new BlockList();
nonPublicV4.addSubnet("0.0.0.0", 8, "ipv4"); // "this network" (RFC 1122)
nonPublicV4.addSubnet("10.0.0.0", 8, "ipv4"); // private (RFC 1918)
nonPublicV4.addSubnet("100.64.0.0", 10, "ipv4"); // shared address space / CGNAT (RFC 6598)
nonPublicV4.addSubnet("127.0.0.0", 8, "ipv4"); // loopback
nonPublicV4.addSubnet("169.254.0.0", 16, "ipv4"); // link local; 169.254.169.254 is the metadata service
nonPublicV4.addSubnet("172.16.0.0", 12, "ipv4"); // private (RFC 1918)
nonPublicV4.addSubnet("192.0.0.0", 24, "ipv4"); // IETF protocol assignments
nonPublicV4.addSubnet("192.0.2.0", 24, "ipv4"); // TEST-NET-1
nonPublicV4.addSubnet("192.88.99.0", 24, "ipv4"); // 6to4 relay anycast (RFC 7526, deprecated)
nonPublicV4.addSubnet("192.168.0.0", 16, "ipv4"); // private (RFC 1918)
nonPublicV4.addSubnet("198.18.0.0", 15, "ipv4"); // benchmarking (RFC 2544)
nonPublicV4.addSubnet("198.51.100.0", 24, "ipv4"); // TEST-NET-2
nonPublicV4.addSubnet("203.0.113.0", 24, "ipv4"); // TEST-NET-3
nonPublicV4.addSubnet("224.0.0.0", 4, "ipv4"); // multicast
nonPublicV4.addSubnet("240.0.0.0", 4, "ipv4"); // reserved, including the broadcast address

// IPv6 is judged the other way round: this is the only range that passes.
const globalV6 = new BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");

// Ranges inside `2000::/3` that are still not somewhere a credential goes.
const nonPublicV6WithinGlobal = new BlockList();
nonPublicV6WithinGlobal.addSubnet("2001::", 23, "ipv6"); // IETF protocol assignments: Teredo (2001::/32), benchmarking (2001:2::/48)
nonPublicV6WithinGlobal.addSubnet("2001:db8::", 32, "ipv6"); // documentation (RFC 3849)
nonPublicV6WithinGlobal.addSubnet("2002::", 16, "ipv6"); // 6to4 (RFC 3056); embeds an IPv4 destination
nonPublicV6WithinGlobal.addSubnet("3fff::", 20, "ipv6"); // documentation (RFC 9637)

// Whether an address literal is one Ward may make a connection to. The input
// is an address the transport has already established is a literal — this
// does not resolve anything, and a hostname passed here answers "no" because
// `isIP` says it is not an address rather than because of anything about it.
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !nonPublicV4.check(address, "ipv4");
  if (family === 6) {
    if (!globalV6.check(address, "ipv6")) return false;
    return !nonPublicV6WithinGlobal.check(address, "ipv6");
  }
  return false;
}

// The address a `URL` hostname denotes, or undefined when the host is a name
// and so has to be resolved.
//
// `URL.hostname` returns an IPv6 literal with its brackets — `[::1]` — because
// that is how the authority is written. The brackets are URL syntax and not
// part of the address, so they come off here, once, rather than at each of
// the places that would otherwise have to remember. The value returned is
// the canonical spelling the URL parser produced, which is what WCLI-9
// stores in the approved snapshot, so what is classified here is the same
// string the developer approved.
export function literalAddress(hostname: string): string | undefined {
  const address =
    hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
  return isIP(address) === 0 ? undefined : address;
}
