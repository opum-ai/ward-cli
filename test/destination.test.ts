// WCLI-10: the destination policy (spec §9.3, gate T16).
//
// A table rather than a set of scenarios, because this is the one place in
// the change where the answer is a classification and the interesting
// question is coverage: which addresses are refused, and — just as load
// bearing — which are not. A rule that refused everything would pass every
// "is this blocked" case and make Ward useless, so the accepting rows are
// half the evidence rather than decoration.
//
// The refused rows are grouped the way the review of a change like this
// asks the question. IPv6 gets its own group because its rule is a
// different shape: global unicast is one range, so IPv6 is allow-listed into
// `2000::/3` and narrowed inside it, where IPv4 is judged by the IANA
// special-purpose registry because it has no covering range for "public".
//
// This table is a prompt and not a proof, in the same sense WCLI-9 recorded
// for the profile golden table: it fails when a row's verdict changes and
// cannot see a change that touches none of its rows. `transport.test.ts`
// carries the half that can — the same addresses, driven through the real
// resolver seam and a real socket, asserting that nothing was dialled.
import { describe, expect, test } from "bun:test";
import { isPublicAddress, literalAddress } from "../src/domain/destination.ts";

const refused: [label: string, addresses: string[]][] = [
  [
    "IPv4 special-purpose ranges",
    [
      "0.0.0.0",
      "0.1.2.3",
      "10.0.0.0",
      "10.255.255.255",
      "100.64.0.1",
      "100.100.100.200",
      "127.0.0.1",
      "127.255.255.254",
      "169.254.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "172.31.255.255",
      "192.0.0.1",
      "192.0.2.1",
      "192.88.99.1",
      "192.168.0.1",
      "192.168.255.255",
      "198.18.0.1",
      "198.51.100.1",
      "203.0.113.1",
      "224.0.0.1",
      "239.255.255.250",
      "240.0.0.1",
      "255.255.255.255",
    ],
  ],
  [
    "IPv6 outside global unicast",
    [
      "::",
      "::1",
      "::ffff:7f00:1",
      "64:ff9b::7f00:1",
      "100::1",
      "fe80::1",
      "fc00::1",
      "fd12:3456::1",
      "ff02::1",
      "5f00::1",
    ],
  ],
  [
    "IPv6 inside global unicast that is still not a destination",
    [
      "2001::1",
      "2001:2::1",
      "2001:db8::1",
      "2002::1",
      "2002:7f00:1::",
      "3fff::1",
    ],
  ],
];

const accepted: [label: string, addresses: string[]][] = [
  [
    "IPv4 global unicast",
    ["1.1.1.1", "8.8.8.8", "93.184.215.14", "140.82.121.4", "223.255.255.255"],
  ],
  [
    "IPv6 global unicast",
    [
      "2606:4700:4700::1111",
      "2001:4860:4860::8888",
      "2600::1",
      "2a00:1450:4001:80e::200e",
    ],
  ],
];

describe("an address Ward may connect to", () => {
  for (const [label, addresses] of refused) {
    test(`refuses ${label}`, () => {
      expect(addresses.filter(isPublicAddress)).toEqual([]);
    });
  }

  for (const [label, addresses] of accepted) {
    test(`accepts ${label}`, () => {
      expect(addresses.filter((address) => !isPublicAddress(address))).toEqual(
        [],
      );
    });
  }

  test("a name is neither, because it is not an address", () => {
    // `isPublicAddress` judges literals. A name reaching it answers "no",
    // and the transport's route for a name is resolution first — so this
    // asserts the function is not a hostname filter wearing an address
    // filter's name.
    expect(
      ["api.example.invalid", "localhost", "", "[::1]"].map(isPublicAddress),
    ).toEqual([false, false, false, false]);
  });
});

describe("the address a URL host denotes", () => {
  test("an IPv6 literal loses its brackets and nothing else", () => {
    // The brackets are URL syntax; the classifier takes the address. The
    // spelling is the one the approved snapshot stores, so what is judged
    // here is what was approved.
    expect(literalAddress("[::1]")).toBe("::1");
    expect(literalAddress("[2606:4700:4700::1111]")).toBe(
      "2606:4700:4700::1111",
    );
  });

  test("an IPv4 literal is returned as written", () => {
    expect(literalAddress("127.0.0.1")).toBe("127.0.0.1");
  });

  test("a name is not an address", () => {
    // A name is resolved by the transport, never parsed here.
    expect(literalAddress("example.invalid")).toBeUndefined();
    expect(literalAddress("localhost")).toBeUndefined();
  });

  test("an IPv6 address with no brackets is still an address", () => {
    // `URL.hostname` always brackets one, so this shape does not arrive from
    // a parsed URL — but it is a valid IPv6 literal, and answering "this is
    // a name" would send it to a resolver instead of the policy.
    expect(literalAddress("::1")).toBe("::1");
    expect(literalAddress("2606:4700:4700::1111")).toBe("2606:4700:4700::1111");
  });
});
