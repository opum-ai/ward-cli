// WCLI-84 (DEC-248): the secret-valued header scheme, `auth.type` "header".
//
// The normalizer, the comparison, the stored shape and the stale rule, in
// both directions: what a header-type profile must accept, and what it and
// the ordinary profile headers must refuse. The run and the wire are asserted
// beside the cases that already own them (test/run.test.ts,
// test/transport.test.ts, test/terminal-consent.test.ts). Synthetic names and
// aliases only; no case here holds a credential value.
import { describe, expect, test } from "bun:test";
import {
  differingProfileFields,
  normalizeProfile,
  profileSnapshotVersion,
} from "../src/domain/profile.ts";
import {
  findProfileApproval,
  parseVaultState,
  serializeVaultState,
  withProfileApproval,
  vaultStateFormatVersion,
} from "../src/domain/vault-state.ts";

const NAME = "X-Example-Bypass";
const ALIAS = "example.bypass";

const declaration = (
  overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
  adapter: "http",
  method: "GET",
  url: "https://api.example.invalid/rate_limit",
  auth: { type: "header", name: NAME, secret: ALIAS },
  headers: { Accept: "application/json" },
  requestBody: "none",
  output: "status",
  ...overrides,
});

function codeOf(value: unknown): string | undefined {
  try {
    normalizeProfile(value);
  } catch (error) {
    return (error as { code?: string }).code;
  }
  return undefined;
}

// The names DEC-248 (1) refuses, spelled in a mix of cases so the comparison
// is measured as case-insensitive. `proxy-*` is a family, so two members stand
// for it.
const refusedNames = [
  "Authorization",
  "Proxy-Authorization",
  "Proxy-Connection",
  "Proxy-X-Anything",
  "HOST",
  "Content-Length",
  "Transfer-Encoding",
  "Connection",
  "Keep-Alive",
  "TE",
  "Trailer",
  "Upgrade",
  "Expect",
  "Cookie",
];

describe("DEC-248: a header-type profile normalizes", () => {
  test("to a snapshot carrying the alias and the name as written, never a value", () => {
    const snapshot = normalizeProfile(declaration());
    expect(snapshot.auth).toEqual({
      type: "header",
      name: NAME,
      secret: ALIAS,
    });
    expect(snapshot.headers).toEqual([
      { name: "Accept", value: "application/json" },
    ]);
  });

  test("a name of exactly 128 token characters is accepted and 129 is not", () => {
    const longest = "X".repeat(128);
    expect(
      normalizeProfile(
        declaration({ auth: { type: "header", name: longest, secret: ALIAS } }),
      ).auth,
    ).toEqual({ type: "header", name: longest, secret: ALIAS });
    expect(
      codeOf(
        declaration({
          auth: { type: "header", name: `${longest}X`, secret: ALIAS },
        }),
      ),
    ).toBe("profile_invalid");
  });

  test("a name that is merely near a refused one is accepted", () => {
    for (const name of ["X-Authorization", "Hosts", "Cookies", "Proxy"])
      expect(
        codeOf(declaration({ auth: { type: "header", name, secret: ALIAS } })),
      ).toBeUndefined();
  });
});

describe("DEC-248: what the header scheme and the profile headers refuse", () => {
  for (const name of refusedNames) {
    test(`${name} is refused as the secret header's name`, () => {
      expect(
        codeOf(declaration({ auth: { type: "header", name, secret: ALIAS } })),
      ).toBe("profile_invalid");
    });

    test(`${name} is refused as an ordinary profile header, in the same change`, () => {
      expect(codeOf(declaration({ headers: { [name]: "x" } }))).toBe(
        "profile_invalid",
      );
    });
  }

  test("a name that is not an RFC 9110 token is refused", () => {
    for (const name of ["", "X Bad", "X:Bad", "X\r\nBad", "Xé"])
      expect(
        codeOf(declaration({ auth: { type: "header", name, secret: ALIAS } })),
      ).toBe("profile_invalid");
  });

  test("a name that is not a string, or an absent one, is refused", () => {
    expect(
      codeOf(declaration({ auth: { type: "header", name: 7, secret: ALIAS } })),
    ).toBe("profile_invalid");
    expect(
      codeOf(declaration({ auth: { type: "header", secret: ALIAS } })),
    ).toBe("profile_invalid");
  });

  test("an ordinary header with the secret header's name is refused in any case", () => {
    for (const name of [NAME, NAME.toLowerCase(), NAME.toUpperCase()])
      expect(codeOf(declaration({ headers: { [name]: "public" } }))).toBe(
        "profile_invalid",
      );
  });

  test("an extra key is unsupported, for each type's exact key set", () => {
    expect(
      codeOf(
        declaration({
          auth: { type: "header", name: NAME, secret: ALIAS, scheme: "Bearer" },
        }),
      ),
    ).toBe("profile_unsupported");
    expect(
      codeOf(
        declaration({
          auth: { type: "bearer", secret: ALIAS, name: NAME },
        }),
      ),
    ).toBe("profile_unsupported");
  });

  test("a scheme that is neither bearer nor header is still unsupported", () => {
    expect(
      codeOf(declaration({ auth: { type: "basic", secret: ALIAS } })),
    ).toBe("profile_unsupported");
  });

  test("a secret that is not an alias is refused", () => {
    expect(
      codeOf(
        declaration({
          auth: { type: "header", name: NAME, secret: "../etc/passwd" },
        }),
      ),
    ).toBe("profile_invalid");
  });
});

describe("DEC-248: the name is part of the approved operation", () => {
  const base = normalizeProfile(declaration());

  test("a changed name, even only in case, is a different auth", () => {
    for (const name of ["X-Other-Bypass", NAME.toLowerCase()])
      expect(
        differingProfileFields(
          normalizeProfile(
            declaration({ auth: { type: "header", name, secret: ALIAS } }),
          ),
          base,
        ),
      ).toEqual(["auth"]);
  });

  test("a changed type, with the same alias, is a different auth", () => {
    expect(
      differingProfileFields(
        normalizeProfile(
          declaration({ auth: { type: "bearer", secret: ALIAS } }),
        ),
        base,
      ),
    ).toEqual(["auth"]);
  });

  test("the same name and alias is no difference", () => {
    expect(
      differingProfileFields(normalizeProfile(declaration()), base),
    ).toEqual([]);
  });
});

describe("DEC-248: the stored shape carries the name", () => {
  const checkout = {
    root: "/Users/dev/code/project",
    device: "16777232",
    inode: "8429931",
  };
  const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";

  function stateWith(snapshot: ReturnType<typeof normalizeProfile>) {
    return withProfileApproval(
      parseVaultState(
        new TextEncoder().encode(
          JSON.stringify({
            formatVersion: vaultStateFormatVersion,
            localBindings: [
              {
                projectId,
                ...checkout,
                registeredAt: "2026-10-29T00:00:00.000Z",
              },
            ],
          }),
        ),
      ),
      {
        profile: "example",
        projectId,
        ...checkout,
        approvedAt: "2026-10-29T00:00:00.000Z",
        expiresAt: "2026-10-30T00:00:00.000Z",
        snapshotVersion: profileSnapshotVersion,
        snapshot,
      },
    );
  }

  test("a name survives write and read, so dropping it on either side fails here", () => {
    const state = stateWith(normalizeProfile(declaration()));
    const bytes = serializeVaultState(state);
    expect(new TextDecoder().decode(bytes)).toContain(`"name":"${NAME}"`);
    const read = parseVaultState(bytes);
    expect(
      findProfileApproval(read, checkout, projectId, "example")?.snapshot.auth,
    ).toEqual({ type: "header", name: NAME, secret: ALIAS });
  });

  test("a stored header scheme without its name is a damaged document", () => {
    const text = new TextDecoder()
      .decode(serializeVaultState(stateWith(normalizeProfile(declaration()))))
      .replace(`"name":"${NAME}",`, "");
    let caught: string | undefined;
    try {
      parseVaultState(new TextEncoder().encode(text));
    } catch (error) {
      caught = (error as { code?: string }).code;
    }
    expect(caught).toBe("vault_state_malformed");
  });

  test("a version-2 snapshot is held inert, and a version-3 one authorises", () => {
    expect(profileSnapshotVersion).toBe(3);
    const text = new TextDecoder().decode(
      serializeVaultState(stateWith(normalizeProfile(declaration()))),
    );
    const current = parseVaultState(new TextEncoder().encode(text));
    expect(
      findProfileApproval(current, checkout, projectId, "example"),
    ).toBeDefined();
    const v2 = text.replace(
      `"snapshotVersion":${profileSnapshotVersion}`,
      '"snapshotVersion":2',
    );
    expect(v2).not.toBe(text);
    const stale = parseVaultState(new TextEncoder().encode(v2));
    expect(findProfileApproval(stale, checkout, projectId, "example")).toBe(
      undefined,
    );
    expect(stale.staleProfileApprovals).toHaveLength(1);
    expect(stale.staleProfileApprovals[0]?.snapshotVersion).toBe(2);
  });
});
