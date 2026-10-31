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
  WardError,
  errorEnvelope,
  refusedHeaderCanonicalNames,
} from "../src/contract/errors.ts";
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

  // WCLI-98 fold rule: the fold
  // applies to refusal, duplicate and collision checks, never to the approval
  // comparison, so a rename that only the fold would equate still re-prompts.
  test("renaming auth.name from X-Api-Key to X_Api_Key requires a new approval", () => {
    const approved = normalizeProfile(
      declaration({
        auth: { type: "header", name: "X-Api-Key", secret: ALIAS },
      }),
    );
    const renamed = normalizeProfile(
      declaration({
        auth: { type: "header", name: "X_Api_Key", secret: ALIAS },
      }),
    );
    expect(differingProfileFields(renamed, approved)).toEqual(["auth"]);
  });

  test("renaming an ordinary header by case alone requires a new approval", () => {
    const approved = normalizeProfile(
      declaration({ headers: { "X-Trace": "1" } }),
    );
    const renamed = normalizeProfile(
      declaration({ headers: { "x-trace": "1" } }),
    );
    expect(differingProfileFields(renamed, approved)).toEqual(["headers"]);
  });

  test("renaming an ordinary header only by underscore requires a new approval", () => {
    const approved = normalizeProfile(
      declaration({ headers: { "X-Trace": "1" } }),
    );
    const renamed = normalizeProfile(
      declaration({ headers: { X_Trace: "1" } }),
    );
    expect(differingProfileFields(renamed, approved)).toEqual(["headers"]);
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

// WCLI-98 (opum-doc ruling 2026-10-30): the request-rewriting names are
// refused beside the DEC-248 set, in both positions, and fold into the same
// snapshot version.
const overrideNames = [
  "X-HTTP-Method-Override",
  "X-HTTP-Method",
  "X-Method-Override",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Forwarded-Host",
  "X-Forwarded-Proto",
  "X-Forwarded-For",
  "Forwarded",
  "X-Forwarded-Port",
  "X-Forwarded-Prefix",
  "X-Original-Host",
  "X-Host",
];

describe("WCLI-98: the request-rewriting names are refused", () => {
  for (const written of overrideNames)
    for (const [label, name] of [
      ["as written", written],
      ["lower case", written.toLowerCase()],
      ["upper case", written.toUpperCase()],
    ] as const) {
      test(`${written} ${label} is refused as auth.name`, () => {
        expect(
          codeOf(
            declaration({ auth: { type: "header", name, secret: ALIAS } }),
          ),
        ).toBe("profile_invalid");
      });

      test(`${written} ${label} is refused as an ordinary profile header`, () => {
        expect(codeOf(declaration({ headers: { [name]: "x" } }))).toBe(
          "profile_invalid",
        );
      });
    }

  test("a name merely near one is accepted in both positions", () => {
    for (const name of [
      "X-Forwarded",
      "X-HTTP-Methods",
      "Forwarded-For",
      "X-Original-URLs",
      "X-Rewrite",
    ]) {
      expect(
        codeOf(declaration({ auth: { type: "header", name, secret: ALIAS } })),
      ).toBeUndefined();
      expect(codeOf(declaration({ headers: { [name]: "x" } }))).toBeUndefined();
    }
  });

  test("the snapshot version stays 3: the names fold into DEC-248's change", () => {
    expect(profileSnapshotVersion).toBe(3);
  });

  test("a stored version-3 snapshot declaring one is a damaged document, never an approval", () => {
    const checkout = {
      root: "/Users/dev/code/project",
      device: "16777232",
      inode: "8429931",
    };
    const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
    const state = withProfileApproval(
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
        snapshot: normalizeProfile(declaration()),
      },
    );
    const text = new TextDecoder().decode(serializeVaultState(state));
    expect(text).toContain(`"snapshotVersion":${profileSnapshotVersion}`);
    // Positive control: the untouched document is an approval, so the
    // refusals below come from the names alone.
    expect(
      findProfileApproval(
        parseVaultState(new TextEncoder().encode(text)),
        checkout,
        projectId,
        "example",
      ),
    ).toBeDefined();
    // Each position the set guards: the secret header's name, and an
    // ordinary header.
    const asAuthName = text.replace(
      `"name":"${NAME}"`,
      '"name":"X-Method-Override"',
    );
    const asHeader = text.replace(
      '"Accept":"application/json"',
      '"x-forwarded-host":"application/json"',
    );
    for (const damaged of [asAuthName, asHeader]) {
      expect(damaged).not.toBe(text);
      let caught: { code?: string; message?: string } | undefined;
      try {
        parseVaultState(new TextEncoder().encode(damaged));
      } catch (error) {
        caught = error as { code?: string; message?: string };
      }
      expect(caught?.code).toBe("vault_state_malformed");
    }
  });
});

// WCLI-98, opum-doc ruling 2026-10-30 (A): a refusal names the refused header
// by Ward's own canonical spelling, never by the profile's bytes.

function refusalOf(value: unknown): WardError | undefined {
  try {
    normalizeProfile(value);
  } catch (error) {
    return error instanceof WardError ? error : undefined;
  }
  return undefined;
}

const VALUE_SENTINEL = "value-sentinel-4f2a";

describe("WCLI-98: the refusal names Ward's canonical spelling", () => {
  test("a mixed-case spelling prints the byte-identical canonical name, in both positions", () => {
    const asAuth = refusalOf(
      declaration({
        auth: { type: "header", name: "x-FORWARDED-host", secret: ALIAS },
      }),
    );
    const asHeader = refusalOf(
      declaration({ headers: { "x-FORWARDED-host": VALUE_SENTINEL } }),
    );
    for (const error of [asAuth, asHeader]) {
      expect(error?.code).toBe("profile_invalid");
      expect(error?.refusedHeader).toBe("X-Forwarded-Host");
      const printed = JSON.stringify(errorEnvelope(error as WardError));
      expect(printed).toContain("(refused header: X-Forwarded-Host)");
      expect(printed).not.toContain("x-FORWARDED-host");
      expect(printed).not.toContain(VALUE_SENTINEL);
    }
  });

  for (const written of overrideNames)
    for (const spelled of [
      written.toLowerCase(),
      written.toUpperCase(),
      written,
    ])
      test(`${spelled} prints ${written}`, () => {
        expect(
          refusalOf(
            declaration({
              auth: { type: "header", name: spelled, secret: ALIAS },
            }),
          )?.refusedHeader as string | undefined,
        ).toBe(written);
        expect(
          refusalOf(declaration({ headers: { [spelled]: "x" } }))
            ?.refusedHeader as string | undefined,
        ).toBe(written);
      });

  test("a proxy-* name prints the family constant, never the declared spelling", () => {
    const error = refusalOf(
      declaration({ headers: { "Proxy-Tail-Sentinel-77": "x" } }),
    );
    expect(error?.refusedHeader).toBe("Proxy-*");
    expect(JSON.stringify(errorEnvelope(error as WardError))).not.toContain(
      "Sentinel-77",
    );
  });

  test("a header that is not listed never appears in any error output, nor does a value", () => {
    const unlisted = "X-Unlisted-Sentinel-91";
    // Three defects that are not a listed name: a bad value, a bad type, and a
    // name colliding with the secret header's. None may print the name.
    const cases = [
      declaration({ headers: { [unlisted]: `${VALUE_SENTINEL}\r\nBad` } }),
      declaration({ headers: { [unlisted]: 7 } }),
      declaration({
        auth: { type: "header", name: unlisted, secret: ALIAS },
        headers: { [unlisted.toLowerCase()]: VALUE_SENTINEL },
      }),
    ];
    for (const value of cases) {
      const error = refusalOf(value);
      expect(error).toBeDefined();
      expect(error?.refusedHeader).toBeUndefined();
      const printed = JSON.stringify(errorEnvelope(error as WardError));
      expect(printed).not.toContain(VALUE_SENTINEL);
      expect(printed).not.toContain(unlisted);
      expect(printed).not.toContain(unlisted.toLowerCase());
      expect(printed).not.toContain("refused header");
    }
  });

  test("the constructor drops a name that is not on the list", () => {
    const error = new WardError(
      "profile_invalid",
      undefined,
      "x-FORWARDED-host" as never,
    );
    expect(error.refusedHeader).toBeUndefined();
  });

  test("a stored snapshot carries the same canonical detail at load, in both positions", () => {
    const checkout = {
      root: "/Users/dev/code/project",
      device: "16777232",
      inode: "8429931",
    };
    const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
    const state = withProfileApproval(
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
        snapshot: normalizeProfile(declaration()),
      },
    );
    const text = new TextDecoder().decode(serializeVaultState(state));
    const asValue = (header: string) =>
      text.replace(
        '"Accept":"application/json"',
        `"${header}":"${VALUE_SENTINEL}"`,
      );
    const damaged = [
      text.replace(`"name":"${NAME}"`, '"name":"x-FORWARDED-host"'),
      asValue("x-FORWARDED-host"),
    ];
    // An unlisted but ordinary header swapped in must not name itself, and a
    // value it carries must not be printed either.
    const unlisted = text.replace('"Accept":"application/json"', '"X-Bad":7');
    // The control byte is a JSON escape, so the document still parses and the
    // refusal comes from the profile's own header-value check, not from the
    // JSON reader.
    const unlistedWithValue = text.replace(
      '"Accept":"application/json"',
      `"X-Bad":"${VALUE_SENTINEL}\\u0001"`,
    );
    for (const bytes of [...damaged, unlisted, unlistedWithValue]) {
      expect(bytes).not.toBe(text);
      expect(() => JSON.parse(bytes)).not.toThrow();
      let caught: WardError | undefined;
      try {
        parseVaultState(new TextEncoder().encode(bytes));
      } catch (error) {
        caught = error as WardError;
      }
      expect(caught?.code).toBe("vault_state_malformed");
      const printed = JSON.stringify(errorEnvelope(caught as WardError));
      expect(printed).not.toContain("x-FORWARDED-host");
      expect(printed).not.toContain("X-Bad");
      expect(printed).not.toContain(VALUE_SENTINEL);
      if (bytes === unlisted || bytes === unlistedWithValue) {
        expect(caught?.refusedHeader).toBeUndefined();
        expect(printed).not.toContain("refused header");
      } else {
        expect(caught?.refusedHeader).toBe("X-Forwarded-Host");
        expect(printed).toContain("(refused header: X-Forwarded-Host)");
      }
    }
  });

  // A mapping that names the wrong member (a swapped pair, say) still
  // type-checks, because both names are on the list. Every canonical spelling
  // therefore has to come back as itself, from itself and from its folds.
  test("every canonical spelling round-trips through a declaration as itself", () => {
    expect(refusedHeaderCanonicalNames.length).toBe(26);
    for (const canonical of refusedHeaderCanonicalNames) {
      if (canonical === "Proxy-*") continue;
      for (const spelled of [
        canonical,
        canonical.toLowerCase(),
        canonical.toUpperCase(),
      ]) {
        const asAuth = refusalOf(
          declaration({
            auth: { type: "header", name: spelled, secret: ALIAS },
          }),
        );
        const asHeader = refusalOf(
          declaration({ headers: { [spelled]: "x" } }),
        );
        expect(asAuth?.refusedHeader as string | undefined).toBe(canonical);
        expect(asHeader?.refusedHeader as string | undefined).toBe(canonical);
      }
    }
  });

  test("a proxy-* name other than proxy-connection prints Proxy-*, proxy-authorization included", () => {
    for (const spelled of [
      "proxy-authorization",
      "Proxy-Authenticate",
      "PROXY-X",
    ])
      expect(
        refusalOf(declaration({ headers: { [spelled]: "x" } }))
          ?.refusedHeader as string | undefined,
      ).toBe("Proxy-*");
  });

  // WCLI-98 fold rule: `_` folds to `-` (after case-folding)
  // before every refused-name lookup, so a server that reads X_Forwarded_Host
  // as X-Forwarded-Host cannot be handed a header the prompt did not show. The
  // printed detail is still Ward's canonical constant.
  for (const canonical of refusedHeaderCanonicalNames) {
    if (canonical === "Proxy-*" || !canonical.includes("-")) continue;
    for (const spelled of [
      canonical.replaceAll("-", "_"),
      canonical.replaceAll("-", "_").toLowerCase(),
      canonical.replaceAll("-", "_").toUpperCase(),
    ])
      test(`underscore spelling ${spelled} is refused in both positions and prints ${canonical}`, () => {
        const asAuth = refusalOf(
          declaration({
            auth: { type: "header", name: spelled, secret: ALIAS },
          }),
        );
        const asHeader = refusalOf(
          declaration({ headers: { [spelled]: VALUE_SENTINEL } }),
        );
        for (const error of [asAuth, asHeader]) {
          expect(error?.code).toBe("profile_invalid");
          expect(error?.refusedHeader as string | undefined).toBe(canonical);
          const printed = JSON.stringify(errorEnvelope(error as WardError));
          expect(printed).toContain(`(refused header: ${canonical})`);
          expect(printed).not.toContain(spelled);
          expect(printed).not.toContain(VALUE_SENTINEL);
        }
      });
  }

  test("a mixed hyphen and underscore spelling, and Proxy_Authorization, are caught", () => {
    expect(
      refusalOf(declaration({ headers: { "x_FORWARDED-host": "x" } }))
        ?.refusedHeader as string | undefined,
    ).toBe("X-Forwarded-Host");
    expect(
      refusalOf(declaration({ headers: { Content_Length: "1" } }))
        ?.refusedHeader as string | undefined,
    ).toBe("Content-Length");
    expect(
      refusalOf(declaration({ headers: { Proxy_Authorization: "x" } }))
        ?.refusedHeader as string | undefined,
    ).toBe("Proxy-*");
  });

  test("near names stay accepted in both positions, hyphen or underscore", () => {
    for (const name of [
      "X-Forwarded-Hostname",
      "X_Forwarded_Hostname",
      "X-Host-Name",
      "X_Host_Name",
      "X-Hosts",
      "X-Forwarded-Ports",
      "Content_Lengths",
    ]) {
      expect(
        codeOf(declaration({ auth: { type: "header", name, secret: ALIAS } })),
      ).toBeUndefined();
      expect(codeOf(declaration({ headers: { [name]: "x" } }))).toBeUndefined();
    }
  });

  test("a stored snapshot spelling a refused name with underscores is refused at load, naming the constant", () => {
    const checkout = {
      root: "/Users/dev/code/project",
      device: "16777232",
      inode: "8429931",
    };
    const projectId = "33b05c92-8a6e-4f15-9dcb-65ae5d371123";
    const state = withProfileApproval(
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
        snapshot: normalizeProfile(declaration()),
      },
    );
    const text = new TextDecoder().decode(serializeVaultState(state));
    for (const bytes of [
      text.replace(`"name":"${NAME}"`, '"name":"X_Forwarded_Host"'),
      text.replace('"Accept":', '"X_Forwarded_Host":'),
    ]) {
      expect(bytes).not.toBe(text);
      let caught: WardError | undefined;
      try {
        parseVaultState(new TextEncoder().encode(bytes));
      } catch (error) {
        caught = error as WardError;
      }
      expect(caught?.code).toBe("vault_state_malformed");
      expect(caught?.refusedHeader as string | undefined).toBe(
        "X-Forwarded-Host",
      );
      expect(JSON.stringify(errorEnvelope(caught as WardError))).not.toContain(
        "X_Forwarded_Host",
      );
    }
  });

  // WCLI-98 fold rule: the same fold applies to the
  // duplicate and collision checks, since a CGI-style server reads X_Api_Key
  // and X-Api-Key as one variable and one value could clobber the other.
  for (const [authName, header] of [
    ["X-Api-Key", "X_Api_Key"],
    ["X_Api_Key", "X-Api-Key"],
    ["X-Api-Key", "x_API_key"],
    ["X-Api-Key", "X-API-KEY"],
  ] as const)
    test(`an ordinary ${header} folding onto auth.name ${authName} is refused`, () => {
      expect(
        codeOf(
          declaration({
            auth: { type: "header", name: authName, secret: ALIAS },
            headers: { [header]: "x" },
          }),
        ),
      ).toBe("profile_invalid");
    });

  test("two ordinary headers folding onto one name are refused", () => {
    expect(
      codeOf(declaration({ headers: { "X-Api-Key": "a", X_Api_Key: "b" } })),
    ).toBe("profile_invalid");
  });

  test("unrelated names do not collide", () => {
    expect(
      codeOf(
        declaration({
          auth: { type: "header", name: "X-Api-Key", secret: ALIAS },
          headers: { X_Api_Token: "x", "X-Api-Keys": "y", Accept: "z" },
        }),
      ),
    ).toBeUndefined();
    expect(
      codeOf(
        declaration({ headers: { "X-Api-Key": "a", "X-Api-Token": "b" } }),
      ),
    ).toBeUndefined();
  });
});
