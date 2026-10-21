// WCLI-15, T26 (DEC-217 (a2)): the qualification build differs from the shipped
// build in one thing, the credential-store service constant, and the shipped
// build gains no way to be redirected.
//
// Measured four ways, none of which touches a credential store:
//   - the build command (the one buildExecutable runs) refuses any service
//     that is neither the production service nor one under the qualification
//     prefix. It is that function's guard, not a property of the compiler: a
//     person can still run `bun build` with a define of their own;
//   - the two JavaScript bundles, built with the exact define each ships with,
//     differ in exactly one line, and substituting the qualification service
//     back makes them byte-identical. A bundle is compared rather than the
//     compiled executables because those are not reproducible: two builds of
//     identical input differ in about 700 000 bytes of signature and layout,
//     which was measured once on bun 1.3.14 (not asserted, since a reproducible
//     bun would only make the comparison stronger);
//   - the qualification executable embeds its service and the shipped one does
//     not embed the qualification prefix;
//   - neither executable carries the define's identifier, so the service is not
//     looked up under that name at runtime. This is evidence about the compiled
//     form and not a proof that nothing anywhere reads an environment variable;
//     the source has no such read (grep keychainService), and the bundle
//     comparison above shows the one line that differs.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  assertQualifyService,
  buildCommand,
  buildExecutable,
  entry,
  newQualifyService,
  productionService,
  qualifyServicePrefix,
  serviceDefine,
} from "../scripts/build.ts";
import { createTempRoot } from "./support/temp-root.ts";

const ROOT = join(import.meta.dir, "..");
const work = createTempRoot("ward-qualify-build-");

function bundle(service: string, name: string): string {
  const outfile = join(work, name);
  const run = Bun.spawnSync(
    [
      process.execPath,
      "build",
      "--target",
      "bun",
      "--external",
      "@napi-rs/*",
      "--define",
      serviceDefine(service),
      entry,
      "--outfile",
      outfile,
    ],
    { cwd: ROOT },
  );
  if (run.exitCode !== 0) throw new Error(run.stderr.toString());
  return readFileSync(outfile, "utf8");
}

describe("the qualification build", () => {
  test("a build's service is the production one or sits under the qualification prefix", () => {
    const base = { entry, outfile: join(work, "x") };
    expect(() =>
      buildCommand({ ...base, service: "opum.ward.other" }),
    ).toThrow();
    expect(() => buildCommand({ ...base, service: "elsewhere" })).toThrow();
    expect(() =>
      buildCommand({ ...base, service: `${qualifyServicePrefix}a"b` }),
    ).toThrow();
    expect(buildCommand(base)).toContain(serviceDefine(productionService));
    const service = newQualifyService();
    expect(service).toMatch(/^opum\.ward\.qualify-[0-9a-f]{8}$/);
    expect(service).not.toBe(productionService);
    expect(buildCommand({ ...base, service })).toContain(
      serviceDefine(service),
    );
    expect(newQualifyService()).not.toBe(service);
  });

  test("the delete guard refuses every name outside the qualification prefix and accepts one under it", () => {
    for (const name of [
      productionService,
      "opum.ward.other",
      "opum.ward.qualify",
      qualifyServicePrefix,
      `x${qualifyServicePrefix}a`,
      "",
    ])
      expect(() => assertQualifyService(name)).toThrow(/refusing/);
    // The positive controls: a generated name and a hand-written one pass.
    expect(() => assertQualifyService(newQualifyService())).not.toThrow();
    expect(() =>
      assertQualifyService(`${qualifyServicePrefix}0123abcd`),
    ).not.toThrow();
  });

  test("deleteService runs the guard before it spawns anything", () => {
    // The script exits at import on a non-macOS host or without its opt-in, so
    // it cannot be imported here; the order is read from its source.
    const source = readFileSync(
      join(ROOT, "scripts", "qualify-packaged.ts"),
      "utf8",
    );
    const body = source.slice(source.indexOf("function deleteService("));
    expect(body.indexOf("assertQualifyService(name)")).toBeGreaterThan(0);
    expect(body.indexOf("assertQualifyService(name)")).toBeLessThan(
      body.indexOf("Bun.spawnSync"),
    );
  });

  test("the bundles differ in the service constant and nothing else", () => {
    const service = "opum.ward.qualify-0123abcd";
    const shipped = bundle(productionService, "shipped.js");
    const qualify = bundle(service, "qualify.js");
    const a = shipped.split("\n");
    const b = qualify.split("\n");
    expect(a.length).toBe(b.length);
    const differing = a
      .map((line, index) => [line, b[index]] as const)
      .filter(([left, right]) => left !== right);
    expect(differing).toEqual([
      [
        `var keychainService = "${productionService}";`,
        `var keychainService = "${service}";`,
      ],
    ]);
    expect(qualify.replaceAll(service, productionService)).toBe(shipped);
    // The shipped bundle holds no conditional on a defined identifier.
    expect(shipped).not.toContain("WARD_KEYCHAIN_SERVICE");
  });

  test("the executables embed their service and carry no override", () => {
    const service = newQualifyService();
    const shippedPath = buildExecutable({ entry, outfile: join(work, "ward") });
    const qualifyPath = buildExecutable({
      entry,
      outfile: join(work, "ward-qualify"),
      service,
    });
    const shipped = readFileSync(shippedPath);
    const qualify = readFileSync(qualifyPath);
    expect(qualify.includes(Buffer.from(service))).toBe(true);
    expect(shipped.includes(Buffer.from(qualifyServicePrefix))).toBe(false);
    for (const binary of [shipped, qualify])
      expect(binary.includes(Buffer.from("WARD_KEYCHAIN_SERVICE"))).toBe(false);
  });
});
