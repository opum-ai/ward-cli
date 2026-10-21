// WCLI-76: the packaged qualification's cleanup deletes every item under a
// service by name, so it refuses any name outside the qualification prefix.
// Both halves are measured with an injected runner: a refusal happens before
// /usr/bin/security is reached, and a qualify-prefixed name is accepted and
// drives the runner.
import { describe, expect, test } from "bun:test";
import { newQualifyService, qualifyServicePrefix } from "../scripts/build.ts";
import { deleteService } from "../scripts/qualify-cleanup.ts";

// Records each runner invocation and answers with the next scripted exit code.
function recorder(results: number[]) {
  const calls: string[][] = [];
  const run = (argv: string[]): number => {
    calls.push(argv);
    return results[calls.length - 1] ?? 1;
  };
  return { calls, run };
}

describe("the qualification cleanup guard", () => {
  test("refuses every name outside the qualification prefix without running security", () => {
    const { calls, run } = recorder([0]);
    const refused = [
      "opum.ward",
      "opum.ward.qualify",
      "opum.ward.qualifyX",
      "OPUM.WARD.QUALIFY-0123abcd",
      "xopum.ward.qualify-0123abcd",
      "elsewhere",
      "",
    ];
    for (const name of refused)
      expect(() => deleteService(name, run)).toThrow(qualifyServicePrefix);
    expect(calls).toEqual([]);
  });

  test("accepts a qualification service and deletes until an item is gone", () => {
    const service = newQualifyService();
    const { calls, run } = recorder([0, 0, 1, 0]);
    expect(deleteService(service, run)).toEqual({
      deleted: 2,
      remaining: true,
    });
    expect(calls).toEqual([
      ["delete-generic-password", "-s", service],
      ["delete-generic-password", "-s", service],
      ["delete-generic-password", "-s", service],
      ["find-generic-password", "-s", service],
    ]);
  });

  test("reports a qualifying service with no items as gone", () => {
    const service = newQualifyService();
    const { calls, run } = recorder([1, 1]);
    expect(deleteService(service, run)).toEqual({
      deleted: 0,
      remaining: false,
    });
    expect(calls).toEqual([
      ["delete-generic-password", "-s", service],
      ["find-generic-password", "-s", service],
    ]);
  });
});
