// WCLI-17 negative control: deliberately failing. Reverted in the next commit.
import { expect, test } from "bun:test";

test("deliberate CI violation", () => {
  expect(1).toBe(2);
});
