// T22's text half: Ward replaces only the bytes between its own markers, and
// refuses a file whose markers it cannot read rather than guessing. These are
// pure-text cases, so the awkward shapes (a marker the user indented, a CRLF
// line ending, a file with no trailing newline) are cheap to pin here; the
// filesystem half is in project-binding.test.ts.
import { describe, expect, test } from "bun:test";
import {
  managedBlockBegin,
  managedBlockEnd,
  upsertManagedBlock,
} from "../src/domain/managed-block.ts";

const body = "## Credentials: Ward\nUse `ward instructions`.\n";
const block = `${managedBlockBegin}\n${body}${managedBlockEnd}\n`;

describe("a file with no Ward block", () => {
  test("the block is appended after a blank line, and the file's bytes are kept", () => {
    const original = "# Project\n\nSome prose.\n";
    const result = upsertManagedBlock(original, body);
    expect(result.status).toBe("updated");
    expect(result.text).toBe(`${original}\n${block}`);
  });

  test("a file with no trailing newline gains one before the block", () => {
    const original = "# Project";
    const result = upsertManagedBlock(original, body);
    expect(result.text).toBe(`${original}\n\n${block}`);
  });

  test("an empty file holds only the block", () => {
    const result = upsertManagedBlock("", body);
    expect(result.status).toBe("created");
    expect(result.text).toBe(block);
  });
});

describe("a file that already has the block", () => {
  test("only the region between the markers changes", () => {
    const before =
      "<!-- quest:agent-instructions:begin -->\npeer\n<!-- quest:agent-instructions:end -->\n\n";
    const after = "\ntrailing user prose\n";
    const original = `${before}${managedBlockBegin}\nold body\n${managedBlockEnd}${after}`;
    const result = upsertManagedBlock(original, body);
    expect(result.status).toBe("updated");
    expect(result.text).toBe(`${before}${block.slice(0, -1)}${after}`);
    expect(result.text).toContain("peer");
    expect(result.text).toContain("trailing user prose");
  });

  test("a second run is a no-op", () => {
    const once = upsertManagedBlock("# Project\n", body);
    const twice = upsertManagedBlock(once.text, body);
    expect(twice.text).toBe(once.text);
    expect(twice.status).toBe("unchanged");
  });

  test("indentation and a trailing carriage return still identify a marker", () => {
    const original = `x\r\n  ${managedBlockBegin}  \r\nold\r\n\t${managedBlockEnd}\r\ny\r\n`;
    const result = upsertManagedBlock(original, body);
    expect(result.status).toBe("updated");
    expect(result.text).toContain("x\r\n");
    expect(result.text.endsWith("y\r\n")).toBe(true);
    expect(upsertManagedBlock(result.text, body).status).toBe("unchanged");
  });
});

describe("markers Ward cannot read", () => {
  const cases: [label: string, text: string][] = [
    ["a begin marker without an end marker", `${managedBlockBegin}\nbody\n`],
    ["an end marker without a begin marker", `body\n${managedBlockEnd}\n`],
    [
      "two begin markers",
      `${managedBlockBegin}\n${managedBlockEnd}\n${managedBlockBegin}\n${managedBlockEnd}\n`,
    ],
    [
      "an end marker before its begin marker",
      `${managedBlockEnd}\nbody\n${managedBlockBegin}\n`,
    ],
  ];
  for (const [label, text] of cases) {
    test(`${label} is a conflict, not an overwrite`, () => {
      expect(() => upsertManagedBlock(text, body)).toThrow();
      try {
        upsertManagedBlock(text, body);
      } catch (error) {
        expect((error as { code?: string }).code).toBe(
          "instructions_markers_conflict",
        );
      }
    });
  }

  test("a near-miss marker is the user's text, not a marker", () => {
    const original = "<!--ward:begin-->\nprose\n";
    const result = upsertManagedBlock(original, body);
    expect(result.text.startsWith(original)).toBe(true);
  });
});
