// WCLI-96 (DEC-255): the notes' sha256 and cdhash lines and the checksum file
// are regenerated from the Mac-signed asset. Synthetic bytes only.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { expect, test } from "bun:test";
import { checksumFile, rewriteNotes } from "../scripts/release-metadata.mjs";
import { createTempRoot } from "./support/temp-root.ts";

const root = join(import.meta.dir, "..");
const dir = createTempRoot("ward-release-metadata-");

const OLD_SHA = "a".repeat(64);
const OLD_CDHASH = "b".repeat(40);
const NEW_SHA = "c".repeat(64);
const NEW_CDHASH = "d".repeat(40);

const notes = [
  "Ward v0.1.1, local developer preview, macOS on Apple silicon.",
  "",
  "- Source: 0123456789abcdef",
  `- sha256 ward-darwin-arm64: ${OLD_SHA}`,
  `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${OLD_CDHASH}`,
  "",
  "Install and upgrade: https://example.invalid/runbook",
].join("\n");

test("both byte-naming lines are rewritten and nothing else changes", () => {
  const out = rewriteNotes(notes, NEW_SHA, NEW_CDHASH);
  expect(out).toBe(
    notes.replace(OLD_SHA, NEW_SHA).replace(OLD_CDHASH, NEW_CDHASH),
  );
  expect(out).not.toContain(OLD_SHA);
  expect(out).not.toContain(OLD_CDHASH);
});

test("a notes body without exactly one of each line is refused", () => {
  const noSha = notes.replace(`- sha256 ward-darwin-arm64: ${OLD_SHA}\n`, "");
  expect(() => rewriteNotes(noSha, NEW_SHA, NEW_CDHASH)).toThrow(
    "found 0 and 1",
  );
  const twice = `${notes}\n- sha256 ward-darwin-arm64: ${OLD_SHA}`;
  expect(() => rewriteNotes(twice, NEW_SHA, NEW_CDHASH)).toThrow(
    "found 2 and 1",
  );
  expect(() => rewriteNotes("", NEW_SHA, NEW_CDHASH)).toThrow("found 0 and 0");
});

test("a value that is not the right length of hex is refused", () => {
  expect(() => rewriteNotes(notes, "short", NEW_CDHASH)).toThrow("sha256");
  expect(() => rewriteNotes(notes, NEW_SHA, NEW_SHA)).toThrow("cdhash");
});

test("the checksum file is the sha256sum format the workflow writes", () => {
  expect(checksumFile(NEW_SHA, "ward-darwin-arm64")).toBe(
    `${NEW_SHA}  ward-darwin-arm64\n`,
  );
});

test.skipIf(process.platform !== "darwin")(
  "the script writes the notes and checksum from a compiled executable's own bytes",
  () => {
    const entry = join(dir, "hello.ts");
    const asset = join(dir, "ward-darwin-arm64");
    writeFileSync(entry, "console.log('hello');\n");
    const build = spawnSync("bun", [
      "build",
      "--compile",
      entry,
      "--outfile",
      asset,
    ]);
    expect(build.status).toBe(0);
    const notesIn = join(dir, "notes.md");
    writeFileSync(notesIn, notes);
    const r = spawnSync(
      "node",
      [
        join(root, "scripts", "regenerate-release-metadata.mjs"),
        asset,
        notesIn,
        dir,
      ],
      { encoding: "utf8" },
    );
    expect(r.status).toBe(0);
    const sha = createHash("sha256").update(readFileSync(asset)).digest("hex");
    expect(readFileSync(join(dir, "ward-darwin-arm64.sha256"), "utf8")).toBe(
      `${sha}  ward-darwin-arm64\n`,
    );
    const written = readFileSync(join(dir, "release-notes.md"), "utf8");
    expect(written).toContain(`- sha256 ward-darwin-arm64: ${sha}`);
    expect(written).not.toContain(OLD_SHA);
    expect(r.stdout).toContain(`sha256 ${sha}`);
  },
);
