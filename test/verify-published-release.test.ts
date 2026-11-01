// WCLI-96 (DEC-255): the step that proves the PUBLISHED Release is the one the
// operator signed. gh and codesign are fakes on PATH; shasum is the real one.
// Synthetic bytes only. Every mismatch must exit non-zero, and the clean case
// must pass, so the gate is proved both ways.
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { expect, test } from "bun:test";
import { createTempRoot } from "./support/temp-root.ts";

const script = join(
  import.meta.dir,
  "..",
  "scripts",
  "verify-published-release.sh",
);
const root = createTempRoot("ward-verify-published-");
const bin = join(root, "bin");
mkdirSync(bin);

writeFileSync(
  join(bin, "gh"),
  `#!/bin/sh
if [ "$1 $2" = "release view" ]; then cat "$FAKE_BODY"; exit "\${FAKE_VIEW_EXIT:-0}"; fi
if [ "$1 $2" = "release download" ]; then
  while [ "$#" -gt 0 ]; do [ "$1" = "-D" ] && dest="$2"; shift; done
  cp "$FAKE_ASSETS"/* "$dest"/; exit 0
fi
exit 9
`,
);
writeFileSync(
  join(bin, "codesign"),
  `#!/bin/sh
case "$1" in
  --verify) exit "\${FAKE_VERIFY_EXIT:-0}" ;;
  -dvvv) echo "CDHash=$FAKE_CDHASH" >&2; exit 0 ;;
esac
exit 9
`,
);
chmodSync(join(bin, "gh"), 0o755);
chmodSync(join(bin, "codesign"), 0o755);

const CDHASH = "d".repeat(40);
const sha = (bytes: string) => createHash("sha256").update(bytes).digest("hex");

type Case = {
  local?: string;
  published?: string;
  checksum?: string;
  body?: (sha256: string, cdhash: string) => string;
  verifyExit?: string;
  signedCdhash?: string;
};

let n = 0;
function run(c: Case = {}) {
  const dir = join(root, `case-${n++}`);
  const assets = join(dir, "assets");
  mkdirSync(assets, { recursive: true });
  const published = c.published ?? "signed bytes";
  const localBytes = c.local ?? "signed bytes";
  writeFileSync(join(assets, "ward-darwin-arm64"), published);
  writeFileSync(
    join(assets, "ward-darwin-arm64.sha256"),
    c.checksum ?? `${sha(published)}  ward-darwin-arm64\n`,
  );
  const localFile = join(dir, "ward-darwin-arm64");
  writeFileSync(localFile, localBytes);
  const makeBody =
    c.body ??
    ((s: string, h: string) =>
      [
        "Ward v0.1.1",
        `- sha256 ward-darwin-arm64: ${s}`,
        `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}`,
      ].join("\n"));
  const bodyFile = join(dir, "body.md");
  writeFileSync(bodyFile, makeBody(sha(localBytes), CDHASH));
  return spawnSync("bash", [script, "v0.1.1", localFile], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      TMPDIR: dir,
      FAKE_BODY: bodyFile,
      FAKE_ASSETS: assets,
      FAKE_CDHASH: c.signedCdhash ?? CDHASH,
      FAKE_VERIFY_EXIT: c.verifyExit ?? "0",
    },
  });
}

test("a published Release that matches the signed file passes and says so", () => {
  const r = run();
  expect(r.stderr).toBe("");
  expect(r.status).toBe(0);
  expect(r.stdout).toContain(`PASS tag=v0.1.1 sha256=${sha("signed bytes")}`);
  expect(r.stdout).toContain(`cdhash=${CDHASH}`);
});

test("a published asset that is not the local signed file fails", () => {
  const r = run({ published: "other bytes" });
  expect(r.status).toBe(1);
  expect(r.stderr).toContain("is not the local signed file's");
});

test("a checksum file that does not match the published asset fails", () => {
  const r = run({ checksum: `${"0".repeat(64)}  ward-darwin-arm64\n` });
  expect(r.status).toBe(1);
  expect(r.stderr).toContain("checksum file does not match");
});

test("notes whose sha256 line is stale fail even when asset and checksum agree", () => {
  const r = run({
    body: (_s, h) =>
      [
        `- sha256 ward-darwin-arm64: ${"a".repeat(64)}`,
        `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}`,
      ].join("\n"),
  });
  expect(r.status).toBe(1);
  expect(r.stderr).toContain("is not the published notes'");
});

test("notes whose cdhash line is stale fail", () => {
  const r = run({ signedCdhash: "e".repeat(40) });
  expect(r.status).toBe(1);
  expect(r.stderr).toContain("CDHash");
  expect(r.stderr).toContain("is not the published notes'");
});

test("a signature that does not verify strictly fails", () => {
  const r = run({ verifyExit: "1" });
  expect(r.status).toBe(1);
  expect(r.stderr).toContain("codesign --verify --strict failed");
});

test("notes without exactly one of each line fail", () => {
  const none = run({ body: () => "Ward v0.1.1\n" });
  expect(none.status).toBe(1);
  expect(none.stderr).toContain("exactly one sha256 line");
  const twice = run({
    body: (s, h) =>
      [
        `- sha256 ward-darwin-arm64: ${s}`,
        `- sha256 ward-darwin-arm64: ${s}`,
        `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}`,
      ].join("\n"),
  });
  expect(twice.status).toBe(1);
  expect(twice.stderr).toContain("exactly one sha256 line");
});
