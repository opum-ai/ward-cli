// WCLI-96 (DEC-255): the step that proves the PUBLISHED Release is the one the
// operator signed. gh and codesign are fakes on PATH; shasum is the real one.
// Synthetic bytes only. Every mismatch must exit non-zero, and the clean case
// must pass, so the gate is proved both ways.
//
// The fakes are strict: gh exits non-zero unless argv is exactly a command the
// script is supposed to run, so a script that asked for the wrong tag, pattern
// or output would fail rather than pass. The fake codesign prints the block the
// real `-dvvv` prints on stderr, near-miss lines included.
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
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
case "$*" in
  "repo view --json nameWithOwner -q .nameWithOwner") echo "opum-ai/ward-cli"; exit 0 ;;
  "release view v0.1.1 --json body -q .body") cat "$FAKE_BODY"; exit "\${FAKE_VIEW_EXIT:-0}" ;;
  "release download v0.1.1 -p ward-darwin-arm64* -D "*)
    [ "\${FAKE_DOWNLOAD_EXIT:-0}" = "0" ] || exit "$FAKE_DOWNLOAD_EXIT"
    for argument in "$@"; do dest="$argument"; done
    cp "$FAKE_ASSETS"/* "$dest"/; exit 0 ;;
esac
echo "fake gh: unexpected argv: $*" >&2
exit 9
`,
);
writeFileSync(
  join(bin, "codesign"),
  `#!/bin/sh
case "$1" in
  --verify)
    [ "$2 $3" = "--strict --verbose=2" ] || exit 9
    exit "\${FAKE_VERIFY_EXIT:-0}" ;;
  -dvvv)
    [ "\${FAKE_DV_EXIT:-0}" = "0" ] || exit "$FAKE_DV_EXIT"
    {
      echo "Executable=$2"
      echo "Identifier=a.out"
      echo "Format=Mach-O thin (arm64)"
      echo "CodeDirectory v=20400 size=3519 flags=0x20002(adhoc,linker-signed) hashes=108+0 location=embedded"
      echo "Hash type=sha256 size=32"
      echo "CandidateCDHash sha256=$FAKE_CANDIDATE"
      echo "CandidateCDHashFull sha256=$FAKE_CANDIDATE$FAKE_CANDIDATE"
      echo "Hash choices=sha256"
      echo "CMSDigest=$FAKE_CANDIDATE"
      echo "CMSDigestType=2"
      [ -n "\${FAKE_NO_CDHASH:-}" ] || echo "CDHash=$FAKE_CDHASH"
      echo "Signature=adhoc"
    } >&2
    exit 0 ;;
esac
exit 9
`,
);
chmodSync(join(bin, "gh"), 0o755);
chmodSync(join(bin, "codesign"), 0o755);

const CDHASH = "d".repeat(40);
const sha = (bytes: string) => createHash("sha256").update(bytes).digest("hex");

type Case = {
  tag?: string;
  localName?: string;
  local?: string;
  published?: string;
  checksum?: (downloadedSha: string) => string;
  body?: (sha256: string, cdhash: string) => string;
  verifyExit?: string;
  signedCdhash?: string;
  noCdhash?: boolean;
  dvExit?: string;
  viewExit?: string;
  downloadExit?: string;
  omit?: "asset" | "checksum";
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
    (c.checksum ?? ((s) => `${s}  ward-darwin-arm64\n`))(sha(published)),
  );
  if (c.omit === "asset") rmSync(join(assets, "ward-darwin-arm64"));
  if (c.omit === "checksum") rmSync(join(assets, "ward-darwin-arm64.sha256"));
  const localFile = join(dir, c.localName ?? "ward-darwin-arm64");
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
  return spawnSync("bash", [script, c.tag ?? "v0.1.1", localFile], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      TMPDIR: dir,
      FAKE_BODY: bodyFile,
      FAKE_ASSETS: assets,
      FAKE_CDHASH: c.signedCdhash ?? CDHASH,
      FAKE_CANDIDATE: "c".repeat(40),
      FAKE_NO_CDHASH: c.noCdhash ? "1" : "",
      FAKE_DV_EXIT: c.dvExit ?? "0",
      FAKE_VIEW_EXIT: c.viewExit ?? "0",
      FAKE_DOWNLOAD_EXIT: c.downloadExit ?? "0",
      FAKE_VERIFY_EXIT: c.verifyExit ?? "0",
    },
  });
}

function expectFail(r: ReturnType<typeof run>, message: string) {
  expect(r.status).toBe(1);
  expect(r.stderr).toContain(message);
  expect(r.stdout).not.toContain("PASS");
}

test("a published Release that matches the signed file passes and names the repository", () => {
  const r = run();
  expect(r.stderr).toContain("");
  expect(r.status).toBe(0);
  expect(r.stdout).toContain(
    `PASS repo=opum-ai/ward-cli tag=v0.1.1 sha256=${sha("signed bytes")}`,
  );
  expect(r.stdout).toContain(`cdhash=${CDHASH}`);
});

test("a published asset that is not the local signed file fails", () => {
  expectFail(
    run({ published: "other bytes" }),
    "is not the local signed file's",
  );
});

test("a checksum file that does not match the published asset fails", () => {
  expectFail(
    run({ checksum: () => `${"0".repeat(64)}  ward-darwin-arm64\n` }),
    "published checksum file is not exactly",
  );
});

test("a checksum file naming another path with that path's own hash fails", () => {
  // shasum -c would read the named file and report OK without reading the asset.
  const other = join(root, "elsewhere");
  writeFileSync(other, "anything");
  expectFail(
    run({ checksum: () => `${sha("anything")}  ${other}\n` }),
    "published checksum file is not exactly",
  );
});

test("an empty checksum file fails", () => {
  expectFail(
    run({ checksum: () => "" }),
    "published checksum file is not exactly",
  );
});

test("notes whose sha256 line is stale fail even when asset and checksum agree", () => {
  expectFail(
    run({
      body: (_s, h) =>
        [
          `- sha256 ward-darwin-arm64: ${"a".repeat(64)}`,
          `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}`,
        ].join("\n"),
    }),
    "is not the published notes'",
  );
});

test("notes whose cdhash line is stale fail", () => {
  const r = run({ signedCdhash: "e".repeat(40) });
  expectFail(r, "CDHash");
  expect(r.stderr).toContain("is not the published notes'");
});

test("a signature that does not verify strictly fails", () => {
  expectFail(run({ verifyExit: "1" }), "codesign --verify --strict failed");
});

test("codesign -dvvv failing, or printing no CDHash, fails", () => {
  expectFail(run({ dvExit: "1" }), "codesign -dvvv failed");
  expectFail(run({ noCdhash: true }), "printed no CDHash");
});

test("notes without exactly one of each line fail", () => {
  expectFail(run({ body: () => "Ward v0.1.1\n" }), "exactly one sha256 line");
  expectFail(
    run({
      body: (s, h) =>
        [
          `- sha256 ward-darwin-arm64: ${s}`,
          `- sha256 ward-darwin-arm64: ${s}`,
          `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}`,
        ].join("\n"),
    }),
    "exactly one sha256 line",
  );
  expectFail(
    run({
      body: (s, h) =>
        [
          `- sha256 ward-darwin-arm64: ${s}`,
          `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}`,
          `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}`,
        ].join("\n"),
    }),
    "exactly one cdhash line",
  );
  expectFail(
    run({
      body: (s) => `- sha256 ward-darwin-arm64: ${s}\n`,
    }),
    "exactly one cdhash line",
  );
});

test("a notes body with CRLF line endings is refused rather than passed", () => {
  expectFail(
    run({
      body: (s, h) =>
        `- sha256 ward-darwin-arm64: ${s}\r\n- cdhash (ad-hoc signature, macOS keychain trust follows it): ${h}\r\n`,
    }),
    "exactly one sha256 line",
  );
});

test("an unreadable or empty published notes body fails", () => {
  expectFail(run({ viewExit: "1" }), "could not read the published notes");
  expectFail(run({ body: () => "" }), "published notes for v0.1.1 are empty");
});

test("a failed download, and a Release missing either file, fail", () => {
  expectFail(run({ downloadExit: "1" }), "could not download");
  expectFail(run({ omit: "asset" }), "has no ward-darwin-arm64 asset");
  expectFail(
    run({ omit: "checksum" }),
    "has no ward-darwin-arm64.sha256 asset",
  );
});

test("a local file under another name is refused", () => {
  expectFail(run({ localName: "ward" }), "must be named ward-darwin-arm64");
});

test("a tag that is not v1.2.3, including a flag, is refused before gh runs", () => {
  expectFail(
    run({ tag: "--repo=other/repo" }),
    "the tag must look like v1.2.3",
  );
  expectFail(run({ tag: "latest" }), "the tag must look like v1.2.3");
});

test("a failure names the directory holding the downloaded files", () => {
  expect(run({ published: "other bytes" }).stderr).toContain(
    "downloaded files are in",
  );
});
