// The two release-notes lines that name the artifact's bytes, and the checksum
// file's text, rewritten from a different set of bytes (WCLI-96, DEC-255).
//
// The tag run signs the darwin asset on macOS and writes the notes from those
// signed bytes (WCLI-123). A re-sign changes both the sha256 and the cdhash, so
// the operator sitting route regenerates the notes and the checksum file from
// the re-signed file; install step 3 refuses on a cdhash that does not match
// the notes.

const SHA256_LINE = /^- sha256 ward-darwin-arm64: [0-9a-f]{64}$/;
const CDHASH_LINE =
  /^- cdhash \(ad-hoc signature, macOS keychain trust follows it\): [0-9a-f]{40}$/;

export function rewriteNotes(notes, sha256, cdhash) {
  if (!/^[0-9a-f]{64}$/.test(sha256))
    throw new Error("sha256 is not 64 hex digits");
  if (!/^[0-9a-f]{40}$/.test(cdhash))
    throw new Error("cdhash is not 40 hex digits");
  const lines = notes.split("\n");
  const seen = { sha256: 0, cdhash: 0 };
  const out = lines.map((line) => {
    if (SHA256_LINE.test(line)) {
      seen.sha256++;
      return `- sha256 ward-darwin-arm64: ${sha256}`;
    }
    if (CDHASH_LINE.test(line)) {
      seen.cdhash++;
      return `- cdhash (ad-hoc signature, macOS keychain trust follows it): ${cdhash}`;
    }
    return line;
  });
  if (seen.sha256 !== 1 || seen.cdhash !== 1) {
    throw new Error(
      `expected exactly one sha256 line and one cdhash line in the notes, found ${seen.sha256} and ${seen.cdhash}`,
    );
  }
  return out.join("\n");
}

export function checksumFile(sha256, name) {
  return `${sha256}  ${name}\n`;
}
