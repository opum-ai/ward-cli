// The two release-notes lines that name the artifact's bytes, and the checksum
// file's text, rewritten from a different set of bytes (WCLI-96, DEC-255).
//
// The tag run signs the darwin asset on macOS and writes the notes from those
// signed bytes (WCLI-123). A re-sign changes both the sha256 and the cdhash, so
// the operator sitting route regenerates the notes and the checksum file from
// the re-signed file; install step 3 refuses on a cdhash that does not match
// the notes.

const SHA256_LINE = /^- sha256 ward-darwin-arm64: [0-9a-f]{64}$/;
// The cdhash line names how the bytes are signed, and the wording must agree
// with the file's own signature (WCLI-186, DEC-301 (a4) item 2). Ad-hoc is the
// build job's wording; the sign job rewrites it to Developer ID.
const ADHOC_LABEL = "ad-hoc signature, macOS keychain trust follows it";
const CDHASH_LINE =
  /^- cdhash \((?:ad-hoc signature, macOS keychain trust follows it|Developer ID signature, team [A-Z0-9]{10}, identifier ai\.opum\.ward)\): [0-9a-f]{40}$/;
export const REAPPROVAL_LINE =
  "Expect one keychain re-approval per upgrade; the binary is ad-hoc signed.";

// Reads `codesign -dvvv` output (it goes to stderr) and names the signature:
// { kind: "adhoc" } or { kind: "developer-id", team }. Anything else throws, so
// an unrecognised signature can never pick a wording.
export function signatureFromCodesign(output) {
  if (/^Signature=adhoc$/m.test(output)) return { kind: "adhoc" };
  const team = /^TeamIdentifier=([A-Z0-9]{10})$/m.exec(output)?.[1];
  if (
    team !== undefined &&
    /^Authority=Developer ID Application: .+/m.test(output) &&
    /^Identifier=ai\.opum\.ward$/m.test(output)
  )
    return { kind: "developer-id", team };
  throw new Error(
    "the signature is neither ad hoc nor a Developer ID signature with identifier ai.opum.ward",
  );
}

function cdhashLine(signature, cdhash) {
  const label =
    signature.kind === "adhoc"
      ? ADHOC_LABEL
      : `Developer ID signature, team ${signature.team}, identifier ai.opum.ward`;
  return `- cdhash (${label}): ${cdhash}`;
}

// Fails when the notes' signing wording disagrees with the signature: a
// Developer ID binary must never be described as ad hoc, nor the reverse.
export function assertNotesMatchSignature(notes, signature) {
  const adhoc = /ad[- ]?hoc/i.test(notes);
  const developerId = /Developer ID/.test(notes);
  if (signature.kind === "developer-id" && (adhoc || !developerId))
    throw new Error(
      "the release notes and the signature disagree: the binary is Developer ID signed but the notes say otherwise",
    );
  if (signature.kind === "adhoc" && developerId)
    throw new Error(
      "the release notes and the signature disagree: the binary is ad-hoc signed but the notes say Developer ID",
    );
}

export function rewriteNotes(notes, sha256, cdhash, signature) {
  if (
    signature === undefined ||
    !["adhoc", "developer-id"].includes(signature.kind)
  )
    throw new Error("a signature is required to word the notes");
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
      return cdhashLine(signature, cdhash);
    }
    // The re-approval claim is held until the operator's Mac measures it
    // (DEC-301 (a4)); for a Developer ID build only the false "ad hoc" fact
    // goes, and nothing is claimed about the Keychain.
    if (line === REAPPROVAL_LINE && signature.kind === "developer-id")
      return `This build is signed with a Developer ID certificate (team ${signature.team}); how the keychain treats it across builds is not yet measured.`;
    return line;
  });
  if (seen.sha256 !== 1 || seen.cdhash !== 1) {
    throw new Error(
      `expected exactly one sha256 line and one cdhash line in the notes, found ${seen.sha256} and ${seen.cdhash}`,
    );
  }
  const result = out.join("\n");
  assertNotesMatchSignature(result, signature);
  return result;
}

export function checksumFile(sha256, name) {
  return `${sha256}  ${name}\n`;
}
