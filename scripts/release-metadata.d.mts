export type Signature =
  | { kind: "adhoc" }
  | { kind: "developer-id"; team: string };
export const REAPPROVAL_LINE: string;
export function signatureFromCodesign(output: string): Signature;
export function assertNotesMatchSignature(
  notes: string,
  signature: Signature,
): void;
export function rewriteNotes(
  notes: string,
  sha256: string,
  cdhash: string,
  signature: Signature,
): string;
export function checksumFile(sha256: string, name: string): string;
