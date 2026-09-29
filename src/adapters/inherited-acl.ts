// Removing the ACL a new file inherits from its directory (docs/adr/0001).
//
// An inherited ACL (macOS) can grant access beyond the 0700/0600 modes, so
// every entry Ward itself creates gets its ACL stripped. Detecting an ACL on
// an entry that already exists would need a subprocess read, so pre-existing
// entries are checked for mode, ownership and links only, and an ACL the
// user placed there stays (documented in docs/adr/0001). Off macOS this is a
// no-op: the Linux ACL story belongs to the Linux platform work (WCLI-21).
//
// Shared by the two places Ward creates files: the vault store and the
// backup file. Measured on 2026-09-28 (WCLI-13's review): a directory
// carrying `chmod +a "everyone allow read,file_inherit"` leaves a 0600 file
// created inside it readable by everyone until this runs.
//
// The caller decides what a failure means, because the two are different
// conditions with different catalog text: an unstripped vault directory is
// `vault_store_insecure`, and an unstripped backup file is
// `backup_file_unwritable`. This reports the fact; it does not choose a
// code. No test covers either path — the treatment needs a real ACL to
// observe, and neither path had one before this was shared.
import { spawnSync } from "node:child_process";

// True when the entry's ACL is clear (including when the platform has no
// such concept), false when the strip was attempted and failed.
export function stripInheritedAcl(path: string): boolean {
  if (process.platform !== "darwin") return true;
  const result = spawnSync("/bin/chmod", ["-N", path]);
  return result.error === undefined && result.status === 0;
}
