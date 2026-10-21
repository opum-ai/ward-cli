// The T05 disk scan, shared by every test that asserts a synthetic value is
// absent from disk (WCLI-15). It looks for the value raw, base64 and hex in
// every regular file under a directory, including the SQLite -wal, -shm and
// -journal sidecars a store leaves beside its database.
//
// A scan that reads nothing cannot find anything, so it also reports how many
// files it read: a caller asserts that count is positive, and pairs the scan
// with a planted-value case that proves it can find the value at all.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

export interface DiskScan {
  readonly filesRead: number;
  readonly found: string[];
}

export function scanDisk(directory: string, needle: string): DiskScan {
  const forms = [
    needle,
    Buffer.from(needle).toString("base64"),
    Buffer.from(needle).toString("hex"),
  ].map((form) => Buffer.from(form));
  const files = readdirSync(directory, { recursive: true })
    .map(String)
    .filter((name) => statSync(join(directory, name)).isFile());
  const found = files.filter((name) => {
    const content = readFileSync(join(directory, name));
    return forms.some((form) => content.includes(form));
  });
  return { filesRead: files.length, found };
}

export function filesContaining(directory: string, needle: string): string[] {
  return scanDisk(directory, needle).found;
}
