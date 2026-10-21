// The cleanup side of the packaged qualification (WCLI-15, T26), in its own
// module so `bun test` can measure the guard below: the qualification script
// itself exits unless it is a macOS run with WARD_QUALIFY_REAL_KEYCHAIN=1, so
// it cannot be imported by a test (WCLI-76).
import { qualifyServicePrefix } from "./build.ts";

// Runs one `/usr/bin/security` invocation and returns its exit code. The
// runner is injectable so a test can prove the guard without a keychain.
export type SecurityRunner = (argv: string[]) => number;

const runSecurity: SecurityRunner = (argv) =>
  Bun.spawnSync(["/usr/bin/security", ...argv]).exitCode ?? 1;

// Deletes EVERY item under a service this run named, by service alone and then
// by lookup, because the run cannot know which items a child created: a setup
// that died after creating its key leaves no vault to read an id from. An item
// is owned by the build that created it, so this process cannot use the
// keychain library for it (AsyncEntry refuses with "Invalid attempt to change
// the owner of this item", measured); /usr/bin/security can. Neither command
// asks for the secret.
//
// The service name is the only thing selecting what is deleted, so it must sit
// under the qualification prefix: a later caller passing `opum.ward` would
// otherwise delete the developer's real items.
export function deleteService(
  name: string,
  run: SecurityRunner = runSecurity,
): { deleted: number; remaining: boolean } {
  if (!name.startsWith(qualifyServicePrefix))
    throw new Error(
      `refusing to delete a credential-store service outside ${qualifyServicePrefix}: ${name}`,
    );
  let deleted = 0;
  for (let attempt = 0; attempt < 50; attempt++) {
    const removed = run(["delete-generic-password", "-s", name]);
    if (removed !== 0) break;
    deleted++;
  }
  const lookup = run(["find-generic-password", "-s", name]);
  return { deleted, remaining: lookup === 0 };
}
