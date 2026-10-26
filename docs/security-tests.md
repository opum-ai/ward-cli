---
# yaml-language-server: $schema=../.lore/schemas/reference.schema.json
type: Reference
title: Ward's security test matrix
tags:
  - security
  - tests
summary: The T-numbered security gates, the test that discharges each, and the recorded result. T01 to T25 are mapped clause by clause; T26's packaged-binary run is recorded by WCLI-15's second pull request.
generated:
  by: lore/0.14.1
  at: 2026-10-20T23:12:28.950Z
---

# Ward's security test matrix

The T-numbered gates of the spec of record (section 14), the test that
discharges each, and the result recorded for it. A row is added when its test
exists. WCLI-15 completed the rows and scored each one clause by clause, so a
row says what its test covers and what it leaves to another gate; where a
clause can only be discharged at a release the result column says so instead of
reading "Passing". T26's packaged-binary run is recorded by WCLI-15's second
pull request.
"Passing" means `bun test` on the named file at the head of the pull request
that added the row, and `bun run check` plus the three required CI contexts on
the merge SHA.

| Gate | What it proves | Test | Recorded result |
|---|---|---|---|
| T01 | Explicit setup creates a protected credential-store item and an encrypted vault; `--help` and `instructions` never initialize a store; a rerun on a finished setup changes nothing | `test/setup.test.ts`, `T01: setup and non-initialization`. The item here is a memory credential store; the real-keychain clause is T26's | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T02 | An existing vault with a missing, locked or unresponsive key fails closed and is left unchanged; no key is written on a failed check | `test/setup.test.ts`, `T02: an existing vault fails closed`; `test/key-provider.test.ts`, `the key side of T02: failures never write a key` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T03 | Known-answer AES-256-GCM vectors, round trip and size limits, fresh nonces, wrong-key refusal, and every malformed key, nonce, tag and length | `test/envelope.test.ts`, the four `T03:` groups. Known answers are independent vectors, not output of the code under test | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T04 | A changed ciphertext, nonce, tag, vault id, revision or header field fails authentication before any plaintext is returned | `test/envelope.test.ts`, `T04: any change fails before plaintext is returned`; `test/vault-store.test.ts`, `a modified ciphertext on disk fails authentication` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T05 | No synthetic plaintext in the database, its `-wal`, `-shm` and `-journal` sidecars, temporary paths, checkouts or backups, raw, base64 or hex, after every command path and the forced failures. Ward writes no temporary file; the scan keeps `TMPDIR` inside what it reads | `test/vault-store.test.ts`, `T05: no synthetic plaintext on disk` (the store's own create, update, delete and forced failures); `test/disk-exposure.test.ts`, `T05: no synthetic plaintext on disk after any command path`. The second drives every command in the manifest (a new command, or a new action of `secret` or `profile`, fails it until it is driven or exempted with a reason), the replace, run, refused-admission, backup, restore, wrong-passphrase restore, grant, revoke, delete and unregister paths, scans the whole root after each step and reads command output too. The scan reports how many files it read, and a planted-value case proves it finds each form in a sidecar and a backup | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T06 | Concurrent writers keep both updates or report a conflict; an interrupted write leaves a valid committed snapshot | `test/vault-store.test.ts`, `T06: transactions`, including separate-process writers and a writer killed mid-change and mid-write | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T07 | Private modes and ownership; symlinks, path traversal, foreign, WAL-mode and oversized files refused untouched | `test/vault-store.test.ts`, `T07: permissions, links and untrusted files` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T08 | Hidden and stdin entry, replacement, metadata-only read, explicit deletion, no value, length or fingerprint disclosure | `test/secret.test.ts`, `T08: entry, metadata and deletion` and `the alias grammar and value bounds` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T09 | Sentinels in rejected arguments, malformed input and thrown exceptions never reappear in stdout or stderr, in process and in the packaged executable | `test/non-disclosure.test.ts`, `rejected arguments are not echoed` and `unexpected exceptions`; `test/secret.test.ts`, `T09: sentinels never reach output` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T10 | An unknown project, a copied project id, a nested repository, a worktree, a moved path, a clone at another path and an unregistered checkout each get no binding | `test/project-binding.test.ts`, `T10: no checkout inherits a binding`, one case per clause | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T11 | A missing local alias neither falls back to another project nor enumerates its inventory | `test/secret.test.ts`, `T11: a lookup is scoped to the bound project` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T12 | Exact sharing works; the target cannot edit, delete or re-grant; an owner update is visible to the next use; revoke and owner delete block new admissions | `test/grant.test.ts`, the `T12: exact sharing works` and `T12: revocation and owner deletion block new admissions` groups, and `the grant record is exact and its relations are enforced` | Passing before merge: `bun test` 722 pass, 0 fail, Bun 1.3.14 (WCLI-12 branch, opum-ai/ward-cli#149). Filled with the merge SHA and CI run at finalization |
| T13 | A changed URL, method, auth alias, body or output policy, binding or unknown profile field cannot reuse an approval; an approval expires, and an expired one is refused at admission inside the store transaction | `test/profile.test.ts`, `T13: a changed declaration cannot reuse an approval` and `the approval belongs to one binding`; `test/approval-expiry.test.ts` for expiry, `--ttl` and the read-valid then admit-expired race | Passing before merge: `bun test` 731 pass, 0 fail, Bun 1.3.14 (WCLI-72 branch), recorded at #152 (e2ee2ea). Filled with the CI run at finalization |
| T14 | The synthetic credential reaches only the approved authentication header and is absent from argv, environment, files, output and audit; a control byte in it sends nothing | `test/run.test.ts`, `T14: the credential reaches only the approved header`; the files clause is also `test/disk-exposure.test.ts` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T15 | A 301, 302, 307 or 308 to another host, the same host, a local IP or a URL echoing the credential is not followed: the server is contacted once and the named target sees nothing | `test/transport.test.ts`, `T15: a redirect is not followed, whatever it names`, sixteen cases | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T16 | HTTP, user-info, loopback, private, link-local, metadata, CGNAT and multicast destinations, IPv6 forms, a name resolving to a refused address, DNS re-resolution, an ambient proxy and an attempt to disable TLS verification are refused or inert | `test/destination.test.ts`; `test/transport.test.ts`, `the destination policy runs on what a name actually resolves to`, the re-resolution count, `an ambient proxy does not move the dial` and `NODE_TLS_REJECT_UNAUTHORIZED=0 does not turn verification off` (a child process with its own control); `test/profile.test.ts`, the plain-HTTP and user-info refusals | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T17 | The credential echoed raw, reversed, base64, JSON-escaped, split across chunks or header lines, in a status text or in an error body never reaches the caller; the outcome is a status and nothing else | `test/transport.test.ts`, `a response body echoing the credential never reaches the caller` and `T17: echoes in any form never reach the caller`; `test/run.test.ts`, output is status-only | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T18 | A timeout, a disconnect and an ambiguous outcome are reported safely, with exactly one request and no automatic retry | `test/run.test.ts`, `T18: the transport is not retried, and its outcome is reported safely` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T19 | A pre-delivery audit failure blocks delivery; a post-delivery failure is reported without claiming rollback | `test/run.test.ts`, `T19: audit persistence failures, measured at the vault` and `admission precedes delivery, and completion follows it` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T20 | A backup restores with only its passphrase; a wrong passphrase, a changed byte, hostile KDF parameters and an oversized file are refused with the destination untouched | `test/backup.test.ts`, `T20: a backup opens with only its passphrase` and `the container's authenticated header` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T21 | A restore uses a fresh key, clears bindings and leaves no grant or approval active | `test/grant.test.ts`, `T21: restore clears grants and approvals`; `test/backup.test.ts` | Passing before merge: `bun test` 722 pass, 0 fail, Bun 1.3.14 (WCLI-12 branch, opum-ai/ward-cli#149). Filled with the merge SHA and CI run at finalization |
| T22 | Repeated init keeps user content and peer blocks; malformed markers and escaping symlinks are conflicts, not overwrites | `test/project-binding.test.ts`, `T22: init preserves every file it does not own`; `test/managed-block.test.ts` | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T23 | The full P0 workflow runs with neither Lore nor Quest on PATH, checked as a precondition; with failing `lore` and `quest` on PATH it still succeeds and neither is called, with a positive control that the record can be written | `test/standalone.test.ts`, `T23: standalone`. In process with a memory credential store; the packaged confirmation is T26's run under a stripped PATH. Ward spawns no external tool but `/bin/chmod` by absolute path | Passing before merge: `bun test` 767 pass, 0 fail, Bun 1.3.14 (WCLI-15 branch). Filled with the merge SHA and CI run at finalization |
| T24 | The agent contract. Automated half: the guidance block and packaged skill for both hosts, judged by `ward agents --check`, and the eval suite's structure. Behavioural halves: Claude through `scripts/run-eval.sh`, Codex through the manual smoke (ADR 0012) | `test/agents.test.ts`, `test/init-multiselect.test.ts` and `bun run eval:check` run in CI. The five `evals/` cases measure when the skill triggers and how it handles an exposed credential; none runs `check` or `run` on synthetic data, so that clause rests on the Codex smoke and on T14's tests. Claude's last full run is under `evals/results/` | Automated half passing, as for every row. Behavioural halves are discharged at release, per ADR 0012 and `docs/runbooks/release-smoke-t24-s-manual-half.md`; not run here |
| T25 | The skill, plugin and CLI release references agree, and the federated index resolves to an existing artifact | `test/plugin-manifest.test.ts` for the references in this repository. The federated entry cannot exist before a release artifact does (spec section 11.3) | References: passing, as for every row. Federated index: discharged at release, step 4 of `docs/runbooks/cutting-a-ward-release.md` |
| T26 | Real native key-provider integration and a packaged-binary smoke on macOS; mocked unit tests do not count | `scripts/qualify-packaged.ts` (not in `bun test`: it needs `WARD_QUALIFY_REAL_KEYCHAIN=1` and a person to start it), with the build measured by `test/qualify-build.test.ts`. See How T26 is measured | Passing on macOS 27.0.1, Bun 1.3.14: 21 of 21 checks, run at 5ca368d (the pull request branch before its squash; the code is the same at 81caf85), build `9f6fd8cb4405`; `~/.ward` tree digest unchanged. Re-run at each release. This is macOS only: Linux and Windows are not advertised platforms for the first preview (ADR 0004) |

## Release gates this matrix cannot discharge before a release

| Gate | What it requires | Where it is carried |
|---|---|---|
| `profileSnapshotVersion` bump | The release commit changes the constant from 1 and updates the comment in `src/domain/profile.ts`, so the released build refuses every dev-era snapshot with no migration (DEC-50, ADR 0018) | Step 1 of `docs/runbooks/cutting-a-ward-release.md`; recorded when the release is cut, not before |
| T24 behavioural halves | The Claude eval run and the Codex manual smoke | Step 3 of the same runbook, which names both |
| T26 with a real send | The packaged smoke stops at admission and a refused destination, so it sends nothing. Before the first release it must also send once, to a real endpoint or a loopback TLS server (DEC-217 (a3)) | Not run before the first release; recorded here so the pre-release floor is not read as the whole gate |
| T25 federated index | The marketplace entry resolves to the release artifact | Step 4 of the same runbook, and spec section 11.3 |

## Release 0.1.0 gate results (WCLI-82)

Recorded 2026-10-26 on the draft release commit. The tag waits for every row
not Done; DEC-246 D3 sets which gates run for 0.1.0.

| Gate | Result |
|---|---|
| `profileSnapshotVersion` bump | Done: the constant is 2; a dev-era approval is refused with `vault_format_unsupported`, a release approval parses (in-process, synthetic data) |
| Plugin and CLI versions agree | Done: 0.1.0 in `package.json` and `.claude-plugin/plugin.json`, held by `test/plugin-manifest.test.ts` |
| Format-compatibility decision (runbook step 5) | Done: [ADR 0023](adr/0023-keep-the-vault-state-reader-s-exact-key-set-comparison-at-the-first-release.md), DEC-246 D1 |
| T24 Claude half | **FAILED, blocks the tag.** `scripts/run-eval.sh` under Claude Code 2.1.309: 3 of 5 cases. `ward-shell-history-curl` (0.00) and `ward-stdout-debug-print` (0.33) never fired the skill. The last full run, 2026-09-29 under 2.1.284, was 5 of 5; `skills/` and `evals/` are unchanged and plugin version 0.0.0 fails the same way. WCLI-83 |
| T24 Codex half | Deferred for 0.1.0 by DEC-246 D3: Codex is retired for the fleet and this half is a manual smoke ([ADR 0012](adr/0012-t24-s-codex-half-is-qualified-by-the-artifacts-plus-a-documented-manual-smoke.md)) |
| T26 packaged-binary run | Pending the operator sitting (DEC-246 D3): run in the same sitting as the keychain and profile re-approval after install, on the released artifact |
| T26 with a real send | Not run, and DEC-246 does not remove it: it still has to send once to a real endpoint or a loopback TLS server (DEC-217 (a3)) before the tag |
| T25 federated index | Not yet: it needs the tag and release artifact |

## How T26 is measured

DEC-217 (a2) rules the isolation. The run builds `dist/ward-qualify`, the shipped
program compiled with a credential-store service of its own,
`opum.ward.qualify-<random>`, and drives that binary against a temporary store.
The shipped binary gains no override: `scripts/build.ts` always defines
`WARD_KEYCHAIN_SERVICE`, to `opum.ward` for the shipped build, and the compiler
folds the check, so nothing at runtime can redirect it.

What the run proves, and how:

- **The build differs by one constant.** The two JavaScript bundles, built with
  the exact define each ships with, differ in one line, and substituting the
  qualification service back makes them byte-identical
  (`test/qualify-build.test.ts`). The compiled executables are not compared
  byte for byte, because two builds of identical input differ in about 700,000
  bytes of signature and layout (measured once, bun 1.3.14). The run prints the
  one differing line and finds the service inside the executable.
- **The developer's `~/.ward` is untouched.** HOME is a temporary directory, and
  a digest of the real `~/.ward` tree (path, type, size, mode, mtime and content
  hash of every entry) is taken before and after and must match. The run does
  not read, list or probe the real `opum.ward` credential-store item, not even
  its metadata, because a read can raise a keychain prompt with no operator at
  the host.
- **Everything a child created is deleted**, by service alone, so an item from a
  setup that died before it wrote a vault is covered too; a lookup then finds
  nothing. A SIGINT, SIGTERM or SIGHUP runs the same exit path: it removes the
  items, takes the second digest, removes the temporary root and reports
  `FAILED`. An interrupted run was exercised and cleaned up.
- **The workflow runs on the packaged binary** with `PATH=/usr/bin:/bin`, which
  holds neither Lore nor Quest (T23 on the shipped form): setup, init, secret
  set, profile approve, check, run, audit, status, doctor, backup, restore into
  a second store with only the passphrase, unregister, and a refused run after
  it. `ward run` reaches admission and is refused at an unresolvable `.invalid`
  destination with `run_destination_unresolved`, so nothing is sent (the check pins that exact
  code, so a transport that sent and then failed would not pass); the only
  network activity is that name lookup. The audit holds exactly one admission and
  one completion. The whole temporary root is then scanned for the secret value
  and the backup passphrase (T05 on the packaged form) and holds neither.
- **The key provider on its own** is exercised through the real keychain by
  `test/qualification/keychain-roundtrip.ts`, with a service the parent names
  and deletes (the probe may die first) and a timeout: create, load, a second create
  refused with `vault_key_exists`, delete, and a load after delete reporting
  `vault_key_missing`.

Findings from building it, kept because each changes how the run must be done:

- A bare temporary HOME makes every credential-store call fail with
  `vault_key_unavailable`, because the Security framework finds the login
  keychain under `$HOME/Library/Keychains`. Each temporary HOME therefore links
  that one file, the login keychain, and nothing else of the real HOME.
- An item is owned by the build that created it. The run's own process cannot
  delete the executable's item (`Invalid attempt to change the owner of this
  item`), so cleanup uses `/usr/bin/security delete-generic-password` by exact
  service and account. An earlier run that failed at this step left two items
  under its own service; they were removed the same way and a lookup found
  nothing.
- `/usr/bin/script` refuses a socket for stdin, so the terminal the prompts need
  is a small Python pty bridge.

## How T12 is measured

A refusal is measured by three witnesses and not by the exit code alone: the
recording transport was never asked to send, the vault revision did not move,
and the audit count did not change. A target-side write is measured by the
whole serialized document before and after. The admission race is measured by
a store that revokes the grant between the run's read and its admission write.
The check itself was mutated: making the active-grant lookup ignore
revocation turned exactly the revocation, in-flight and race cases red.

## How T21 is measured

The restored vault is read directly and holds no grant and no approval. After
re-registering and re-approving the target, the run is still refused, because
the grant is gone; only a fresh grant from the re-registered owner makes it run.
