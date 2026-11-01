# Security policy

Ward is a local-first secret-management CLI. This policy says how to report a
suspected vulnerability, and what Ward does and does not defend against. The
bounds below are deliberate bounds of the v0.1 design;
the full record is the threat model in
[`docs/adr/0002-p0-threat-model-and-non-guarantees.md`](docs/adr/0002-p0-threat-model-and-non-guarantees.md).

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private
vulnerability reporting: open this repository's **Security** tab and choose
**Report a vulnerability**. If the Security tab offers no such option, private
reporting is not switched on: open an issue that says only that you have a
security report, with no details, and ask for a private route. Do not put the
vulnerability itself in a public issue.

## What Ward protects against

Ward is built to reduce accidental disclosure through normal use: committed
`.env` files, credentials passed as arguments, exported credentials, copied
command output, prompts, agent memory, raw HTTP errors, diagnostic logs,
unencrypted backups, and unintended cross-project lookup.

Tampering with the encrypted vault is detected before any plaintext is used. A
manifest copied into another repository does not grant access to the original
project's credentials, and a repository change does not silently widen an
operation the developer approved. Ward's supported agent commands do not
intentionally write stored values or key material into their output.

## What Ward does not defend against

Ward runs as your OS user. It is not a security boundary against code with the
same authority:

- **Same-user authority.** A compromised OS account, root, a hostile runtime or
  dependency, a debugger, an unlocked keychain, or arbitrary code running as you
  can reach the vault key and the secrets, as can a process that reads Ward's
  memory or a core dump of it. `BUN_OPTIONS` and `BUN_BE_BUN` reach
  the shipped executable with that authority.
- **Interactive prompts are not authentication.** A TTY check is a
  mistake-reduction, not a consent gate. Anything that can supply a
  pseudo-terminal (for example `script -q /dev/null`) can answer Ward's prompts,
  edit a manifest, approve its own profile, and run it; with the keychain item
  set to always allow, no OS dialog appears. The same route can export a full
  backup with a passphrase of its choosing and decrypt every secret offline. A
  project ID, a path check, an actor label, a TTY check and a prompt instruction
  are guardrails, not proof of a person.
- **Project separation is logical.** A single vault key does not
  cryptographically isolate one project from the vault owner.
- **Rollback is undetected.** Integrity detects a modified ciphertext, not an
  older valid one: copying an older vault back opens without complaint and
  revives revoked grants and approvals. Revocation blocks newly admitted
  operations only; Ward cannot recall a credential it has already sent or revoke
  it at its provider.
- **There is no forensic deletion.** Memory zeroing is best effort, with
  garbage-collector and native copies possible, and replaced values can remain
  in SQLite free pages. The audit ring holds 500 events across the vault, so one
  project's activity can evict another's, and records carry the observed OS user
  and host plus self-asserted labels, not authenticated actor identity. Audit
  output is operator convenience, not an attestation.
- **The release is ad-hoc signed, not notarized, and has no publisher
  identity.** Keychain trust follows each build's cdhash, so expect one
  keychain approval after each upgrade. The dialog should appear right after
  you ran `~/.local/bin/ward` and name the `opum.ward` item; if it appears when
  you ran nothing, stop and do not approve. Checksums and the cdhash detect a
  corrupted download, not a compromised release.

Ward makes no claim of perfect memory zeroization, swap exclusion, forensic
deletion, rollback resistance, immutable audit logging, FIPS validation,
universal prompt-injection resistance, or information-flow noninterference.
