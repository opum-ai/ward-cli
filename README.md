# Ward

A local-first secret-management CLI for agentic engineering, part of the Opum
product family. An agent names a credential and an approved operation; Ward
consumes the credential without returning its value to the agent.

Ward is a local developer preview. It has no stability promise yet, and its
documentation is the design record rather than a finished manual.

## Install

Once the repository is public, the release downloads over HTTPS with no GitHub
account:

```
curl -fLO https://github.com/opum-ai/ward-cli/releases/download/v0.1.1/ward-darwin-arm64
curl -fLO https://github.com/opum-ai/ward-cli/releases/download/v0.1.1/ward-darwin-arm64.sha256
shasum -a 256 -c ward-darwin-arm64.sha256 \
  && codesign --verify --strict ward-darwin-arm64 \
  && install -m 0755 ward-darwin-arm64 ~/.local/bin/ward
```

Until the repository is public, fetch the same two files with
`gh release download v0.1.1 -R opum-ai/ward-cli -p 'ward-darwin-arm64*'` from an
account that can read it.

The chain stops at the first failed check. Expect one macOS keychain
re-approval afterwards: the binary is ad-hoc signed, so the trust in the vault
key follows that signature and a new build is a new identity. The full
procedure — the cdhash check, what the keychain dialog should look like, the
profile re-approval a snapshot bump raises, and how to upgrade — is
[Install and upgrade Ward from a release](docs/runbooks/install-and-upgrade-ward-from-a-release.md).

Prerequisites: macOS on Apple silicon (the only artifact built is
`darwin-arm64`) and `~/.local/bin` on `PATH`. The
[latest release](https://github.com/opum-ai/ward-cli/releases/latest) carries
the same install steps.

## Security and limits

Ward is not a security boundary against code running with your OS authority.
Its stated limits:

- **A TTY check is not authentication.** Anything that can supply a
  pseudo-terminal (for example `script -q /dev/null`) can answer Ward's
  prompts, approve a profile, and export a full backup with a passphrase of its
  choosing — and with the keychain item set to always allow, no OS dialog
  appears. Ward does not defend against a same-user agent.
- **Same-user authority is outside the boundary.** A compromised account, root,
  a debugger, an unlocked keychain, or arbitrary code running as you can reach
  the vault key; so can `BUN_OPTIONS` and `BUN_BE_BUN` against the shipped
  executable.
- **Rollback is undetected.** Integrity detects a modified ciphertext, not an
  older valid vault copied back, which revives revoked grants and approvals.
- **There is no forensic deletion.** Memory zeroing is best effort, replaced
  values can remain in SQLite free pages, and the audit ring holds 500 events
  across the vault with observed user/host and self-asserted labels, not an
  authenticated actor identity. Audit output is operator convenience, not an
  attestation.
- **The release is ad-hoc signed, not notarized.** Expect one keychain approval
  after each upgrade; the dialog should appear right after you ran
  `~/.local/bin/ward`, and if it appears when you ran nothing, stop.
- **Checksums prove integrity, not authorship.** The documented checks detect a
  corrupted download, not a compromised release.

The full statement, and how to report a vulnerability privately, is in
[SECURITY.md](SECURITY.md).

## Where to read next

- [SECURITY.md](SECURITY.md) is the security policy: what Ward does and does not
  defend against, and the private reporting route.
- [`docs/`](docs/) is the documentation bundle: the architecture decisions
  (`docs/adr/`), the runbooks (`docs/runbooks/`), and the release gate results
  (`docs/security-tests.md`).
- [`WARD_MVP_AGENT_SPEC.md`](WARD_MVP_AGENT_SPEC.md) is the v0.1 implementation
  brief the code answers to.
- [`plugin/skills/ward/SKILL.md`](plugin/skills/ward/SKILL.md) is the agent skill, packaged as
  the `opum-ward` plugin for Claude Code.
