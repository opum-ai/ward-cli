# Ward

A local-first secret-management CLI for agentic engineering, part of the Opum
product family. An agent names a credential and an approved operation; Ward
consumes the credential without returning its value to the agent.

Ward is a local developer preview. It has no stability promise yet, and its
documentation is the design record rather than a finished manual.

## Install

```
gh release download v0.1.0 -R opum-ai/ward-cli -p 'ward-darwin-arm64*'
shasum -a 256 -c ward-darwin-arm64.sha256
install -m 0755 ward-darwin-arm64 ~/.local/bin/ward
```

Verify the checksum before installing anything, and expect one macOS keychain
re-approval afterwards: the binary is ad-hoc signed, so the trust in the vault
key follows that signature and a new build is a new identity. The full
procedure — the cdhash check, the keychain prompt, the profile re-approval a
snapshot bump raises, and how to upgrade — is
[Install and upgrade Ward from a release](docs/runbooks/install-and-upgrade-ward-from-a-release.md).

Prerequisites: macOS on Apple silicon (the only artifact built is
`darwin-arm64`), the GitHub CLI signed in to an account that can read this
private repository, and `~/.local/bin` on `PATH`. The
[latest release](https://github.com/opum-ai/ward-cli/releases/latest) carries
the same install steps.

## Where to read next

- [`docs/`](docs/) is the documentation bundle: the architecture decisions
  (`docs/adr/`), the runbooks (`docs/runbooks/`), and the release gate results
  (`docs/security-tests.md`).
- [`WARD_MVP_AGENT_SPEC.md`](WARD_MVP_AGENT_SPEC.md) is the v0.1 implementation
  brief the code answers to.
- [`skills/ward/SKILL.md`](skills/ward/SKILL.md) is the agent skill, packaged as
  the `opum-ward` plugin for Claude Code.
