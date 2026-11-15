---
# yaml-language-server: $schema=../../.lore/schemas/adr.schema.json
type: ADR
title: "TPM2 key custody on Linux: tool trust, the leaked session slot and the stored-format template"
tags:
  - tpm2
  - linux
  - vault-format
  - security
summary: "TPM2 custody as built in slice 3a/3b: the tool-trust rules, the leaked-session behaviour, and the primary template as stored-format contract (DEC-262 a15-a20, DEC-255 a6)."
generated:
  by: lore/0.14.1
  at: 2026-11-15T02:02:24.217Z
---

# TPM2 key custody on Linux: tool trust, the leaked session slot and the stored-format template

## Status

Accepted, 2026-11-15 (UTC), under **DEC-262 (a15), (a16), (a17), (a18), (a19) and (a20)** and **DEC-255
(a6)**, ruled by opum-doc as design authority (not the operator's words) and carried here from its
relays. The decision record binds, not this document's copy. It records what slices 3a and 3b of
WCLI-21 **built** (opum-ai/ward-cli#326 and #331), not what was proposed. The wiring that makes
Linux select this provider is slice 3d and is deliberately not decided here.

## Context

[ADR 0001](0001-vault-storage-and-key-custody.md) put the vault key in the macOS Keychain. A headless
Linux host has no keychain, so WCLI-21 seals the 32-byte vault key to the host's TPM2 through
`tpm2-tools` and keeps only the sealed blobs on disk: the key unseals after the process and the host
restart with nobody present, and cannot be unsealed off-host. Ward is public since 0.1.1, so every
stored format is a contract (DEC-255 a6). Three things about that provider needed a recorded
answer because a later change could break them without any test noticing: what makes a `tpm2_*`
binary trustworthy enough to receive the key on its stdin, what happens when the tool leaves a saved
session behind, and which bytes of the sealing recipe are part of the vault's stored format.

## Decision

**(i) A tool receives the key only after a trust walk (DEC-262 a10, a12, a13, a14).** Every element
from the resolved `tpm2_*` path to the final regular file is checked: each directory component, each
symlink hop (its target resolved component by component) and the file. Each must be owned by root or
the invoking user and must not be group- or other-writable; a sticky bit does not excuse a writable
directory, and a symlink is judged by its owner only because who can replace it is decided by the
directory that holds it. A failure refuses by name, before any spawn, and a later `PATH` entry is
never tried in its place. The walk runs at each detection, before any spawn, not once at install.

**The shebang rules, as built.** An executable is the walked file plus what its `#!` line names. The
interpreter must be an absolute path made of printable ASCII (a `\r` is refused here, not
interpreted), must pass the same walk, and is judged by its final file, which must not itself start
with `#!`: that is refused, never followed. A line longer than the 256 bytes Ward reads, or a file
it cannot read, is refused: the check fails closed rather than skipping. The text after the
interpreter (spaces and tabs trimmed, as Linux does) is ONE argument. When the interpreter is `env`,
by the name written or by the final file (a multicall install or an alias), that argument must be a
single bare command name (no `/`, no `=`, not starting with `-`), because `env` resolves it on the
child's confined `PATH`. That `PATH` is built, never inherited: the tool's own directory, then
`/usr/bin` and `/bin`, each of which passes the walk first. The child also gets
`TPM2TOOLS_TCTI=device:/dev/tpmrm0` and a C locale, and no `LD_*`, `DYLD_*` or `HOME`, so an
inherited TCTI cannot point the tools at another TPM.

**(ii) Recorded residuals, not defects.** Each needs a trusted owner to write the bad file, which is
the packaging-defect class, and none is closed by this ADR.
- **The RUNPATH residual (a12 rule 3).** An ELF `RUNPATH` that points at a directory another user
  can write is a packaging defect outside AC2. Ward does not parse ELF, and shared libraries are not
  walked.
- Spotting `env` by name misses a hardlink or copy of it under another name, and a multicall alias
  whose written and final names are both something else.
- Other single-argument wrappers (`nice`, `nohup`, `timeout`, `stdbuf`, or a shebang of
  `/bin/sh /abs/script`) can run an unwalked absolute path through the one shebang argument.

**(iii) The session, and the leaked saved-session slot (DEC-262 a9, a15 items 1 and 2, a17).** Every
unseal starts a fresh salted HMAC session (never a saved or reused one) in its own scratch
directory, requires the session's decrypt and encrypt attributes on before the unseal, reads the 32
bytes from `tpm2_unseal`'s stdout only, and flushes the session. The attribute check is fail-closed
and has two refusals that never merge: a printout that parses and says encryption is off is
`session_not_encrypted` (the AC2 stop, a security failure); a printout that does not parse against
the measured shape is `tool_incompatible`, which names the `tpm2-tools` version and is never worded
"not encrypted". Ward holds no `/dev/tpmrm0` connection and a saved session survives into another
process, so **a flush that fails leaks a saved-session slot until a TPM reset or a reboot**. The
behaviour is:
- After a **successful** unseal, the key is returned. `unsealKey` calls its optional `onWarning`
  exactly once with `{ code: "tpm_session_leaked" }`, which carries no path and no handle. There is
  no retry. Only the session Ward created, by its own path, is ever flushed, so a handle Ward did not
  create is never touched. A listener that throws, or returns a rejecting promise, cannot take the
  key away.
- After a **failed** unseal, the unseal's own error is rethrown with a readonly `flushFailure`
  holding the flush's reason, and `detail` stays the unseal's. No warning is emitted.
- Doctor reports the **visible saved-session handle count** as an attention state that does not fail
  doctor and names what clears it: a reset or a reboot. The count comes from `tpm2_getcap
  handles-saved-session`, which is not a required tool: it is resolved and trust-walked on its own,
  and a count that cannot be read (absent, untrusted, failed, unrecognised output) is a distinct
  "unavailable" answer, never zero and never a failure. An untrusted `tpm2_getcap` reports its reason
  and the path as fields, because an untrusted binary on the tool path may be a tampering signal.
  The count says only what is visible: it may be another program's session, and a Ward unseal
  running at that moment can show a self-clearing 1. An unseal that times out can also strand a saved
  session (NB4); only the count shows that.

**(iv) A lone `.priv` is a sealed key with its pair gone (DEC-262 a16 Q1).** The private blob is the
single commit marker, written last, so it alone says a key exists. A lone `.priv` is
`key_incomplete`, a recovery condition that refuses with the do-not-run-setup hint and never leads to
a re-init; a lone `.pub` holds no key and stays `key_not_sealed`. An `EEXIST` on the `.pub` link is
not `key_exists`: only the `.priv` link says a key now exists.

**(v) The sealing recipe is part of the stored-format contract (DEC-262 a15 item 3, DEC-255 a6).**
The primary is recreated from one pinned template at each use, because a saved context does not
survive a reboot and a changed `tpm2-tools` default would orphan the blob:

```
tpm2_createprimary -C o -g sha256 -G ecc256:aes128cfb \
  -a restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda -c <ctx> -Q
tpm2_create -C <primary> -g sha256 -a fixedtpm|fixedparent|noda|userwithauth -i - -u <pub> -r <priv> -Q
```

The key reaches `tpm2_create` only on its stdin; it is never in argv, a file or the environment. The
sealed object carries **no PCR binding**, because a policy would stop it unsealing after the host
restarts with nobody present. The blobs are `vault-key.pub` and `vault-key.priv`, 0600, in Ward's 0700
directory, published with `link(2)` (which refuses to replace) public first and private last. **A
sealed blob loads only under the primary it was created under, so any change to `-G ecc256:aes128cfb`,
to the explicit `-a` set of the primary, or to the sealed object's attributes is a vault-format
change under DEC-255 (a6).** It needs a re-seal or migration design and comes back to opum-doc
before code. The vault file is unchanged by this provider: nothing new is written into it.

**(vi) A named limitation (DEC-262 a20).** `tool_incompatible` does not win by construction: a load
the tools reject reads as `key_unloadable`. It is accepted, and bounded by (a18) 1 and 2. A
`tpm2_load` that exits non-zero on a complete, private pair is the doctor state `key_unloadable`,
with the contract code `tpm_tool_failed`. Its wording is fixed on the state, not left to a renderer:
the key "could not be loaded" and a TPM clear (`tpm2_clear`) "is a likely cause, among others",
never a statement that the TPM was cleared; it advises nothing destructive and carries only the
do-not-run-setup caution, because setup would destroy the only copy. Access refused, an untrusted
tool and a timeout each win over it, and `tool_incompatible` is found only by an unseal's session
printout. A pre-load probe would close the limitation and reopens only on a real report of a
version-caused load failure.

## Measured

Every fact above about `tpm2-tools` 5.6 was measured on the Jetson (TPM at `/dev/tpmrm0`, the kernel
resource manager only, a throwaway primary, no real key):
- **Probe 1, 2026-11-09.** The pinned template and `-i -` with the sealed attributes are accepted;
  create, load and an unseal without a session round-trip a throwaway key; the tools write every
  context and blob file 0660 whatever the umask, so Ward sets 0600 itself.
- **Probe 2, 2026-11-09.** A salted HMAC session already has decrypt and encrypt on; the bare
  `tpm2_sessionconfig` printout is two lines, `Session-Handle: 0x...` then
  `Session-Attributes: continuesession|decrypt|encrypt`.
- **Probe 3, 2026-11-09.** The tools write the session file in place and keep an existing mode, so
  Ward's 0600 survives and the pre-unseal mode check does not refuse a real unseal.
- **Probe 4, 2026-11-09.** The two off shapes are measured, not invented (`...|decrypt` after
  `--disable-encrypt`, `continuesession` after `--disable-decrypt`); every bare printout carried the
  handle line first; `tpm2_sessionconfig --version` prints the one-line shape Ward reads the version
  from.
- **Probe 5, 2026-11-15 UTC** (2026-11-14 local; the date is bounded by a file mtime, as recorded on
  WCLI-21). With a session saved, `tpm2_getcap handles-saved-session` printed exactly
  `- 0x2000000\n`; with none saved it printed nothing; after the flush all four handle lists were
  byte-identical to before.

Not measured, and left to the T26 harness: encryption of the unsealed bytes on the wire, a reboot,
a second host, and a separate `tpm2_unseal` process using a saved session.

## Consequences

- A change to the primary template, the sealed attributes or the blob names is a vault-format change
  and cannot ship as a refactor: it needs a re-seal or migration design first. This ADR is where a
  reviewer finds that.
- The trust walk is a real cost on every use and a real refusal on a misinstalled host. Its
  residuals (RUNPATH, shared libraries, renamed `env`, other wrappers) stay open and are named, so
  nothing reads as covered that is not.
- A leaked slot is surfaced twice, once as a one-shot warning from the unseal that saw it and once
  as an attention count in doctor, and never retried. Neither fails a command or doctor.
- `key_unloadable` can be raised for causes other than a TPM clear. The hedge in its wording and the
  absence of any destructive advice are what keep that safe, and they are tested.
- **Not decided here:** the wiring that replaces the Keychain provider on Linux, the backend
  selection rules and the doctor surface (slice 3d). Its bindings stay on WCLI-21 until it builds
  them: the provider passes `onWarning`, and doctor shows the untrusted reason and path.
