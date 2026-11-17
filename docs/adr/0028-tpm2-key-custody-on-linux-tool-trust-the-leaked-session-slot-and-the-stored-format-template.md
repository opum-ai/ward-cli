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

Accepted, 2026-11-15 (UTC), under **DEC-262 (a9), (a10), (a12), (a13), (a14), (a15), (a16) Q1, (a17),
(a18), (a19) and (a20)** and **DEC-255 (a6)**, ruled by opum-doc as design authority (not the operator's words) and carried here from its
relays. The decision record binds, not this document's copy. It records what slices 3a and 3b of
WCLI-21 **built** (opum-ai/ward-cli#326 and #331), not what was proposed. The wiring that makes
Linux select this provider is slice 3d: its selection rules are ruled in (a16) Q2 and built in 3d,
and this record does not decide them.

## Context

[ADR 0001](0001-vault-storage-and-key-custody.md) put the vault key in the macOS Keychain. A headless
Linux host has no keychain, so WCLI-21 seals the 32-byte vault key to the host's TPM2 through
`tpm2-tools` and keeps only the sealed blobs on disk. The design aim is that the key unseals after the
process and the host restart with nobody present and cannot be unsealed off-host; a reboot and a
second host are not yet measured (see Measured). Ward is public since 0.1.1, so every
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
interpreter must be an absolute path made of printable ASCII (a `\r` in the interpreter token is
refused here, not interpreted; the argument is not byte-checked unless the interpreter is `env`), must pass the same walk, and is judged by its final file, which must not itself start
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
process (measured 2026-11-08, and seen again from the other side by probe 5; both are listed under
Measured), so **a flush that fails leaks a saved-session slot until a TPM reset or a reboot**. The
behaviour is:
- After a **successful unseal whose flush fails**, the key is returned. `unsealKey` calls its optional `onWarning`
  exactly once with `{ code: "tpm_session_leaked" }`, which carries no path and no handle. There is
  no retry. Only the session Ward created, by its own path, is ever flushed, so a handle Ward did not
  create is never touched. A listener that throws, or returns a rejecting promise, cannot take the
  key away.
- After a **failed** unseal, the unseal's own error is rethrown with a readonly `flushFailure`
  holding the flush's reason, and `detail` stays the unseal's. No warning is emitted. This holds only
  when the unseal's error is a `Tpm2Error`: a non-`Tpm2Error` failure loses `flushFailure`, because
  `spawnTool` is still unwrapped (N4, #301 finding 10, carried to 3d).
- **`diagnoseTpm2`** (adapter-level; `ward doctor` does not call it until slice 3d) reports the
  **visible saved-session handle count** as an attention state that does not fail doctor and names
  what clears it: a reset or a reboot. The count comes from `tpm2_getcap handles-saved-session`,
  which is not a required tool: it is resolved and trust-walked on its own. A count that cannot be
  read (absent, untrusted, failed, unrecognised output) is a distinct "unavailable" answer, never
  zero and never a failure. An untrusted `tpm2_getcap` reports its reason and the path as fields,
  because an untrusted binary on the tool path may be a tampering signal. **When detection itself
  fails, no count is taken and the result has no `savedSessions` key, which is not "0 saved
  sessions":** 3d must not render it as zero (NN1, a 3d BINDING). The count says only what is
  visible: it may be another program's session, and a concurrent Ward unseal can show a
  self-clearing 1 (N6). An unseal that times out can also strand a saved session (NB4, N7); only the
  count shows that.

**(iv) A lone `.priv` is a sealed key with its pair gone (DEC-262 a16 Q1).** The private blob is the
single commit marker, written last, so it alone says a key exists. A lone `.priv` is
`key_incomplete`, a recovery condition that refuses with the do-not-run-setup hint and never leads to
a re-init; a lone `.pub` holds no key and stays `key_not_sealed`. An `EEXIST` on the `.pub` link is
not `key_exists`: only the `.priv` link says a key now exists.

**(v) The sealing recipe is part of the stored-format contract (DEC-262 a15 item 3, DEC-255 a6).**
The primary is recreated from one pinned template at each use, because a saved context does not
survive a reboot and a changed `tpm2-tools` default would orphan the blob. The contract is **these two
argv lines exactly as shown, nothing added or removed, plus the two blob names** (the lines are the
arguments after the tool name; `<ctx>`, `<primary>`, `<pub partial>` and `<priv partial>` are paths):

```
tpm2_createprimary -C o -g sha256 -G ecc256:aes128cfb -a restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda -c <ctx> -Q
tpm2_create -C <primary> -g sha256 -a fixedtpm|fixedparent|noda|userwithauth -i - -u <pub partial> -r <priv partial> -Q
```

A reviewer finds them in `src/adapters/tpm2-tools.ts` as `primaryArgs` (the first line),
`sealedObjectAttributes` (the `-a` value of the second) and the `tpm2_create` argv in `sealKey` (the
rest of the second), and the blob names as `sealedPublicName` (`vault-key.pub`) and
`sealedPrivateName` (`vault-key.priv`). The key reaches `tpm2_create` only on its stdin (`-i -`); it
is never in argv, a file or the environment. The sealed object carries **no PCR binding**, because a
policy would stop it unsealing after the host restarts with nobody present. The blobs are 0600 in
Ward's 0700 directory, published with `link(2)` (which refuses to replace) public first and private
last. **The directory is `<wardDir>/tpm/<vaultId>/` (DEC-262 a22), part of the stored format:** one
not user-owned or not 0700 refuses `blob_not_user_private` and is never chmodded. Moving it is a
vault-format change (DEC-255 a6) that goes to opum-doc first. **A sealed blob loads only under the primary it was created under, so any change to either
argv line (`-C o`, `-g sha256`, `-G ecc256:aes128cfb`, the primary's `-a` set, the sealed object's `-a`
set, or anything added or removed) or to a blob name is a vault-format change under DEC-255 (a6).** It
needs a re-seal or migration design and comes back to opum-doc before code. The vault file is
unchanged by slices 3a and 3b: nothing new is written into it. (a16) Q2 keeps it so for the wiring:
the backend that holds a vault's key is found by the presence of the key itself, not by a field
written into the vault.

**(vi) A named limitation (DEC-262 a20).** `tool_incompatible` does not win by construction: a load
the tools reject reads as `key_unloadable`. It is accepted, and bounded by (a18) 1 and 2. A
`tpm2_load` that exits non-zero on a complete, private pair is the doctor state `key_unloadable`,
with the contract code `tpm_tool_failed`. Its wording is fixed on the state, not left to a renderer:
the key "could not be loaded" and a TPM clear (`tpm2_clear`) "is a likely cause, among others",
never a statement that the TPM was cleared; it advises nothing destructive and carries only the
do-not-run-setup caution, because setup would destroy the only copy. Access refused, an untrusted
tool and a timeout each win over it **in `diagnoseTpm2`**, which runs detection first; **on the unseal
path that precedence needs a fresh detection before the load, which is a 3d BINDING** (otherwise
revoked access could read as `key_unloadable`). `tool_incompatible` is found only by an unseal's
session printout. In opum-doc's words: "B, the pre-load probe, reopens only on a real report of a
version-caused load failure."

**(vii) Not decided here: slice 3d.** The wiring that replaces the Keychain provider on Linux and the
backend selection rules (ruled in (a16) Q2, built in 3d) are not decided by this record. Their
bindings stay on WCLI-21 until 3d builds them, among them: the provider passes `onWarning`, with a
test that fails if it drops the warning; doctor shows the untrusted reason and path in its human
output and its JSON, asserting `tool_untrusted` and the word "untrusted"; the provider's `Tpm2Error`
(reason and detail, never the `WardError`) goes through `tpm2StateFor`; detection is fresh before a
load; the count is never rendered as zero when detection failed (NN1); a lone `.priv` counts as the
TPM holding a key in the presence check (N3 c); and N4 and N7 above. WCLI-21's note holds the full
carry list.

## Measured

Every measured fact above about `tpm2-tools` 5.6 comes from the Jetson (TPM at `/dev/tpmrm0`, the
kernel resource manager only, a throwaway primary, no real key). The first entry is quoted from
another repository's record; probes 1 to 5 were run for this work:
- **2026-11-08 (recorded 2026-11-09 from opum-agent commit df6d1685c, handoff OPAG-1636).** A salted
  HMAC session file crosses processes through `/dev/tpmrm0`: control and measurement both unsealed
  the throwaway key, with handles identical before and after. Not proven then: encryption of the
  unsealed bytes on the wire, a reboot, more than one host.
- **Probe 1, 2026-11-09.** The pinned template and `-i -` with the sealed attributes are accepted;
  create, load and an unseal without a session round-trip a throwaway key; the tools write every
  context and blob file 0660 under umask 077, so Ward sets 0600 itself.
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
  WCLI-21). With a session saved by a `tpm2_startauthsession` that had exited, a later
  `tpm2_getcap handles-saved-session` printed exactly `- 0x2000000\n`; with none saved it printed
  nothing; after the flush all four handle lists were byte-identical to before.

Not measured, and left to the T26 harness: encryption of the unsealed bytes on the wire, a reboot,
and a second host. Probe 2's note on WCLI-21 listed "a separate `tpm2_unseal` process using the saved
salted session" as still unmeasured; the 2026-11-08 measurement above, recorded the same day, is that
case (a session file crossing processes, with an unseal under it), so it is not listed again here.

## Consequences

- A change to either `tpm2_*` argv line in (v) or to a blob name is a vault-format change and cannot
  ship as a refactor: it needs a re-seal or migration design first. This ADR is where a reviewer
  finds that.
- The trust walk is a real cost at each detection and a real refusal on a misinstalled host. Its
  residuals (RUNPATH, shared libraries, renamed `env`, other wrappers) stay open and are named, so
  nothing reads as covered that is not.
- A leaked slot is surfaced twice, once as a one-shot warning from the unseal that saw it and once
  as a count from `diagnoseTpm2` (which doctor shows once 3d wires it), and never retried. Neither
  fails a command or doctor.
- The one-shot warning reaches the user on **stderr**, in front of anything else the command writes
  there, and never on stdout (DEC-262 a23). Under `--json` it is exactly one line,
  `{"warning":"tpm_session_leaked"}`, so a consumer that parses the stdout envelope must also read
  stderr for it; in human mode it is a sentence naming the code and that a reset or reboot clears
  the slot. Neither carries a path or a handle. A second warning type is a new question, not a
  reason to change the envelope.
  The contract is stated in [Ward's stderr output contract](../reference/ward-s-stderr-output-contract.md).
- `key_unloadable` can be raised for causes other than a TPM clear. The hedge in its wording and the
  absence of any destructive advice are what keep that safe, and they are tested.
- What 3d must build against this record is listed in (vii) and, in full, on WCLI-21.
