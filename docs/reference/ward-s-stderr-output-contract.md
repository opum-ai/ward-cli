---
type: Reference
title: Ward's stderr output contract
tags:
  - stderr
  - contract
  - tpm2
summary: "What Ward writes on stderr: the one-shot tpm_session_leaked warning in its --json and human forms, and the rule that the error envelope is always the last stderr line."
generated:
  by: lore/0.11.0
  at: 2026-11-17T04:37:02.673Z
---

# Ward's stderr output contract

## Details

Ward writes machine output on stdout and diagnostics on stderr. This concept fixes what a consumer may rely on there (DEC-262 a23; ADR 0028 records the decision).

- Under `--json` the TPM leak warning is exactly one stderr line: `{"warning":"tpm_session_leaked"}`.
- In human mode it is one sentence: `warning: tpm_session_leaked: a TPM session slot may be leaked; it is cleared by a reset or reboot.`
- The warning carries a code only, never a path or a handle, and appears at most once per command.
- A warning can precede the error envelope; the error envelope is always the last stderr line.
- A consumer that parses the stdout envelope must also read stderr to see the warning. A second warning type is a new question, not a reason to change the envelope.
