// MUTANT REGISTER for slice 3d-1a (WCLI-21), written and committed BEFORE any
// run. Each line is a one-site mutation and the tests predicted to go red, by
// the first words of their titles; every other test in the file must stay
// green. Run against a saved copy of the source, restored after each. A
// prediction is never edited after its run: the observation is annotated
// beside it.
//   P1  the provider omits onWarning                      -> "a leaked session warning reaches the sink"
//   P2  the provider detects once and caches              -> "detection runs again before every load"
//   P3  key_incomplete maps to vault_key_missing          -> "a lone private blob is tpm_key_incomplete"
//   P4  the provider drops the tpm2 side channel          -> "a Tpm2Error rides on the WardError", "detection runs again before every load"
//   P5  the provider never marks a timeout abandoned      -> "a timed-out tool marks the call abandoned"
//   P6  create reads the key after its first await        -> "create copies the key before any await"
//   P7  create skips the read-back comparison             -> "a read-back that differs is unconfirmed"
//   P8  key_not_sealed passes through untranslated        -> "no sealed key is vault_key_missing"
//   P9  unsealKey drops flushFailure for a non-Tpm2Error  -> test/tpm2-tools.test.ts "a non-Tpm2Error unseal failure keeps flushFailure"
//   P10 runTool kills the child but not its group         -> test/tpm2-tools.test.ts "a timed-out tool's grandchild is killed"
//   P11 spawnTool does not detach the child               -> test/tpm2-tools.test.ts "a timed-out tool's grandchild is killed"
//   R1  observeKey maps tpm_key_incomplete to missing     -> test/reporting.test.ts "a lone private blob is never reported as a missing key"
//   R2  observeKey lets other tpm_* codes throw           -> test/reporting.test.ts "a TPM refusal is reported as an unavailable key"
//   S1  setup treats tpm_key_incomplete as missing        -> test/setup.test.ts "setup refuses over an incomplete sealed key"
export {};
