// MUTANT REGISTER for slice 3d-1b (WCLI-21), written and committed BEFORE any
// run. Each line is a one-site mutation and the tests predicted to go red, by
// the first words of their titles; every other test in the file must stay
// green. Run against a saved copy of the source, restored after each. A
// prediction is never edited after its run: the observation is annotated
// beside it.
//   K1  the router takes the first holder without probing the rest -> "two holders refuse as ambiguous"
//   K2  the ambiguous refusal drops the store names                  -> "two holders refuse as ambiguous"
//   K3  load goes to the init backend, not the holder                -> "an existing vault keeps the backend that holds its key"
//   K4  a probe that fails reads as not held (a fallback)            -> "an unavailable holder refuses by name"
//   K5  a probed key of a refused holder is not zeroed               -> "two holders refuse as ambiguous"
//   K6  linux initialises on the keychain backend                    -> "linux initialises on TPM2 when detection passes"
//   K7  linux falls back to the keychain when detection fails        -> "linux with no usable TPM refuses and creates nothing"
//   K8  linux with no holder passes the keychain's unsupported       -> "linux with no sealed key is a missing key"
//   K9  prepareDirectory repairs a wider directory to 0700           -> "a pre-existing directory that is not 0700 is refused and left alone"
//   K10 the blob directory drops the vault id segment                -> "the blob directory is <ward>/tpm/<vaultId>"
//   K11 holdsSealedKey looks for the public blob                     -> "a lone private blob counts as held and a lone public blob does not"
//   K12 main.ts keeps one createKeychainKeyProvider site             -> "no command composes the keychain provider directly"
//   K13 a wired command ignores keySelection                         -> "ward setup on linux seals through the selected backend"
//   K14 abandonedCall ignores a flushFailure of tool_timeout         -> test/tpm2-provider.test.ts "a timed-out flush"
//   K15 translate drops the path                                     -> test/tpm2-provider.test.ts "a Tpm2Error rides on the WardError"
//   K16 a non-Tpm2Error wrap carries String(error) as detail         -> test/tpm2-provider.test.ts "a non-Tpm2Error from the unseal", test/tpm2-tools.test.ts "a non-Tpm2Error unseal failure keeps flushFailure"
//   K17 the mid-seal list drops tool_failed                          -> test/tpm2-provider.test.ts "a tool failure mid-seal is unconfirmed"
//   K18 the mid-seal list drops tool_output_too_large                -> test/tpm2-provider.test.ts "a tool failure mid-seal is unconfirmed"
//   K19 observeKey reads one tpm_* code as a throw                   -> test/reporting.test.ts "every TPM code is reported as an unavailable key"
//   K20 a wired command whose tool timed out does not exit explicitly -> "a ward command whose tpm2 tool times out exits"
export {};
