#!/bin/bash
# The temporary keychain the release workflow's sign job signs with (WCLI-185,
# DEC-301 item 1, docs/reference/developer-id-signing-and-notarization-path-
# draft-for-acceptance.md). Two commands:
#
#   signing-keychain.sh import    decode the operator's Developer ID .p12 into a
#                                 throwaway keychain with a random password,
#                                 let codesign use the key without a prompt, and
#                                 print KEYCHAIN_PATH=<path> for the caller to
#                                 export. It never prints a secret.
#   signing-keychain.sh cleanup   delete that keychain and every file import
#                                 decoded. Safe to run when import never ran or
#                                 stopped half way; the workflow runs it in an
#                                 always-run step.
#
# Environment: RUNNER_TEMP (a directory outside every upload path), and for
# import APPLE_CERT_P12_BASE64 and APPLE_CERT_PASSWORD. Nothing here sets -x.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must name a directory outside the upload paths}"
keychain="${RUNNER_TEMP}/ward-signing.keychain-db"
p12="${RUNNER_TEMP}/ward-signing-cert.p12"

case "${1:-}" in
  import)
    : "${APPLE_CERT_P12_BASE64:?}" "${APPLE_CERT_PASSWORD:?}"
    password="$(openssl rand -hex 24)"
    # Decoded outside any upload path and removed by cleanup.
    (umask 077; printf '%s' "$APPLE_CERT_P12_BASE64" | base64 --decode > "$p12")
    security create-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 3600 "$keychain"
    security unlock-keychain -p "$password" "$keychain"
    security import "$p12" -k "$keychain" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign
    security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
    # codesign finds the identity through the search list.
    security list-keychains -d user -s "$keychain" login.keychain-db
    rm -f "$p12"
    echo "KEYCHAIN_PATH=${keychain}"
    ;;
  cleanup)
    security delete-keychain "$keychain" 2>/dev/null || true
    rm -f "$p12" "${RUNNER_TEMP}/ward-notary-key.p8" "${RUNNER_TEMP}/ward-notary.zip"
    ;;
  *)
    echo "usage: signing-keychain.sh import|cleanup" >&2
    exit 2
    ;;
esac
