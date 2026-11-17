#!/usr/bin/env bash
# Native Orca authenticated RPC check over a public Argus WSS path.
# Pairing credential stays on the VM, in process memory. Never prints tokens.
set -euo pipefail
set +x
if [ "$#" -ne 1 ]; then echo "Usage: bash orca-auth-route.sh wss://argus.example/s/pair/orca"; exit 2; fi
endpoint="$1"
case "$endpoint" in
  wss://*) ;;
  *) echo "ARGUS_NATIVE_ORCA_RPC=FAILED_BAD_ENDPOINT"; exit 2;;
esac
if command -v orca-ide >/dev/null 2>&1; then
  orca=orca-ide
elif command -v orca >/dev/null 2>&1; then
  orca=orca
else
  echo "ARGUS_NATIVE_ORCA_RPC=FAILED_NO_ORCA_CLI"
  exit 2
fi
command -v jq >/dev/null 2>&1 || { echo "ARGUS_NATIVE_ORCA_RPC=FAILED_NO_JQ";exit 2; }
if ! offer="$("$orca" pair --address "$endpoint" --rotate --json 2>/dev/null)"; then
  echo "ARGUS_NATIVE_ORCA_RPC=FAILED_PAIR_OFFER"
  exit 3
fi
pairing_code="$(printf '%s' "$offer" | jq -er '.result.pairingUrl // empty')"
if [[ "$pairing_code" != orca://pair?* ]]; then
  echo "ARGUS_NATIVE_ORCA_RPC=FAILED_PAIR_FORMAT"
  exit 3
fi
if ! status_json="$("$orca" status --pairing-code "$pairing_code" --json 2>/dev/null)"; then
  code="$(printf '%s' "$status_json" | jq -r '.error.code // "unknown"' 2>/dev/null || echo "no-json")"
  echo "ARGUS_NATIVE_ORCA_RPC=FAILED_AUTH_STATUS code=$code"
  exit 4
fi
if ! printf '%s' "$status_json" | jq -e '.ok == true' >/dev/null; then
  error_code="$(printf '%s' "$status_json" | jq -r '.error.code // "unknown"')"
  echo "ARGUS_NATIVE_ORCA_RPC=FAILED_STATUS code=$error_code"
  exit 4
fi
if ! worktrees_json="$("$orca" worktree list --pairing-code "$pairing_code" --limit 1 --json 2>/dev/null)"; then
  echo "ARGUS_NATIVE_ORCA_RPC=FAILED_AUTH_WORKTREE"
  exit 5
fi
if ! printf '%s' "$worktrees_json" | jq -e '.ok == true' >/dev/null; then
  error_code="$(printf '%s' "$worktrees_json" | jq -r '.error.code // "unknown"')"
  echo "ARGUS_NATIVE_ORCA_RPC=FAILED_WORKTREE code=$error_code"
  exit 5
fi
echo "ARGUS_NATIVE_ORCA_RPC=PASS (status and authenticated worktree list)"
