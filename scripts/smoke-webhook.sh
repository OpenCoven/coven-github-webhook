#!/usr/bin/env bash
# Local webhook smoke test for coven-github.
#
# Verifies, against a running server, that:
#   1. an unsigned request is rejected (401 missing signature)
#   2. a request with a bad signature is rejected (401 invalid signature)
#   3. a correctly HMAC-signed request is accepted (200 ok)
#
# It signs with the same scheme GitHub uses (HMAC-SHA256, `sha256=` prefix), so
# a green run proves the signature path end-to-end without a real delivery.
#
# Usage:
#   scripts/smoke-webhook.sh [URL] [SECRET]
#     URL     webhook endpoint   (default: http://localhost:3000/webhook)
#     SECRET  github.webhook_secret from your config (default: $WEBHOOK_SECRET)
set -euo pipefail

URL="${1:-http://localhost:3000/webhook}"
SECRET="${2:-${WEBHOOK_SECRET:-}}"

if [[ -z "$SECRET" ]]; then
  echo "error: webhook secret required (arg 2 or \$WEBHOOK_SECRET)" >&2
  exit 64
fi

# A minimal, valid 'ping' delivery accepted and acknowledged without enqueuing
# a worker task, so the smoke test never needs coven-code or a GitHub token.
BODY='{"zen":"Keep it logically awesome.","hook_id":1}'

status() { # $1=description  $2=expected_code  $@=curl args
  local desc="$1" expected="$2"; shift 2
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "$@")"
  if [[ "$code" == "$expected" ]]; then
    echo "  ok   $desc -> $code"
  else
    echo "  FAIL $desc -> got $code, expected $expected" >&2
    return 1
  fi
}

echo "smoke-testing $URL"

# 1. Unsigned -> 401
status "unsigned request rejected" 401 \
  -X POST -H 'X-GitHub-Event: ping' -d "$BODY" "$URL"

# 2. Bad signature -> 401
status "bad signature rejected" 401 \
  -X POST -H 'X-GitHub-Event: ping' \
  -H 'X-Hub-Signature-256: sha256=deadbeef' -d "$BODY" "$URL"

# 3. Valid signature -> 200
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"
status "valid signature accepted" 200 \
  -X POST -H 'X-GitHub-Event: ping' \
  -H "X-Hub-Signature-256: $SIG" -d "$BODY" "$URL"

echo "smoke test passed"
