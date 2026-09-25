#!/usr/bin/env bash
set -euo pipefail

AWL="${1:?usage: connect-public-tester.sh <awl-binary>}"
TESTER_PEER_ID="12D3KooWJMUjt9b5T1umzgzjLv5yG2ViuuF4qjmN65tsRXZGS1p8"
TESTER_NAME="awl-tester"

# Wait for the local API. The server can take a few seconds to bring up its
# libp2p host and VPN interface on hosted runners.
ready=false
for _ in $(seq 1 45); do
  if "$AWL" cli me status >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  echo "::error::awl local API did not become ready"
  exit 1
fi

# Stable optional CI configs may already contain awl-tester. Ephemeral configs
# start empty and add the public tester here. The public tester auto-accepts
# ordinary peer auth; exit-node permission is checked separately by the
# workflow because it is not granted to arbitrary new peers.
if ! "$AWL" cli peers status 2>/dev/null | grep -q "$TESTER_NAME"; then
  "$AWL" cli peers add --pid "$TESTER_PEER_ID" --name "$TESTER_NAME"
fi

online=false
for _ in $(seq 1 45); do
  STATUS=$("$AWL" cli peers status 2>/dev/null || true)
  if printf '%s\n' "$STATUS" | grep -E "$TESTER_NAME.*online" >/dev/null; then
    online=true
    break
  fi
  sleep 2
done

"$AWL" cli peers status
if [ "$online" != true ]; then
  echo "::error::public awl-tester did not become online"
  exit 1
fi
