#!/usr/bin/env bash
set -euo pipefail

server="$1/bin/technitium-dns-server"
"$server" config validate configuration/examples/minimal.json
state=$(mktemp -d)
trap 'sudo rm -rf -- "$state"' EXIT
cp configuration/examples/minimal.json "$state/technitium.json"
sudo unshare --net bash -se -- "$server" "$state" <<'SCRIPT'
ip link set lo up
"$1" --portable-app --stop-if-bind-fails "$2" &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" || true' EXIT
curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 1 http://127.0.0.1:5380/ > /dev/null
SCRIPT
