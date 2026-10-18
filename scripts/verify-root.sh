#!/usr/bin/env bash
# verify-root.sh — fast post-boot health check for the rooted Z580CA (PGDO 5.5.3).
# Usage: scripts/verify-root.sh   (bridge/serial overridable via env)
set -euo pipefail
BRIDGE=${BRIDGE:?Set BRIDGE to your SSH USB host (user@host)}
SERIAL=${SERIAL:?Set SERIAL to the target adb serial}

s() {
  local command
  printf -v command '%q' "$*"
  ssh "$BRIDGE" "adb -s '$SERIAL' shell $command"
}

echo "== adb state"
test "$(ssh "$BRIDGE" "adb -s '$SERIAL' get-state" | tr -d '\r\n')" = device

echo "== id via su (expect uid=0, context u:r:magisk:s0)"
ROOT_ID=$(s "su -c id" | tr -d '\r')
echo "$ROOT_ID"
[[ "$ROOT_ID" == uid=0\(root\)* ]] || { echo 'root check failed' >&2; exit 1; }

echo "== SELinux (expect Enforcing)"
MODE=$(s "su -c getenforce" | tr -d '\r\n')
echo "$MODE"
[ "$MODE" = Enforcing ] || { echo 'SELinux is not enforcing' >&2; exit 1; }

echo "== magisk version (expect 30.7:MAGISK:R)"
s "su -c 'magisk -v'"

echo "== magiskd processes (expect one root daemon; later boots may show two worker forks)"
s "ps | grep magiskd"

echo "== Magisk data directory contents"
s "su -c 'ls /data/adb'"

echo "== Android unlock-allowed property and build fingerprint (not a fastboot lock-state check)"
s "getprop sys.oem_unlock_allowed; getprop ro.build.fingerprint"

echo "== remaining ASUS package count (informational)"
s "pm list packages | grep -icE 'com\.asus'"
