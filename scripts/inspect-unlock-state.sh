#!/bin/bash
# Inspect Z580CA unlock properties, processes and cached executable hashes.
# usage: BRIDGE=user@host SERIAL=<adb_serial> scripts/inspect-unlock-state.sh [adb_serial]
set -euo pipefail
SERIAL=${1:-${SERIAL:?Set SERIAL or pass the target adb serial}}
BRIDGE=${BRIDGE:?Set BRIDGE to your SSH USB host (user@host)}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib/adb-host.sh"
adb_host_validate

echo "== device =="
state=$(adb_host get-state | tr -d '\r\n')
printf '%s\n' "$state"
[ "$state" = device ] || { echo 'target adb device is not ready' >&2; exit 1; }

echo "== processes (cycle + stragglers) =="
adb_host_optional 'ps | grep -E "app_process|dumpstate" | grep -v grep'

echo "== parent comm =="
adb_host_optional 'P=$(ps | grep /system/bin/app_process | grep -v do_exit | tr -s " " | cut -d" " -f2); echo pid=$P; [ -n "$P" ] && cat /proc/$P/comm 2>&1'

echo "== sys.pwn.* props =="
adb_host_optional 'getprop | grep pwn' 2>&1

echo "== unlock-related props =="
adb_host_optional 'getprop sys.oem_unlock_allowed; getprop sys.boot_completed; getprop ro.frp.pst; getprop ro.boot.verifiedbootstate'

echo "== markers =="
adb_host_optional 'ls -la /data/dalvik-cache/x86/.pwnstop 2>&1; ls -la /data/dalvik-cache/x86/.pwnstate 2>&1'
adb_host_optional 'ls -la /data/local/tmp/' 2>&1

echo "== dirty head shas =="
echo -n "app_process32 (whole):    "
digest=$(adb_host exec-out 'dd if=/system/bin/app_process32 bs=1 2>/dev/null' | sha256sum)
printf '%s\n' "${digest%% *}"
echo -n "logcat head 9152:         "
digest=$(adb_host exec-out 'dd if=/system/bin/logcat bs=1 count=9152 2>/dev/null' | sha256sum)
printf '%s\n' "${digest%% *}"

echo "== partition block map (p4..p19 + boot/rpmb) =="
adb_host_optional 'for N in 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19; do echo p=N $N size=$(cat /sys/class/block/mmcblk0p$N/size 2>/dev/null) ro=$(cat /sys/class/block/mmcblk0p$N/ro 2>/dev/null); done; echo boot0 ro=$(cat /sys/class/block/mmcblk0boot0/ro 2>/dev/null); echo boot1 ro=$(cat /sys/class/block/mmcblk0boot1/ro 2>/dev/null); echo rpmb ro=$(cat /sys/class/block/mmcblk0rpmb/ro 2>/dev/null)'

echo "== recent avc =="
adb_host_optional 'dmesg | grep avc: | tail -12'

echo "== selinux mode =="
adb_host_optional 'cat /sys/fs/selinux/enforce; getenforce'
