#!/usr/bin/env bash
# Replay the recorded Magisk setup taps over adb.
# Automates: wake, swipe-unlock (assumes no PIN), apk install, storage permission,
# Install -> Direct install -> reboot, then the Superuser-tab toggle grant, and verify.
#
# Run from the repo root on the devbox (the bridge holds adb/fastboot):
#   scripts/replay-magisk-setup.sh [serial]
#
# Replay helper assembled after the manual run; not verified end to end.
# Coordinates come from the recorded 1536x2048 portrait screen. UI changes,
# dialogs and existing grants can change what a tap does. Watch the device.
set -euo pipefail

BRIDGE=${BRIDGE:?Set BRIDGE to your SSH USB host (user@host)}
SERIAL=${1:-${SERIAL:?Set SERIAL or pass the target adb serial}}
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
APK_LOCAL=${APK_LOCAL:-$REPO_ROOT/firmware/Magisk-v30.7.apk}

adb()  { ssh "$BRIDGE" "adb -s '$SERIAL' $*"; }
adbsh(){ ssh "$BRIDGE" "adb -s '$SERIAL' shell '$*'"; }
step() { echo "== $1"; }
cleanup() { adbsh "svc power stayon false" >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "push+install the manager apk"
ssh "$BRIDGE" "mkdir -p /tmp/others"
scp -q "$APK_LOCAL" "$BRIDGE:/tmp/others/Magisk.apk"
adb "install -r /tmp/others/Magisk.apk"

wake_unlock() {
  adbsh "svc power stayon true"
  adbsh "input keyevent 224"; sleep 1
  adbsh "input swipe 750 1900 750 400 250"; sleep 1
}

step "unlock screen and open the app"
wake_unlock
adbsh "monkey -p com.topjohnwu.magisk -c android.intent.category.LAUNCHER 1"; sleep 4
adbsh "input tap 1203 1060"   # storage-permission dialog: Allow (fresh install only)
sleep 2

step "Install -> Options(NEXT) -> Direct install -> LET'S GO"
adbsh "input tap 1352 375"    # Install on the Magisk card
sleep 3
adbsh "input tap 1381 218"    # NEXT (defaults: AVB/dm-verity off, force-encrypt preserved)
sleep 3
adbsh "input tap 99 489"      # radio: Direct install (Recommended)
sleep 1
adbsh "input tap 1345 343"    # LET'S GO
echo "-- console runs (~30-60s): unpack/patch/repack/flash"
sleep 45

step "tap Reboot and wait for the boot"
adbsh "input tap 1348 1827"
sleep 5
BOOTED=0
for i in $(seq 1 40); do
  sleep 5
  B=$(adbsh "getprop sys.boot_completed" 2>/dev/null | tr -d '\r\n' || true)
  if [ "$B" = "1" ]; then BOOTED=1; echo "   booted after ~$((i*5))s"; break; fi
done
[ "$BOOTED" = 1 ] || { echo 'timed out waiting for Android' >&2; exit 1; }
sleep 8

step "grant su for com.android.shell via the Superuser tab"
wake_unlock
adbsh "monkey -p com.topjohnwu.magisk -c android.intent.category.LAUNCHER 1"; sleep 3
adbsh "input tap 581 1849"    # Superuser tab
sleep 2
adbsh "input tap 1383 250"    # toggle ON: [SharedUID] Shell / com.android.shell (Forever)
sleep 2

step "verify"
adbsh "su -c id"
adbsh "su -c getenforce"
adbsh "ps | grep magiskd"

step "revert the stay-on setting"
adbsh "svc power stayon false"
echo DONE
