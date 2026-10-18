#!/usr/bin/env bash
# Flash a supplied Android boot image through the USB host.
# Usage (from repo root on the devbox):
#   scripts/flash-boot-image.sh <path/to/boot.img>
#
# Recorded connection details:
#   * Use the bridge: sudo -n fastboot -s 1111111111111111.
#   * Bare `fastboot oem` wedged droidboot during the recorded run.
#   * droidboot's fastboot shows a dummy serial: 1111111111111111.
#   * adb reboot bootloader, wait for the fastboot device, flash boot, reboot, wait for adb.
set -euo pipefail

BRIDGE=${BRIDGE:?Set BRIDGE to your SSH USB host (user@host)}
SERIAL=${SERIAL:?Set SERIAL to the target adb serial}
FASTBOOT_SER=${FASTBOOT_SER:-1111111111111111}
IMG=${1:?usage: flash-boot-image.sh <boot.img>}

echo "== sanity: image magic"
[ "$(head -c8 "$IMG")" = "ANDROID!" ] || { echo "not an ANDROID! boot image"; exit 1; }

echo "== push to bridge"
ssh "$BRIDGE" "mkdir -p /tmp/others"
scp -q "$IMG" "$BRIDGE:/tmp/others/flash-boot.img"

echo "== reboot to bootloader and wait for droidboot"
ssh "$BRIDGE" "
  set -eu
  adb -s '$SERIAL' reboot bootloader
  READY=0
  for i in \$(seq 1 20); do
    sleep 3
    D=\$(timeout 5 sudo -n fastboot -s '$FASTBOOT_SER' devices 2>/dev/null | grep -c '$FASTBOOT_SER' || true)
    if [ \"\$D\" -ge 1 ]; then READY=1; break; fi
  done
  [ \"\$READY\" = 1 ] || { echo 'timed out waiting for droidboot' >&2; exit 1; }
  echo == flashing ==
  timeout 120 sudo -n fastboot -s '$FASTBOOT_SER' flash boot /tmp/others/flash-boot.img
  timeout 20  sudo -n fastboot -s '$FASTBOOT_SER' reboot
"

echo "== wait for Android"
BOOTED=0
for i in $(seq 1 30); do
  sleep 6
  B=$(ssh "$BRIDGE" "adb -s '$SERIAL' shell getprop sys.boot_completed 2>/dev/null" | tr -d '\r\n' || true)
  if [ "$B" = "1" ]; then BOOTED=1; echo "booted after ~$((i*6))s"; break; fi
done
[ "$BOOTED" = 1 ] || { echo 'timed out waiting for Android' >&2; exit 1; }
echo "== build fingerprint"
ssh "$BRIDGE" "adb -s '$SERIAL' shell getprop ro.build.fingerprint"
echo "Run scripts/verify-root.sh after a Magisk install; stock boot does not provide root."
echo DONE
