#!/bin/bash
# Host-side Magisk v30.7 boot patch for the x86 Z580CA.
# usage: patch-magisk-boot.sh <magisk.apk> <stock boot.img> <workdir(empty)> <out.img> [abi, default x86]
set -euo pipefail
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
  echo "usage: $0 <magisk.apk> <stock boot.img> <workdir(empty)> <out.img> [abi]" >&2
  exit 2
fi
APK=$(realpath -e -- "$1")
STOCK=$(realpath -e -- "$2")
W=$(realpath -m -- "$3")
OUT=$(realpath -m -- "$4")
ABI=${5:-x86}
[ "$ABI" = x86 ] || { echo 'the recorded patch supports only the x86 payload' >&2; exit 2; }
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MANIFEST=$SCRIPT_DIR/../firmware/SHA256SUMS
check_input() {
  local file=$1 name=$2 expected actual
  expected=$(awk -v name="firmware/$name" '$2 == name {print $1}' "$MANIFEST")
  actual=$(sha256sum -- "$file" | cut -d' ' -f1)
  if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
    echo "checksum mismatch for $name" >&2; exit 1;
  fi
}
# Verify inputs before extracting or executing any APK-supplied host program.
check_input "$APK" Magisk-v30.7.apk
check_input "$STOCK" boot-stock-WW-5.5.1.img
if [ -e "$W" ] && { [ ! -d "$W" ] || [ -n "$(ls -A -- "$W")" ]; }; then
  echo "work directory must be empty: $W" >&2
  exit 1
fi
mkdir -p "$W"; cd "$W"
unzip -q -o -j "$APK" lib/x86_64/libmagiskboot.so -d host
unzip -q -o -j "$APK" "lib/$ABI/libmagiskinit.so" "lib/$ABI/libmagisk.so" "lib/$ABI/libinit-ld.so" assets/stub.apk -d dev
mv host/libmagiskboot.so magiskboot; chmod 755 magiskboot
mv dev/libmagiskinit.so magiskinit; mv dev/libmagisk.so magisk; mv dev/libinit-ld.so init-ld; mv dev/stub.apk stub.apk
cp "$STOCK" boot.img
./magiskboot unpack boot.img
rc=0; ./magiskboot cpio ramdisk.cpio test || rc=$?
[ "$rc" = 0 ] || { echo "ramdisk not stock (status $rc)"; exit 1; }
SHA1=$(./magiskboot sha1 boot.img)
cp ramdisk.cpio ramdisk.cpio.orig
./magiskboot compress=xz magisk magisk.xz
./magiskboot compress=xz stub.apk stub.xz
./magiskboot compress=xz init-ld init-ld.xz
printf 'KEEPVERITY=false\nKEEPFORCEENCRYPT=false\nRECOVERYMODE=false\nVENDORBOOT=false\nSHA1=%s\n' "$SHA1" > config
./magiskboot cpio ramdisk.cpio \
  "add 0750 init magiskinit" "mkdir 0750 overlay.d" "mkdir 0750 overlay.d/sbin" \
  "add 0644 overlay.d/sbin/magisk.xz magisk.xz" "add 0644 overlay.d/sbin/stub.xz stub.xz" \
  "add 0644 overlay.d/sbin/init-ld.xz init-ld.xz" "patch" "backup ramdisk.cpio.orig" \
  "mkdir 000 .backup" "add 000 .backup/.magisk config"
for dt in dtb kernel_dtb extra; do if [ -f "$dt" ]; then ./magiskboot dtb "$dt" test; ./magiskboot dtb "$dt" patch || true; fi; done
rm -f kernel   # no Samsung/legacy-SAR kernel patches apply; repack keeps the original kernel
./magiskboot repack boot.img "$OUT"
check_input "$OUT" boot-magisk-WW-5.5.1-stage1.img
