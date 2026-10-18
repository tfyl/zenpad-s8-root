# Methodology

This document records the v6 unlock mechanism and the Magisk installation that
followed. The exact initial manual staging and restoration commands are not
included in this guide, so it is not a complete fresh-device installation guide.
The supporting static analysis uses WW 5.5.1 firmware. The tested Android system
reported PGDO 5.5.3; a system build fingerprint does not identify the provenance
of a separately flashed boot image.

## Environment

The implementation targets an unpatched Android 6.0.1 x86 build on the Z580CA.
The device Dirty COW runner is x86-64; the carrier and unlock payload are i386,
and the boot patch uses Magisk's x86 payload. The target must support execution
of the x86-64 runner. The host build uses Linux x86-64, GCC with i386 output
support, Bash, and unzip.
An SSH-accessible USB host runs adb and fastboot.

Copy `config.example.env` to the ignored `config.local.env`, set your own
connection values, then load them:

```bash
set -a
source config.local.env
set +a
```

`SERIAL` selects the device in adb. This Intel droidboot build reports the fixed
dummy fastboot serial `1111111111111111`; `FASTBOOT_SER` overrides that value.
Keep an explicit serial on both tools, particularly when several devices are
connected. On the tested USB host, fastboot required `sudo -n`.

## 1. Establish the bootloader gate

The firmware lacked an OEM-unlocking switch in Developer options. Static analysis
of droidboot identified its unlock-allowed check: the last byte of the persistent
partition named by `ro.frp.pst` must be `0x01`.

This flag was already documented in [earlier Z580CA work](references.md#earlier-zenpad-methods).
The chain here reaches it through Dirty COW on the running Android 6 system.

The partition was `/dev/block/by-name/persistent`, backed by `mmcblk0p9`, with
mode `0660 system:system` and SELinux type `frp_block_device`. File permissions
and SELinux policy both matter when opening it. The selected process needs the
framework's uid and domain, not merely uid 0.

The reference policy parser makes the relevant permission rows inspectable:

```bash
python3 tools/selinux/query_policy.py props dumpstate
python3 tools/selinux/query_policy.py fileaccess frp_block_device
```

These queries describe the bundled WW reference policy. Runtime observations
must be checked separately rather than assumed to match every reference rule.

## 2. Build the payloads

The unlock-flag payload uses raw i386 syscalls and no libc. For its byte-exact
reference build, copy the source into the ignored build directory under its
original basename. GCC records that name in the ELF symbol table; the repository
path describes the source's purpose.

From the repository root:

```bash
mkdir -p work/build
cp unlock/src/set_unlock_flag.c work/build/payload32.c
gcc -m32 -static -nostdlib -ffreestanding -fno-builtin -O2 \
  -fno-stack-protector -fno-pie -no-pie \
  -fno-asynchronous-unwind-tables -fno-unwind-tables -fomit-frame-pointer \
  -o work/build/set-unlock-flag-x86 work/build/payload32.c
```

The same freestanding flags build the zygote-restart carrier. Its original
source basename is also retained in the build directory. The Dirty COW runner
uses libc and pthreads and is built for x86-64:

```bash
cp unlock/src/restart_zygote.c work/build/stage2_runner.c
cp unlock/src/dirtycow.c work/build/dirtycow_x86.c
gcc -m32 -static -nostdlib -ffreestanding -fno-builtin -O2 \
  -fno-stack-protector -fno-pie -no-pie \
  -fno-asynchronous-unwind-tables -fno-unwind-tables -fomit-frame-pointer \
  -o work/build/restart-zygote-x86 work/build/stage2_runner.c
gcc -m64 -static -O2 -fno-stack-protector \
  -o work/build/dirtycow-x86_64 work/build/dirtycow_x86.c -lpthread
```

An independent host check with GCC 13.3.0 (Ubuntu package
`13.3.0-6ubuntu2~24.04.1`) and these flags reproduced the archived v6 and
Dirty COW binaries byte-for-byte. This identifies a verified build environment,
not the original compiler. The original toolchain versions are not recorded here.

The carrier source builds, but its output differs from the archived carrier;
functional equivalence is unestablished. Compiler changes can alter bytes.
[Reference artifacts](artifacts.md#payloads) records the hashes and build limits.

## 3. Recorded staging and trigger mechanism

Initial staging was manual. Its exact transfer paths, permission changes,
cache-replacement commands, and restoration sequence are not included here.
The sequence below explains the mechanism; it does not reconstruct those steps.
`scripts/update-cached-payload.sh` requires an already staged chain.

The staged components are the Dirty COW runner, the unlock-flag payload, the
zygote-restart carrier, and pristine executable copies obtained from the target
for local restoration.
Those target-derived copies are intentionally excluded from this repository.
The updater expects the runner at `/data/local/tmp/dc` and transfers a replacement
to `/data/local/tmp/p32`; it does not establish the original carrier or backups.
The v6 source also checks `/data/dalvik-cache/x86/.pwnstop` before forking. An
existing marker parks the process instead of running the child. The record does
not establish a complete fresh-device setup or retry procedure for these paths.

The carrier sequence is:

1. Replace the cached `logcat` contents with the stage-2 runner and the cached
   `app_process32` contents with v6.
2. Use the bugreport keychord, Volume Down + Volume Up + Power, to start
   dumpstate through init.
3. Dumpstate executes the modified logcat. The runner retains the dumpstate
   domain and sends a property-service request directly, without executing
   `setprop`.
4. Init handles `ctl.restart zygote` and executes the modified `app_process32`
   in the zygote domain.

The property message is 128 bytes: a 32-bit command, a 32-byte name field, and
a 92-byte value field. The request uses command 1, name `ctl.restart`, and
value `zygote`.

The cached `/system` modifications were cleared by reboot. Reboot therefore
does not replace the initial dumpstate trigger. During an active respawn loop,
updating the cached payload allowed the next cycle to execute the new version.

## 4. Set credentials before changing domains

The v6 child performs `setgid(1000)` and `setuid(1000)` while it still has the
zygote domain's permissions. It then writes `u:r:system_server:s0`, including
the trailing NUL, to `/proc/self/attr/current`.

An earlier attempt changed domains first and then received `EPERM` from the
uid change. The reference policy lacks an allow rule for that capability in
`system_server`; a dontaudit rule suppresses the corresponding audit message.
The v6 ordering gives the child the uid/domain combination that can open the
persistent partition.

The payload reads the last byte, writes `0x01` when needed, fsyncs, and reads
back the result. Diagnostics use properties and a parent pipe. The successful
v6 check reported `already1`: it proved access and the allowed flag state,
but did not isolate which earlier attempt first set the byte.

### Archived v6 diagnostic limitation

The historical source and binary retain a defect in the parent pipe parser.
The child sends progress bytes, an `o`/`x` result, then diagnostic text. The parent
scans the entire buffer for progress characters, including characters in that
text. For a successful report ending `rb=1=0x01`, it can decode the final `0` as
progress and lose the `o` result. A host-only model reproduced this behavior.

The parent can consequently overwrite `sys.pwn.rc` with `-` and skip its
success/stop-marker branch despite a successful child readback. Parent status
and marker creation are therefore unreliable success criteria. Read the child
report and its readback field when interpreting the archived run. This is a
known defect in the preserved v6 implementation; no corrected payload is claimed.

## 5. Complete the standard unlock

Droidboot's `flashing get_unlock_ability` reported `The device can be unlocked.`
The subsequent `fastboot flashing unlock` and physical Volume Up confirmation
completed the unlock and wiped userdata. Android setup and adb authorization
were completed afterward.

Bare `fastboot oem` froze the droidboot loop during testing and required a power
cycle. The tested implementation does not depend on that command or an OEM
command scan.

## 6. Install persistent root

Obtain the reference firmware and Magisk APK separately, as described in
[`firmware/README.md`](../firmware/README.md). No captured boot or userdata image
is distributed with the source tree.

Run checksum commands from the repository root; the manifest paths include
`firmware/`:

```bash
sha256sum --check --ignore-missing firmware/SHA256SUMS
scripts/patch-magisk-boot.sh \
  firmware/Magisk-v30.7.apk firmware/boot-stock-WW-5.5.1.img \
  work/patch work/boot-magisk.img x86
scripts/flash-boot-image.sh work/boot-magisk.img
```

`--ignore-missing` permits the optional droidboot image and recorded output to be
absent. The patcher separately requires the pinned APK and stock-boot hashes
before executing the extracted host tool, accepts only the x86 device payload,
and checks the stage-1 output hash before returning it for flashing. Its hash
check covers the host-patched output, not the later app Direct-install image.

The patch work directory must be empty. The recorded configuration used
`KEEPVERITY=false`, `KEEPFORCEENCRYPT=false`, `RECOVERYMODE=false`, and
`VENDORBOOT=false`.

The manual app sequence requires Magisk to be installed and a shell `su`
request to have created the Shell entry before its Superuser switch is used.
The following commands make those prerequisites explicit after loading the local
connection settings and flashing the host patch (which creates `/tmp/others`
on the USB host):

```bash
scp -q firmware/Magisk-v30.7.apk "$BRIDGE:/tmp/others/Magisk.apk"
ssh "$BRIDGE" "adb -s '$SERIAL' install -r /tmp/others/Magisk.apk"
```

Open Magisk, complete its storage-permission prompt if shown, then choose
**Install → Direct install (Recommended)** and reboot. In the recorded manual
run, Direct install resolved the app's setup warnings.

After reboot, request shell root while watching the app's Superuser tab:

```bash
ssh "$BRIDGE" "adb -s '$SERIAL' shell 'su -c id'"
```

Approve or enable `[SharedUID] Shell / com.android.shell`. The recorded initial
request timed out; enabling the existing Shell entry granted access. The expanded
command sequence above has not been replayed end to end. The recorded manual
app outcome is the evidence for successful setup.

`scripts/replay-magisk-setup.sh` collects the recorded taps into an experimental
replay helper. It assumes a swipe-only lock and the same 1536×2048 portrait UI.
The helper has not been validated end to end; the manual app sequence was the
tested path.

The bundled reference boot originated in the WW OTA, not an original PGDO backup.
The boot image after the app's Direct install was not captured separately.
Boot success was verified, but earlier failures were not traced conclusively to
a particular boot-image incompatibility.

## 7. Reduce the app set and verify

The optional [package list](package-removals.txt) uses
`pm uninstall -k --user 0 <package>`. System APKs remain on disk. Launcher, input
method, Intel hardware services, Android core services, GMS, and Play Store were
kept. Factory reset can restore the system apps for user 0.

The recorded pass completed 30 removals and found two attempted entries already
absent. A clean reboot was followed by checks of root, the Magisk daemon, the
system fingerprint, and the resulting package set:

```bash
scripts/verify-root.sh
```

`su -c id` returned uid 0 in the Magisk domain. Global SELinux mode reported
`Enforcing`; earlier logs included per-domain permissive denials, so this does
not establish that every domain enforced every denial. Google account sessions,
Google-signed attestation, and Play Integrity were not validated by this work.
