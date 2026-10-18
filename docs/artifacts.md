# Reference artifacts

## Firmware inputs

The reference files came from the WW 5.5.1 OTA
`UL-P01M-WW-5.5.1.0-user.zip`. The expected boot hash is
`4d9b9b41e1e372d9d585e91248ce7ed14eaa74522c94147523a23a9266a4a09e`;
the droidboot container hash is
`610a5d4597382f4f4e666dc2d7548947db488ebd1d10b7541add9309b83fd63e`.

`reference/ww-5.5.1/ramdisk/` contains the WW ramdisk policy, contexts, properties, and init
configuration. Its `default.prop` identifies `WW_P01M-V5.5.1-20161004`.
`reference/ww-5.5.1/executables/` contains static analysis inputs from that published firmware.

Full firmware images and the Magisk APK are acquired separately and ignored by
Git. See [`firmware/README.md`](../firmware/README.md). The expected files can be
checked against `firmware/SHA256SUMS` after acquisition.

The host patch uses Magisk 30.7's x86 payloads. It reproduced the reference
patched-boot hash
`99a04c22f698bc4a69f5ce8e445e65d63e0022818a7dfd1ce8a1e0c2d0eaf577`.
No original PGDO boot backup or final app-repatched boot is distributed.

## Payloads

| File | Role |
|---|---|
| `unlock/src/set_unlock_flag.c`, `unlock/bin/set-unlock-flag-x86` | Final v6 unlock source and reference binary |
| `unlock/src/restart_zygote.c`, `unlock/bin/restart-zygote-x86` | Dumpstate/logcat trigger source and reference binary |
| `unlock/src/dirtycow.c`, `unlock/bin/dirtycow-x86_64` | Dirty COW primitive source and reference binary |
| `unlock/experiments/set-unlock-flag-v3-x86`, `unlock/experiments/set-unlock-flag-v4-x86`, `unlock/experiments/set-unlock-flag-v5-x86` | Earlier diagnostic binaries |
| `unlock/experiments/boot_dump_v8.c` | Unfinished later boot-dump experiment; no matching binary was archived |

An independent Linux x86-64 host check used GCC 13.3.0 (Ubuntu package
`13.3.0-6ubuntu2~24.04.1`), the original source basenames, and the commands in
[the methodology](methodology.md#2-build-the-payloads). The v6 and Dirty COW
outputs matched their archived binaries byte-for-byte. These compiler details
identify the verified rebuild environment; the original compiler, binutils,
and libc versions are not recorded here.

| Archived binary | Architecture | SHA-256 | Documented rebuild |
|---|---|---|---|
| `unlock/bin/set-unlock-flag-x86` | i386 | `ba6bafb49ba5bda49126b78065542bbf770e6ddc520ce158fd8e0490108dc206` | Byte-identical |
| `unlock/bin/restart-zygote-x86` | i386 | `43a4bc7ec94922b77a7d784d35ea4be8293cd0c7ef61faa8468c5c09f76211f7` | Builds; differs from archive |
| `unlock/bin/dirtycow-x86_64` | x86-64 | `153045c271c7bdcb39d9f4b3a73728a6784e2a69a9c8b03664cbcacd52a53079` | Byte-identical |

The carrier rebuild hash was
`8650dea67d65d7a462e0add2d68016e0bd856a41be2911610133ab0d18427b9e`.
The mismatch also occurred with the original source path; its cause is unresolved,
and functional equivalence is unestablished. Compiler changes can alter bytes.
The archived v6 source and binary are preserved with the
[known parent diagnostic-parser defect](methodology.md#archived-v6-diagnostic-limitation).

The v3 binary hash is
`bfa350c86819eed02e92d4f209bce6dffa83d299106955d6f71a71b666a73d4a`.
It is a different version from the v8 source.

See the [experiment index](../unlock/experiments/README.md) for the status of
the archived diagnostic builds and the LogTool script-writer experiment.

## Host boot tool

`tools/magiskboot` is the x86-64 host executable extracted from
`lib/x86_64/libmagiskboot.so` in the pinned Magisk 30.7 APK. Its SHA-256 is
`a18ecbd7981179494b7d281453d6c4e25b5c719e7d2ef7f6eba3c6be3043c58e`.
The boot-patching script verifies the pinned APK and stock-boot hashes before
extracting and executing its own host tool. It accepts only the x86 device
payload and verifies the recorded host-patched output hash.

## Analysis inputs

The droidboot indexer uses `reference/ww-5.5.1/executables/droidboot`, an ELF executable, with the
matching disassembly and string index. The firmware `droidboot.img` is an Android
boot container, not that ELF. The reference policy parser reads
`reference/ww-5.5.1/ramdisk/sepolicy`.

Target-derived executable copies, raw partition probes, user-storage images,
and screenshots are excluded from the publication tree. A reference-policy
query does not establish the complete contents of a running device's policy.

## Acquisition and licensing gaps

The inventory identifies files and extracted outputs, but it is not a complete
acquisition recipe. This tree does not record the original OTA download/archive
URL or an OTA ZIP hash, or a complete archive-entry/extraction command record
for every bundled reference. External availability of the original OTA has not
been verified. The boot and droidboot hashes identify the extracted images;
they do not authenticate a separately obtained OTA archive.
The pinned Magisk version has an [upstream v30.7 release page](https://github.com/topjohnwu/Magisk/releases/tag/v30.7).

`reference/ww-5.5.1/ramdisk/` contains boot-ramdisk inputs. The executable
references were extracted from the published WW firmware; the droidboot ELF is
distinct from its Android boot container. The OTA system block-image conversion
is described in [the analysis-tool guide](../tools/README.md). The original
per-file extraction record is incomplete.

The upstream revision and local-change history for the imported Dirty COW source
are not recorded in this tree. The [references](references.md#dirty-cow)
identify the vulnerability disclosure, kernel fix, and related Android PoC;
they do not establish the imported file's exact source revision.
A complete license/notice inventory for imported code and
bundled vendor/upstream binaries is also missing. Public distribution of an
input does not, by itself, establish its redistribution terms. This document
does not assign a new license to those materials or supply missing attribution.
