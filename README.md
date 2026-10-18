# ZenPad S 8.0 unlock and root

Bootloader unlock and Magisk root for the ASUS ZenPad S 8.0 **Z580CA (P01MA)**,
running Android 6.0.1 on Intel Moorefield. The chain uses Dirty COW to reach
the unlock flag, then the bootloader's standard unlock command and a Magisk
boot patch.

## How it works

1. **Start the payload.** Dirty COW replaces the running session's cached
   `logcat` and `app_process32` contents. A bugreport starts dumpstate, whose
   modified logcat child sends `ctl.restart zygote` to init's property service.
2. **Reach the unlock flag.** The replacement zygote payload forks a child,
   sets its gid and uid to 1000, then changes its SELinux domain to
   `system_server`. That identity can open the persistent partition and set
   its final byte to `0x01`, the flag droidboot checks before allowing an unlock.
3. **Unlock through droidboot.** `fastboot flashing unlock` uses the device's
   confirmation screen and wipes userdata. The persistent flag survives reboot;
   the cached executable changes are cleared.
4. **Install persistent root.** An x86 Magisk patch goes into the boot image.
   Magisk's in-app Direct install completes setup, and a shell grant enables
   `su` from adb. Optional per-user app removals reduce the stock app set.

## Why this route

I didn't want to downgrade the tablet, and I hadn't found a solution I wanted
to use. I also wanted to figure it out for the love of the game.

## Recorded configuration and limits

The tested Android 6.0.1 system reported **PGDO 5.5.3**. The reference boot,
ramdisk policy, and static analysis inputs came from **WW 5.5.1**; the system
fingerprint does not identify a separately flashed boot image. Root with
**Magisk 30.7** and the resulting app set survived a clean reboot.

The device Dirty COW runner is **x86-64**. The carrier, unlock payload, and
selected Magisk payload are **32-bit x86**; the host tools use Linux x86-64.
The target must be able to execute the x86-64 runner.

The v6 run confirmed partition access and an already-allowed flag (`already1`);
the first writer was not isolated. Global SELinux mode reported `Enforcing`,
with earlier per-domain permissive denials. Play Integrity was not validated.
The [methodology](docs/methodology.md) records these limits, the archived v6
diagnostic-parser defect, and the missing initial staging commands.

## Implementation

| File | Role |
|---|---|
| [`unlock/src/dirtycow.c`](unlock/src/dirtycow.c) | Dirty COW page-cache patching primitive |
| [`unlock/src/restart_zygote.c`](unlock/src/restart_zygote.c) | Dumpstate/logcat carrier that requests a zygote restart |
| [`unlock/src/set_unlock_flag.c`](unlock/src/set_unlock_flag.c) | v6 payload: credential ordering, domain transition, flag access, and diagnostics |
| `unlock/bin/` | Reference binaries for the final implementation |
| [Host scripts](scripts/README.md) | Payload updates, Magisk boot patching, flashing, and root checks |
| [`tools/selinux/query_policy.py`](tools/selinux/query_policy.py) | Queries for the vendor SELinux reference policy |

## Documentation

- [Methodology](docs/methodology.md): builds, the recorded staging mechanism, verification, and evidence limits.
- [Reference artifacts](docs/artifacts.md): firmware origins, hashes, and source versions.
- [References and earlier methods](docs/references.md): upstream credits and comparison with the recovery and downgrade routes.
- [Research index](docs/README.md): supporting static analysis.
- [Privacy and publication](docs/privacy.md): excluded data and release checks.
- [Analysis tools](tools/README.md): SELinux queries, droidboot indexing, and OTA extraction.

Connection scripts require your own `BRIDGE` and `SERIAL` values; see
[`config.example.env`](config.example.env). Firmware images, APKs, device
captures, screenshots, and account data are excluded from the publication tree.

## References and credits

The page-cache primitive uses [CVE-2016-5195 (Dirty COW)](https://dirtycow.ninja/),
discovered by Phil Oester. See the [2016 disclosure](https://seclists.org/oss-sec/2016/q4/204)
and [Linux kernel fix](https://github.com/torvalds/linux/commit/19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619).
Persistent root uses [Magisk by topjohnwu](https://github.com/topjohnwu/Magisk/releases/tag/v30.7).

[Shakalaca's 2018 write-up](https://medium.com/@shakalaca/zenpad-s-8-0-z580ca-bootloader-unlocked-d878335365ab)
already documented the persistent-partition unlock flag. This implementation
reaches that flag from the running Android 6 system through Dirty COW.
