# Local firmware inputs

Firmware images and APKs are not included in the source distribution. Supply
these files locally when reproducing the boot patch:

| Local filename | Input |
|---|---|
| `boot-stock-WW-5.5.1.img` | `boot.img` from the matching WW 5.5.1 OTA |
| `droidboot-WW-5.5.1.img` | Optional `droidboot.img` from the same OTA, for analysis |
| `Magisk-v30.7.apk` | Magisk 30.7 APK from its upstream release |

The OTA filename used for the reference build was
`UL-P01M-WW-5.5.1.0-user.zip`. Expected SHA-256 hashes are in `SHA256SUMS`.
Run its checks from the repository root, because its paths include `firmware/`:

```bash
sha256sum --check --ignore-missing firmware/SHA256SUMS
```

`--ignore-missing` skips the optional droidboot image and output when absent.
The patcher independently enforces the required APK and stock-boot hashes,
accepts only x86 device payloads, and verifies the host-patched output hash.

That manifest also includes the reproducible host-patched boot output,
`boot-magisk-WW-5.5.1-stage1.img`; it is an output, not an additional required input.

Use copies of vendor-distributed firmware for publication checks. Device captures
and backups belong outside the repository, even if they are named `boot.img`.

The original OTA download/archive URL, OTA ZIP hash, and exact Magisk upstream
release URL are not recorded in this tree. Input filenames and extracted-image
hashes do not fill those acquisition gaps. The
[artifact inventory](../docs/artifacts.md#acquisition-and-licensing-gaps) records
the remaining extraction, source-revision, and licensing/notice limits.
