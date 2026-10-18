# WW 5.5.1 policy analysis: tooling notes

The completed policy report is [selinux-policy.md](selinux-policy.md).
These notes retain the initial parser failure and firmware-layout details.

- The reference is the WW 5.5.1 OTA ramdisk, retained in `reference/ww-5.5.1/ramdisk/`.
  It was not compared with a capture of the original PGDO policy.
- Host setools/libsepol failed to parse the version-30 policy with a
  “more than one specifier” error. The completed report documents ASUS's
  ioctl-permission encoding and the parser in `tools/selinux/parse_policy.py`.
- At analysis time, the host had setools 4.4.4, checkpolicy 33, debugfs 1.47,
  Java, unzip, and Python tooling installed.
- The OTA stores system data as `system.new.dat` (3,007,115,264 bytes),
  `system.transfer.list`, and an empty `system.patch.dat`. This is a block-based
  OTA payload, not an Android sparse ext4 image. `tools/ota/extract_block_image.py` converts it
  to a filesystem image for offline inspection.
