# Host scripts

Connection scripts use the settings in [`config.example.env`](../config.example.env).
Run them from the repository root after loading your local configuration.

| Script | Purpose |
|---|---|
| `update-cached-payload.sh` | Update an already staged chain and verify the cached payload bytes before collecting diagnostics |
| `inspect-unlock-state.sh` | Read process state, unlock properties, and cached executable hashes |
| `patch-magisk-boot.sh` | Verify the recorded APK/stock hashes, patch for x86, and verify the stage-1 output hash |
| `flash-boot-image.sh` | Flash the supplied boot image and wait for Android startup |
| `replay-magisk-setup.sh` | Experimental replay of the recorded Magisk setup taps; requires the same screen layout |
| `verify-root.sh` | Check root identity, SELinux mode, Magisk, and system properties |
| `check-public-tree.py` | Check release files and optional Git history for excluded artifacts and private data |
| `prepare-public-release.py` | Create a checked copy with fresh Git history and an explicit or neutral author identity |

The [methodology](../docs/methodology.md) describes the tested sequence and the
UI replay helper's limits. The payload updater assumes the initial chain is
already staged on the tablet.

Run host-only regression checks from the repository root:

```bash
python3 -B -m unittest discover -s tests -v
```

The checks use temporary Git fixtures, reference-policy data, and inert transport
mocks. They do not connect to a tablet, flash an image, or execute unlock binaries.
