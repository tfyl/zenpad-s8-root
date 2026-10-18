# References and earlier methods

## Dirty COW

Dirty COW (CVE-2016-5195) is the Linux copy-on-write race used for the cached
executable replacements. The vulnerability and the general overwrite primitive
predate this implementation.

- [Dirty COW disclosure site](https://dirtycow.ninja/) credits discoverer Phil
  Oester and explains the vulnerability.
- [Solar Designer's oss-security announcement, 21 October 2016](https://seclists.org/oss-sec/2016/q4/204)
  records the public disclosure and links the original technical material.
- [Linux fix by Linus Torvalds, commit `19be0eaffa3a`](https://github.com/torvalds/linux/commit/19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619)
  documents the `get_user_pages()` copy-on-write failure and its correction.
- [Red Hat's technical explanation](https://www.redhat.com/en/blog/understanding-and-mitigating-dirty-cow-vulnerability)
  explains the race and the effect on read-only mappings.
- [The Dirty COW community's proof-of-concept repository](https://github.com/dirtycow/dirtycow.github.io)
  contains the public `dirtyc0w.c` example and research wiki.
- [timwr's Android proof of concept](https://github.com/timwr/CVE-2016-5195)
  provides Android implementation background. The exact imported revision of
  this tree's `unlock/src/dirtycow.c` remains unestablished; see
  [the provenance limits](artifacts.md#acquisition-and-licensing-gaps).

## Earlier ZenPad methods

The [2016 Stack Exchange answer](https://android.stackexchange.com/questions/129000/root-asus-zenpad-s-8-0-z580ca)
uses IntelAndroid-FBRL's T2 temporary recovery and installs SuperSU. Its linked
guide targets Android 5.0. In the recorded locked PGDO Android 6.0.1 run,
`oem backup_factory` and `oem stop_partitioning` were rejected by the device-state
gate, and `oem startftm` was unknown. The direct recovery route was blocked in
that starting state.

[Shakalaca's 2018 Z580CA write-up](https://medium.com/@shakalaca/zenpad-s-8-0-z580ca-bootloader-unlocked-d878335365ab),
also linked in [XDA post #5](https://xdaforums.com/t/how-can-i-root-my-asus-zenpad-s8-z580c.3683395/post-76781752),
already documents the final-byte unlock flag. Its route uses older bootloader
components and T2 recovery before the standard unlock and Magisk steps. The
author records firmware and IFWI compatibility limits. This project did not
validate that toolkit end to end on its PGDO configuration.

The implemented chain reaches the same flag through Dirty COW on Android 6,
without downgrading droidboot, IFWI, or Android. The recorded outcome establishes
that chain's result; it does not establish that every downgrade route fails.
See [the methodology](methodology.md) for execution details and verification limits.

## Magisk

Persistent root uses [Magisk by topjohnwu](https://github.com/topjohnwu/Magisk).
The recorded version is [v30.7](https://github.com/topjohnwu/Magisk/releases/tag/v30.7).
The [reference artifact inventory](artifacts.md) records the pinned hashes and
the distinction between the host patch and Magisk's in-app Direct install.
