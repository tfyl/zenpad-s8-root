# Documentation

- [Methodology](methodology.md) explains the implemented chain, build commands,
  staged execution, and verification limits.
- [Reference artifacts](artifacts.md) identifies firmware inputs and source versions.
- [References and earlier methods](references.md) credits upstream work and compares
  the recorded chain with the temporary-recovery and downgrade routes.
- [Privacy and publication](privacy.md) describes the release boundary and checks.

The `research/ww-5.5.1/` reports provide supporting static analysis:

| Report | Subject |
|---|---|
| [Droidboot](research/ww-5.5.1/droidboot.md) | Unlock checks, command gates, and image verification |
| [Init](research/ww-5.5.1/init.md) | Services, property handling, and domain transitions |
| [Configuration and vouchers](research/ww-5.5.1/configuration-and-vouchers.md) | ASUS configuration storage and voucher verification |
| [Policy](research/ww-5.5.1/selinux-policy.md) | Vendor SELinux permission rows and binary analysis |
| [Parser notes](research/ww-5.5.1/policy-parser-notes.md) | Initial parser failure and OTA layout |

These reports analyze WW 5.5.1 reference firmware. Proposed routes in the reports
are research findings, not additional validated implementations. Device captures,
raw session handoffs, screenshots, and connection identities are excluded.
