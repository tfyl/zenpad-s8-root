# Analysis tools

These tools run on the host and inspect local reference files.

| Tool | Purpose |
|---|---|
| `selinux/parse_policy.py` | Parse the ASUS version-30 binary SELinux policy, including Marshmallow ioctl rules |
| `selinux/query_policy.py` | Query permissions, properties, executable labels, and domain transitions |
| `droidboot/disassembly_index.py` | Interactive index of droidboot instructions, functions, strings, and references |
| `droidboot/find_references.py` | Find references to a hexadecimal droidboot address |
| `ota/extract_block_image.py` | Convert an OTA `.new.dat` file and transfer list into a filesystem image |
| `magiskboot` | Pinned upstream host binary for boot-image inspection |

Run from the repository root:

```bash
python3 tools/selinux/parse_policy.py
python3 tools/selinux/query_policy.py props dumpstate
python3 tools/selinux/query_policy.py fileaccess frp_block_device
python3 tools/droidboot/find_references.py 1aff9c
python3 -i tools/droidboot/disassembly_index.py
```

The policy and ELF inputs are under `reference/ww-5.5.1/`. Saved domain rule queries
are in `selinux/policy-rules/`. Droidboot indexes and disassembly excerpts are
in `droidboot/`; the reports are in [the research index](../docs/README.md).

Policy queries inspect stored reference rules, rather than deciding whether a
live operation is permitted. They do not model DAC, kernel checks, or the complete
running policy. The `rules --spec` filter is a regular expression over rule-kind
names; `--spec '^allow$'` selects ordinary allow rows. Source/target selectors
accept a literal type or attribute, or `/regex/`. Unknown literal selectors fail;
a regex matching no types produces no rows. `who` requires target, class, and
permission options.

For a locally supplied full OTA, extract its block image into ignored workspace:

```bash
mkdir -p work
python3 tools/ota/extract_block_image.py \
  work/system.new.dat work/system.transfer.list work/system.img
```

Artifact origins and hashes are recorded in [reference artifacts](../docs/artifacts.md).
