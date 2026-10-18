#!/usr/bin/env python3
"""Extract an OTA block image from a .new.dat payload and transfer list.

Usage: extract_block_image.py INPUT.new.dat INPUT.transfer.list OUTPUT.img
"""
import sys

dat_path, list_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(list_path) as f:
    lines = [l.rstrip("\n") for l in f if l.strip()]

version = int(lines[0])
new_blocks = int(lines[1])
if version <= 1:
    stmt_start = 2
elif version <= 3:
    stmt_start = 4          # v3: version, new_blocks, src_blocks(0), extra(0)
else:
    stmt_start = 5          # v4: + one more header value

BS = 4096
with open(out_path, "wb") as out, open(dat_path, "rb") as dat:
    out.truncate(new_blocks * BS)
    for line in lines[stmt_start:]:
        parts = line.split(" ", 2)
        cmd, rng = parts[0], parts[1]
        vals = [int(x) for x in rng.split(",")]
        cnt = vals[0]
        if cnt == 0:
            continue
        ranges = list(zip(vals[1::2], vals[2::2]))
        size = sum(e - s for s, e in ranges)
        if cmd in ("erase", "zero"):
            for s, e in ranges:
                out.seek(s * BS)
                out.write(b"\x00" * ((e - s) * BS))
        elif cmd == "new":
            data = dat.read(size * BS)
            assert len(data) == size * BS, (len(data), size * BS)
            p = 0
            for s, e in ranges:
                n = (e - s) * BS
                out.seek(s * BS)
                out.write(data[p:p + n])
                p += n
        else:
            raise SystemExit(f"unsupported cmd: {line[:60]}")
print("done", flush=True)
