#!/usr/bin/env python3
"""Indexer for droidboot (stripped i386 PIE, bionic). Read-only analysis.
Usage: python3 -i disassembly_index.py  then use helper functions."""
import re, collections, bisect
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = HERE.parents[1] / 'reference' / 'ww-5.5.1' / 'executables' / 'droidboot'
ASM = HERE / 'droidboot.asm'
STR = HERE / 'strings.txt'

GOT = 0x1ADCEC  # .got.plt / _GLOBAL_OFFSET_TABLE_
TEXT_LO, TEXT_HI = 0x24980, 0x24980 + 0x11f866
RODATA_LO, RODATA_HI = 0x144200, 0x144200 + 0x2cc1c
# File-backed PT_LOAD ranges of the pinned reference ELF: (vaddr, offset, size).
LOAD_SEGMENTS = ((0, 0, 0x1a21c0), (0x1a3200, 0x1a2200, 0xb818))

def fileoff_to_vaddr(off):
    for vaddr, offset, size in LOAD_SEGMENTS:
        if offset <= off < offset + size:
            return vaddr + off - offset
    return None

# ---- strings ----
strings = {}   # vaddr -> str
with open(STR, 'r', errors='replace') as f:
    for line in f:
        m = re.match(r'\s*([0-9a-f]+)\s(.*)$', line.rstrip('\n'))
        if m:
            v = fileoff_to_vaddr(int(m.group(1), 16))
            if v is not None:
                strings[v] = m.group(2)
skeys = sorted(strings)
def str_at(v):
    return strings.get(v)
def str_near(v, back=0x40):
    """nearest string at or before v"""
    i = bisect.bisect_right(skeys, v) - 1
    if i >= 0 and v - skeys[i] <= back:
        return (skeys[i], strings[skeys[i]], v - skeys[i])
    return None

# ---- PLT names ----
plt_names = {}  # addr -> name
cur_plt = None
with ASM.open() as stream:
    for line in stream:
        m = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if m:
            a = int(m.group(1), 16); lbl = m.group(2)
            if lbl.endswith('@plt'):
                cur_plt = a; plt_names[a] = lbl[:-4]
            else:
                cur_plt = None

# ---- instructions ----
insns = []      # (addr, mnemonic+operands, raw line)
insn_at = {}    # addr -> idx
re_ins = re.compile(r'^\s+([0-9a-f]+):\t(.*)$')
with ASM.open() as stream:
    for line in stream:
        m = re_ins.match(line)
        if m:
            a = int(m.group(1), 16)
            insn_at[a] = len(insns)
            insns.append((a, m.group(2).strip()))

addrs = [a for a, _ in insns]

# ---- call targets -> function starts ----
call_targets = set()
for a, t in insns:
    m = re.match(r'^call\s+0x([0-9a-f]+)', t) or re.match(r'^call\s+([0-9a-f]+)\b', t)
    if m:
        call_targets.add(int(m.group(1), 16))
# entry + init_array entries are starts too
func_starts = set([0x2509e]) | call_targets

fstarts_sorted = sorted(func_starts)

# functions registered via tables (not direct call targets) — known starts
_EXTRA_STARTS = [
    0x29b60,  # oem dispatcher
    0x29660, 0x29730, 0x29690, 0x2a6c0, 0x2ab60, 0x29de0, 0x2a430, 0x29f90,
    0x29800, 0x297d0, 0x2b090, 0x2b200, 0x2cf00, 0x2cf60, 0x2d8d0, 0x31150,
    0x31c40, 0x31c80, 0x31cb0, 0x31ce0, 0x31380, 0x317b0, 0x318b0, 0x31190,
    0x2d300, 0x2e3f0, 0x2d110, 0x2cfb0, 0x3a780,
    0x113b50, 0x1144d0, 0x114620, 0x121200, 0x113090, 0x1131e0, 0x112ca0,
    0x113de0, 0x11ae40, 0x112ac0, 0x121240, 0x11ea90, 0x11e9d0, 0x1213c0,
    0x121000, 0x121cd0, 0x121970, 0x121b90, 0x121280, 0x112fd0, 0x113760,
    0x113cf0, 0x113850, 0x121ab0, 0x114390, 0x114770, 0x1118b0, 0x121d70,
    0x1211c0, 0x1114b0, 0x118f10, 0x111500, 0x119360, 0x1195d0, 0x1144d0,
]
func_starts |= set(_EXTRA_STARTS)
fstarts_sorted = sorted(func_starts)
def func_start(addr):
    """greatest known function start <= addr (nearest containing)"""
    i = bisect.bisect_right(fstarts_sorted, addr) - 1
    if i < 0: return None
    return fstarts_sorted[i]
def func_end(start):
    i = bisect.bisect_right(fstarts_sorted, start)
    if i < len(fstarts_sorted): return fstarts_sorted[i]
    return TEXT_HI

# ---- xrefs ----
# for each insn: memory operand displacements with %ebx -> ea=GOT+disp; immediates
re_mem = re.compile(r'(?:0x)?(-?[0-9a-f]+)?\(%(ebx|eax|ecx|edx|esi|edi|ebp|esp)\)')
re_imm = re.compile(r'\$(-?0x[0-9a-f]+)')

xrefs = collections.defaultdict(list)   # target vaddr -> [(insn_addr, line)]
funcs_xref = collections.defaultdict(set)  # func start -> {targets}
for a, t in insns:
    fs = None
    hits = set()
    for m in re.finditer(r'[-+]?0x[0-9a-f]+\(%ebx\)', t):
        d = int(m.group(0).split('(')[0], 16) if '0x' in m.group(0).split('(')[0] else int(m.group(0).split('(')[0])
        ea = (GOT + d) & 0xffffffff
        hits.add(ea)
    for m in re_imm.finditer(t):
        v = int(m.group(1), 16) & 0xffffffff
        hits.add(v)
    for ea in hits:
        if str_at(ea) is not None or (RODATA_LO <= ea < RODATA_HI) or (0x1a3200 <= ea < 0x1b7000):
            xrefs[ea].append((a, t))
            if fs is None:
                fs = func_start(a)
            funcs_xref[fs].add(ea)

def xrefs_str(s, exact=False):
    """find string vaddr(s) matching text; return {vaddr: [(insn_addr,line)...]}"""
    out = {}
    for v, txt in strings.items():
        if txt == s or (not exact and s in txt):
            out[v] = xrefs.get(v, [])
    return out

def d(x):
    return f'0x{x:x}'

def strref(v):
    if v in strings:
        return f'{d(v)} "{strings[v][:80]}"'
    n = str_near(v)
    if n:
        return f'{d(v)} (near "{n[1][:60]}" @ {d(n[0])} +{n[2]})'
    if 0x23d50 <= v < 0x24980:
        nm = plt_names.get(v)
        return f'{d(v)} <PLT {nm}>' if nm else f'{d(v)} <PLT?>'
    return d(v)

# disassembly range printer with annotations
def dis(start, end=None, n=None):
    if end is None and n is None: n = 60
    i = insn_at.get(start)
    if i is None:
        i = bisect.bisect_right(addrs, start) - 1
    out = []
    cnt = 0
    while i < len(insns):
        a, t = insns[i]
        if end and a >= end: break
        if n is not None and cnt >= n and a >= start: break
        ann = ''
        # annotate ebx-relative and immediates
        def repl(m):
            nonlocal ann
            raw = m.group(0); dsp = raw.split('(')[0]
            try:
                dd = int(dsp, 16) if dsp.startswith('0x') or dsp.startswith('-0x') else (int(dsp) if dsp else 0)
            except ValueError:
                dd = 0
            ea = (GOT + dd) & 0xffffffff
            s = str_near(ea, back=0x20)
            if s and s[2] == 0:
                ann += f' ; "{s[1][:70]}"'
            elif ea in plt_names:
                ann += f' ; GOT[{plt_names[ea]}]'
            elif str_at(ea):
                ann += f' ; "{str_at(ea)[:70]}"'
            return raw
        tt = re.sub(r'[-+]?0x[0-9a-f]*\(%ebx\)', repl, t)
        def repl2(m):
            nonlocal ann
            v = int(m.group(1), 16) & 0xffffffff
            if v in plt_names:
                return f'{plt_names[v]}@plt'
            if v in strings and (RODATA_LO <= v < RODATA_HI or 0x1a3200 <= v < 0x1b7000):
                ann += f' ; "{strings[v][:70]}"'
            return m.group(0)
        tt2 = re.sub(r'\$(-?0x[0-9a-f]+)', repl2, tt)
        # call/jmp target labels
        def repl3(m):
            tgt = int(m.group(2), 16)
            nm = name_at(tgt)
            if nm:
                return f'{m.group(1)} {nm}'
            return m.group(0)
        tt2 = re.sub(r'(call|j[a-z]+|jmp)\s+0x([0-9a-f]+)', repl3, tt2)
        fs = func_start(a)
        tag = 'F' if fs == a else ' '
        out.append(f'{tag}{a:6x}: {tt2}{ann}')
        i += 1; cnt += 1
    return '\n'.join(out)

def func_of(s, first_only=True):
    """find functions referencing string s; return list of func starts"""
    r = xrefs_str(s)
    fs = set()
    for v, xr in r.items():
        for a, _ in xr:
            f = func_start(a)
            if f is not None: fs.add(f)
    return sorted(fs)

def xref_lines(s):
    for v, xr in sorted(xrefs_str(s).items()):
        print(f'--- {d(v)} "{strings[v][:90]}"')
        for a, t in xr:
            print(f'    {d(a)}  {t}   (func {d(func_start(a))})')

# ---- data pointer scan (link-time vaddrs stored in file) ----
import struct
BINPATH = BIN
_raw = BINPATH.read_bytes()
def read_bytes(vaddr, n):
    """Read an entirely file-backed virtual address range, or return no bytes."""
    if n < 0:
        raise ValueError('byte count must be nonnegative')
    for start, offset, size in LOAD_SEGMENTS:
        if start <= vaddr < start + size and vaddr + n <= start + size:
            off = offset + vaddr - start
            return _raw[off:off+n] if off + n <= len(_raw) else b''
    return b''

def data_ptrs(lo=0x1a3200, hi=0x1ae200, lo_val=0x1000, hi_val=0x1ae000):
    """Scan aligned pointers in virtual [lo, hi), limited to file-backed loads.

    Return {pointer_vaddr: string}; each complete pointer must fit within both
    the requested bounds and a mapped segment. ELF metadata and BSS are skipped.
    """
    if lo < 0 or hi < lo:
        raise ValueError('invalid virtual address bounds')
    out = {}
    for start, offset, size in LOAD_SEGMENTS:
        first = (max(lo, start) + 3) & ~3
        end = min(hi, start + size)
        first_off = offset + first - start
        end_off = min(offset + end - start, len(_raw))
        for off in range(first_off, end_off - 3, 4):
            v = struct.unpack_from('<I', _raw, off)[0]
            if lo_val <= v < hi_val and v in strings:
                out[start + off - offset] = strings[v]
    return out

def ptrs_to(vaddr):
    """find data locations (vaddrs) whose 4-byte value == vaddr (pointer arrays)"""
    res = []
    target = struct.pack('<I', vaddr)
    # scan whole file (data segment + rodata)
    for seg in [(0x144200, 0x144200 + 0x2cc1c), (0x1a3200, 0x1a3200 + 0x86f0), (0x1ab940, 0x1ab940 + 0x2214), (0x1ae000, 0x1ae000 + 0xa18)]:
        off0 = seg[0] if seg[0] < 0x1a2200 else seg[0] - 0x1000
        blob = _raw[off0:off0 + (seg[1] - seg[0])]
        start = 0
        while True:
            i = blob.find(target, start)
            if i < 0: break
            if i % 4 == 0:
                res.append(seg[0] + i)
            start = i + 1
    return res

# ---- defined (exported) symbols as function map ----
sym_funcs = []  # (addr, size, name)
with (HERE / 'exported-functions.txt').open() as stream:
    for line in stream:
        parts = line.split()
        if len(parts) == 3:
            sym_funcs.append((int(parts[0], 16), int(parts[1], 16), parts[2]))
sym_funcs.sort()
sym_starts = [a for a, s, n in sym_funcs]
def sym_at(addr):
    i = bisect.bisect_right(sym_starts, addr) - 1
    if i >= 0:
        a, sz, n = sym_funcs[i]
        if a <= addr < a + sz:
            return f'{n}+0x{addr-a:x}' if addr != a else n
    return None

def name_at(addr):
    if addr in plt_names: return plt_names[addr] + '@plt'
    s = sym_at(addr)
    if s: return s
    if addr in strings and str_at(addr): return f'str:"{strings[addr][:40]}"'
    return None

def dump_func(start, maxins=400):
    end = func_end(start)
    print(f'===== func {d(start)} .. {d(end)} =====')
    print(dis(start, end, maxins))

if __name__ == '__main__':
    pass
