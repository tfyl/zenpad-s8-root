import disassembly_index, re, sys

GOT = 0x1ADCEC
ref_re = re.compile(r'[-+]?0x[0-9a-f]+\(%ebx\)')

def all_refs(target):
    """insns whose ebx-relative EA or immediate equals target (or negatives)"""
    hits = []
    for a, t in disassembly_index.insns:
        m = ref_re.search(t)
        if m:
            dsp = m.group(0).split('(')[0]
            try:
                dd = int(dsp, 16) if ('0x' in dsp) else int(dsp)
            except ValueError:
                dd = 0
            ea = (GOT + dd) & 0xffffffff
            if ea == target:
                hits.append((a, t))
                continue
        for mm in re.finditer(r'\$(-?0x[0-9a-f]+)', t):
            v = int(mm.group(1), 16) & 0xffffffff
            if v == target:
                hits.append((a, t))
                break
    return hits

if __name__ == '__main__':
    for arg in sys.argv[1:]:
        tgt = int(arg, 16)
        fs = disassembly_index.func_start(tgt)
        print(f'--- refs to {hex(tgt)} ({disassembly_index.sym_at(tgt) or disassembly_index.name_at(tgt) or "?"}) nearest-func {hex(fs or 0)}')
        for a, t in all_refs(tgt):
            f = disassembly_index.func_start(a)
            print(f'    {hex(a)}  {t}   (func {hex(f or 0)})')
