#!/usr/bin/env python3
"""parse_policy.py -- standalone parser for the ASUS WW 5.5.1 kernel binary SELinux
policy (policy version 30, MLS, xperms).  Format modelled on libsepol's
policydb_read()/avtab_read_item()/ebitmap_read() (SELinuxProject master),
targeting exactly the sections present at version 30:

  header, policycaps ebitmap, permissive_map ebitmap,
  8 symbol tables (commons, classes, roles, types, users, bools, levels, cats),
  te_avtab (u16 key + u32 data or xperms block), cond_list,
  role_trans, role_allow, filename_trans (pre-COMP_FTRANS "compat" layout),
  7 ocontext tables, genfs, range_trans, type_attr_map ebitmaps.

Devbox tool. READ-ONLY analysis support.
"""
import struct, sys
from pathlib import Path

DEFAULT_POLICY = (
    Path(__file__).resolve().parents[2]
    / 'reference' / 'ww-5.5.1' / 'ramdisk' / 'sepolicy'
)

U16 = lambda f, o: struct.unpack_from('<H', f, o)[0]
U32 = lambda f, o: struct.unpack_from('<I', f, o)[0]
U64 = lambda f, o: struct.unpack_from('<Q', f, o)[0]

AVTAB_ALLOWED      = 0x0001
AVTAB_AUDITALLOW   = 0x0002
AVTAB_AUDITDENY    = 0x0004
AVTAB_NEVERALLOW   = 0x0080
AVTAB_TRANSITION   = 0x0010
AVTAB_MEMBER       = 0x0020
AVTAB_CHANGE       = 0x0040
# AOSP marshmallow "ioctl operations" spec bits (NOT upstream xperms):
AVTAB_OPNUM_ALLOWED     = 0x0100
AVTAB_OPNUM_AUDITALLOW  = 0x0200
AVTAB_OPNUM_DONTAUDIT   = 0x0400
AVTAB_OPTYPE_ALLOWED    = 0x1000
AVTAB_OPTYPE_AUDITALLOW = 0x2000
AVTAB_OPTYPE_DONTAUDIT  = 0x4000
AVTAB_OP = 0x7700
AVTAB_ENABLED      = 0x8000      # runtime-only cond flag
AVTAB_ENABLED_OLD  = 0x80000000

SPEC_NAMES = {
    AVTAB_ALLOWED: 'allow', AVTAB_AUDITALLOW: 'auditallow',
    AVTAB_AUDITDENY: 'auditdeny/dontaudit', AVTAB_NEVERALLOW: 'neverallow',
    AVTAB_TRANSITION: 'typetransition', AVTAB_MEMBER: 'typemember',
    AVTAB_CHANGE: 'typechange',
    AVTAB_OPNUM_ALLOWED: 'allow ioctl-opnum', AVTAB_OPNUM_AUDITALLOW: 'auditallow ioctl-opnum',
    AVTAB_OPNUM_DONTAUDIT: 'dontaudit ioctl-opnum',
    AVTAB_OPTYPE_ALLOWED: 'allow ioctl-optype', AVTAB_OPTYPE_AUDITALLOW: 'auditallow ioctl-optype',
    AVTAB_OPTYPE_DONTAUDIT: 'dontaudit ioctl-optype',
}

SYM_NAMES = ['commons', 'classes', 'roles', 'types', 'users', 'bools',
             'sensitivities', 'categories']


class Cur:
    def __init__(self, data):
        self.f = data
        self.o = 0

    def u32(self):
        v = U32(self.f, self.o); self.o += 4; return v

    def u8(self):
        v = self.f[self.o]; self.o += 1; return v

    def raw(self, n):
        v = self.f[self.o:self.o + n]; self.o += n; return v

    def strn(self, n):
        s = self.raw(n)
        return s.rstrip(b'\x00').decode('utf-8', 'replace')

    def ebitmap(self):
        mapsize = self.u32(); highbit = self.u32(); count = self.u32()
        assert mapsize == 64, f'ebitmap mapsize {mapsize} at {self.o-12:#x}'
        bits = set()
        for _ in range(count):
            startbit = self.u32(); mp = U64(self.f, self.o); self.o += 8
            for b in range(64):
                if mp & (1 << b):
                    bits.add(startbit + b)
        return bits  # 0-based bit positions


class Policy:
    pass


def parse(path):
    data = open(path, 'rb').read()
    c = Cur(data)
    p = Policy()
    p.path = path
    magic = c.u32(); strlen = c.u32()
    assert magic == 0xf97cff8c, hex(magic)
    ident = c.strn(strlen)
    assert ident == 'SE Linux', ident
    p.version = c.u32()
    p.config = c.u32()
    p.sym_num = c.u32()
    p.ocon_num = c.u32()
    assert p.sym_num == 8 and p.ocon_num == 7, (p.sym_num, p.ocon_num)
    p.mls = bool(p.config & 1)
    p.policycaps = c.ebitmap()
    p.permissive_map = c.ebitmap()   # bits = permissive type values (0-based)

    # --- symbol tables ---
    commons = {}   # value -> {name, perms{value:name}}
    classes = {}   # value -> {name, perms{value:name}, common, constraints, defaults}
    roles = {}     # value -> {name, dominates, types}
    types = {}     # value -> {name, properties, bounds}
    type_by_name = {}
    users = {}
    bools = {}
    sens = {}
    cats = {}

    def perm_read(tbl):
        ln = c.u32(); val = c.u32()
        name = c.strn(ln)
        tbl[val] = name

    def common_read():
        ln = c.u32(); val = c.u32(); nprim = c.u32(); nel = c.u32()
        name = c.strn(ln)
        perms = {}
        for _ in range(nel):
            perm_read(perms)
        commons[val] = {'name': name, 'perms': perms}

    def class_read2():
        ln = c.u32(); ln2 = c.u32(); val = c.u32(); nprim = c.u32()
        nel = c.u32(); ncons = c.u32()
        name = c.strn(ln)
        comkey = c.strn(ln2) if ln2 else None
        perms = {}
        for _ in range(nel):
            perm_read(perms)
        def read_cons(ncons, allowxtarget):
            nodes = []
            for _ in range(ncons):
                perms_ = c.u32(); nexpr = c.u32()
                exprs = []
                for _ in range(nexpr):
                    et = c.u32(); attr = c.u32(); op = c.u32()
                    names = set(); tset = None
                    if et == 5:  # CEXPR_NAMES (CEXPR_ATTR=4 carries no payload)
                        names = c.ebitmap()
                        t1 = c.ebitmap(); t2 = c.ebitmap(); fl = c.u32()
                        tset = (t1, t2, fl)
                    exprs.append((et, attr, op, names, tset))
                nodes.append((perms_, exprs))
            return nodes
        constraints = read_cons(ncons, 0)
        nvt = c.u32()
        validatetrans = read_cons(nvt, 1)
        du = c.u32(); dr = c.u32(); drange = c.u32(); dtype = c.u32()
        classes[val] = {'name': name, 'perms': perms, 'common': comkey,
                        'constraints': constraints,
                        'validatetrans': validatetrans,
                        'defaults': (du, dr, drange, dtype)}

    def role_read():
        ln = c.u32(); val = c.u32(); bounds = c.u32()
        name = c.strn(ln)
        dominates = c.ebitmap()
        types_e = c.ebitmap()
        if name != 'object_r':
            roles[val] = {'name': name, 'bounds': bounds,
                          'dominates': dominates, 'types': types_e}

    def type_read():
        ln = c.u32(); val = c.u32(); properties = c.u32(); bounds = c.u32()
        name = c.strn(ln)
        d = {'name': name, 'properties': properties, 'bounds': bounds,
             'value': val}
        types[val] = d
        type_by_name[name] = d

    def role_trans_read():
        nel = c.u32()
        out = []
        for _ in range(nel):
            r = c.u32(); t = c.u32(); nr = c.u32(); tclass = c.u32()
            out.append((r, t, nr, tclass))
        return out

    def role_allow_read():
        nel = c.u32()
        out = []
        for _ in range(nel):
            out.append((c.u32(), c.u32()))
        return out

    def filename_trans_read_compat():
        nel = c.u32()
        out = []
        for _ in range(nel):
            ln = c.u32(); name = c.strn(ln)
            stype = c.u32(); ttype = c.u32(); tclass = c.u32(); otype = c.u32()
            out.append((stype, ttype, tclass, name, otype))
        return out

    def user_read():
        ln = c.u32(); val = c.u32(); bounds = c.u32()
        name = c.strn(ln)
        roles_e = c.ebitmap()
        # mls_read_range_helper + mls_read_level
        rng = mls_range()
        lvl_sens = c.u32(); lvl_cat = c.ebitmap()
        users[val] = {'name': name, 'bounds': bounds, 'roles': roles_e,
                      'range': rng, 'dfltlevel': (lvl_sens, lvl_cat)}

    def mls_range():
        items = c.u32()
        sens = [c.u32() for _ in range(items)]
        cat0 = c.ebitmap()
        cat1 = c.ebitmap() if items > 1 else set(cat0)
        return (sens, cat0, cat1)

    def cond_read_bool():
        val = c.u32(); state = c.u32(); ln = c.u32()
        name = c.strn(ln)
        bools[val] = {'name': name, 'state': state}

    def sens_read():
        ln = c.u32(); isalias = c.u32()
        name = c.strn(ln)
        lvl_sens = c.u32(); lvl_cat = c.ebitmap()
        sens[lvl_sens] = {'name': name, 'isalias': isalias, 'cat': lvl_cat}

    def cat_read():
        ln = c.u32(); val = c.u32(); isalias = c.u32()
        name = c.strn(ln)
        cats[val] = {'name': name, 'isalias': isalias}

    readers = [common_read, class_read2, role_read, type_read, user_read,
               cond_read_bool, sens_read, cat_read]

    p.symtab_offsets = {}
    for i in range(p.sym_num):
        nprim = c.u32(); nel = c.u32()
        p.symtab_offsets[SYM_NAMES[i]] = (nprim, nel, c.o)
        if 'POLDDBG' in __import__('os').environ:
            print(f'symtab[{i}] {SYM_NAMES[i]} nprim={nprim} nel={nel} '
                  f'start={c.o:#x}')
        for _ in range(nel):
            readers[i]()
        if 'POLDDBG' in __import__('os').environ:
            print(f'   end={c.o:#x}')

    # --- avtab ---
    def avtab_read_item(cond=False):
        o_key = c.o
        src = U16(c.f, c.o); tgt = U16(c.f, c.o + 2)
        cls = U16(c.f, c.o + 4); spec = U16(c.f, c.o + 6)
        c.o += 8
        entry = {'src': src, 'tgt': tgt, 'cls': cls, 'spec_raw': spec,
                 'spec': spec & ~AVTAB_ENABLED,
                 'enabled_flag': bool(spec & AVTAB_ENABLED),
                 'xperms': None, 'data': None, 'cond': cond,
                 'key_off': o_key}
        if spec & AVTAB_OP:
            # AOSP-M avtab_operations: u8 type + u32 perms[8]  (33 bytes)
            op_type = c.u8()
            perms = [U32(c.f, c.o + 4 * k) for k in range(8)]
            c.o += 32
            entry['xperms'] = (op_type, perms)
        else:
            entry['data'] = c.u32()
        return entry

    p.avtab_off = c.o
    nel = c.u32()
    p.avtab = []
    spec_hist = {}
    for _ in range(nel):
        e = avtab_read_item()
        spec_hist[e['spec_raw']] = spec_hist.get(e['spec_raw'], 0) + 1
        p.avtab.append(e)
    p.avtab_spec_hist = spec_hist

    # --- conditionals ---
    def cond_read_av_list(cond=True):
        ln = c.u32()
        return [avtab_read_item(cond) for _ in range(ln)]

    def cond_read_node():
        cur_state = c.u32()
        elen = c.u32()
        expr = [(c.u32(), c.u32()) for _ in range(elen)]
        true_l = cond_read_av_list()
        false_l = cond_read_av_list()
        return {'cur_state': cur_state, 'expr': expr,
                'true': true_l, 'false': false_l}

    ncond = c.u32()
    p.cond_list = [cond_read_node() for _ in range(ncond)]

    p.role_trans = role_trans_read()
    p.role_allow = role_allow_read()
    p.filename_trans = filename_trans_read_compat()

    # --- ocontexts ---
    def context():
        user = c.u32(); role = c.u32(); typ = c.u32()
        rng = mls_range() if p.mls else None
        return (user, role, typ, rng)

    def ocon_isid():
        nel = c.u32()
        return [(c.u32(), context()) for _ in range(nel)]

    def ocon_name2ctx():
        nel = c.u32()
        out = []
        for _ in range(nel):
            ln = c.u32(); name = c.strn(ln)
            out.append((name, context(), context()))
        return out

    def ocon_port():
        nel = c.u32()
        return [((c.u32(), c.u32(), c.u32()), context()) for _ in range(nel)]

    def ocon_netif():
        return ocon_name2ctx()

    def ocon_node():
        nel = c.u32()
        out = []
        for _ in range(nel):
            addr = U32(c.f, c.o); mask = U32(c.f, c.o + 4)
            c.o += 8
            out.append(((addr, mask), context()))
        return out

    def ocon_fsuse():
        nel = c.u32()
        out = []
        for _ in range(nel):
            beh = c.u32(); ln = c.u32(); name = c.strn(ln)
            out.append((beh, name, context()))
        return out

    def ocon_node6():
        nel = c.u32()
        out = []
        for _ in range(nel):
            addr = U32(c.f, c.o); mask = U32(c.f, c.o + 4)
            c.o += 32
            out.append(((addr, mask), context()))
        return out

    ocons = [ocon_isid, ocon_name2ctx, ocon_port, ocon_netif, ocon_node,
             ocon_fsuse, ocon_node6]
    p.ocontexts = {}
    for i, fn in enumerate(ocons):
        p.ocontexts[i] = fn()

    # --- genfs ---
    nel = c.u32()
    p.genfs = []
    for _ in range(nel):
        ln = c.u32(); fstype = c.strn(ln)
        nel2 = c.u32()
        entries = []
        for _ in range(nel2):
            ln = c.u32(); path = c.strn(ln)
            sclass = c.u32()
            entries.append((path, sclass, context()))
        p.genfs.append((fstype, entries))

    # --- range_trans ---
    nel = c.u32()
    p.range_trans = []
    for _ in range(nel):
        st = c.u32(); tt = c.u32(); tc = c.u32()
        p.range_trans.append((st, tt, tc, mls_range()))

    # --- type_attr_map ---
    nprim = p.symtab_offsets['types'][0]
    p.type_attr_map = {}
    for i in range(nprim):
        p.type_attr_map[i + 1] = {b + 1 for b in c.ebitmap()}

    p.end_offset = c.o
    p.file_len = len(data)

    # convenience
    p.commons = commons
    p.classes = classes
    p.roles = roles
    p.types = types
    p.type_by_name = type_by_name
    p.users = users
    p.bools = bools
    p.sens = sens
    p.cats = cats

    # class perm name lookup (merge common + own perms by bit value)
    p.class_perms = {}
    for val, cl in classes.items():
        merged = dict(cl['perms'])
        if cl['common'] is not None:
            for cv, cd in commons.items():
                if cd['name'] == cl['common']:
                    for pv, pn in cd['perms'].items():
                        merged.setdefault(pv, pn)
        p.class_perms[val] = merged

    # attribute expansion.  type_attr_map[t] = {t's attributes incl. itself};
    # members of an attribute are the transpose.
    p.attr_members = {}
    p.type_attrs = {}
    for tval, members in p.type_attr_map.items():
        attrs = {m for m in members
                 if m != tval and (types.get(m, {}).get('properties', 0) & 0x0002)}
        p.type_attrs[tval] = attrs
        for a in attrs:
            p.attr_members.setdefault(a, set()).add(tval)
    return p


# ---------- query helpers ----------

def tname(p, v):
    return p.types.get(v, {}).get('name', f'<type{v}>')


def cname(p, v):
    return p.classes.get(v, {}).get('name', f'<class{v}>')


def expand(p, name_or_val):
    """Resolve a type/attribute name or value to the set of concrete type
    values it covers (attributes expand to members; types to themselves)."""
    if isinstance(name_or_val, int):
        v = name_or_val
    else:
        d = p.type_by_name.get(name_or_val)
        if d is None:
            return set()
        v = d['value']
    if p.types.get(v, {}).get('properties', 0) & 0x0002:
        return set(p.attr_members.get(v, set()))
    return {v}


def perm_name(p, cls_val, bit):
    return p.class_perms.get(cls_val, {}).get(bit + 1, f'<perm{bit+1}>')


def perm_bit(p, cls_val, name):
    for pv, pn in p.class_perms.get(cls_val, {}).items():
        if pn == name:
            return pv - 1
    return None


def rule_str(p, e):
    spec = SPEC_NAMES.get(e['spec'], f"spec{e['spec']:#x}")
    s = (f"{spec} {tname(p, e['src'])} {tname(p, e['tgt'])} : "
         f"{cname(p, e['cls'])}")
    if e['xperms'] is not None:
        op_type, perms = e['xperms']
        bits = [i * 32 + b for i, w in enumerate(perms) for b in range(32)
                if w & (1 << b)]
        if e['spec'] & 0x0f00:  # OPNUM: type byte = ioctl magic, bits = _IOC_NR
            s += f" [ioctl magic=0x{op_type:02x} nr={{{' '.join(hex(b) for b in bits)}}}]"
        else:                  # OPTYPE: bits = allowed ioctl magic values
            s += f" [ioctl types={{{' '.join(hex(b) for b in bits)}}}]"
    else:
        if e['spec'] in (AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE):
            s += f" -> {tname(p, e['data'])}"
        else:
            bits = [perm_name(p, e['cls'], b) for b in range(32)
                    if e['data'] is not None and e['data'] & (1 << b)]
            s += f" {{{' '.join(bits)}}}"
    if e.get('cond'):
        s += '  [conditional]'
    return s


def all_rules(p):
    for e in p.avtab:
        yield e
    for node in p.cond_list:
        for e in node['true']:
            yield e
        for e in node['false']:
            yield e


if __name__ == '__main__':
    p = parse(sys.argv[1] if len(sys.argv) > 1
              else DEFAULT_POLICY)
    print(f"version={p.version} mls={p.mls} file={p.file_len} "
          f"parsed_end={p.end_offset} trailing={p.file_len - p.end_offset}")
    print(f"avtab entries: {len(p.avtab)}  cond nodes: {len(p.cond_list)}")
    print(f"types={len(p.types)} classes={len(p.classes)} roles={len(p.roles)}")
    print('spec histogram (raw):')
    for k in sorted(p.avtab_spec_hist):
        print(f"  {k:#06x} {SPEC_NAMES.get(k & ~AVTAB_ENABLED, '?'):24s} "
              f"n={p.avtab_spec_hist[k]} enabled_flag={bool(k & AVTAB_ENABLED)}")
