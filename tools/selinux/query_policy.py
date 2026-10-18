#!/usr/bin/env python3
"""query_policy.py -- query CLI over parse_policy.py for the bundled ASUS compiled policy.
Devbox tool. READ-ONLY analysis support.

Usage: python3 query_policy.py <cmd> [args]
  types [filter]              list types/attributes
  attrs <name>                expand attribute -> members
  rules [--src S] [--tgt T] [--class C] [--perm P] [--spec NAME] [--flat]
  who   --tgt T --class C --perm P    sources that hold perm on target
  domain <name>               full allow power-set of a domain (attributes expanded at source side only)
  props <domain>              property_service set targets for domain
  trans [--from S] [--to T]   type_transition rules (avtab + filename_trans)
  dyntrans <target>           process dyntransition sources into target
  execs <file-type>           who can execute/transition/entrypoint a *_exec type
  fileaccess <label>          who can read/write/open a file label
"""
import argparse
import sys, re
import parse_policy
from parse_policy import (parse, expand, tname, cname, perm_name, rule_str, all_rules,
                   AVTAB_ALLOWED, AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE,
                   AVTAB_ENABLED)

P = None

def load():
    global P
    if P is None:
        P = parse(parse_policy.DEFAULT_POLICY)
    return P


def match_name(p, v, pat):
    return re.search(pat, tname(p, v)) is not None


def cmd_types(filt=None):
    p = load()
    for v in sorted(p.types):
        n = tname(p, v)
        if filt and not re.search(filt, n):
            continue
        is_attr = p.types[v]['properties'] & 0x0002
        print(f"{v:4d} {'A' if is_attr else ' '} {n}")


def cmd_attrs(name):
    p = load()
    for v in expand(p, name):
        print(tname(p, v))


def _resolve(p, pat):
    """pattern = name or /regex/ -> set of type values (attrs expand)"""
    if pat is None:
        return None
    if pat.startswith('/') and pat.endswith('/'):
        vals = {d['value'] for d in p.types.values()
                if re.search(pat[1:-1], d['name'])}
        out = set()
        for v in vals:
            out |= expand(p, v)
        return out
    if pat not in p.type_by_name:
        raise ValueError(f"unknown type or attribute: {pat}")
    return expand(p, pat)


def cmd_rules(src=None, tgt=None, cls=None, perm=None, spec=None, flat=False):
    p = load()
    sset = _resolve(p, src)
    tset = _resolve(p, tgt)
    out = []
    for e in all_rules(p):
        if sset is not None:
            if e['src'] in sset:
                pass
            elif not flat and (set(p.attr_members.get(e['src'], set())) & sset):
                pass
            else:
                continue
        if tset is not None:
            if e['tgt'] in tset:
                pass
            elif not flat and (set(p.attr_members.get(e['tgt'], set())) & tset):
                pass
            else:
                continue
        if cls and cname(p, e['cls']) != cls:
            continue
        if spec:
            want = {value for value, label in parse_policy.SPEC_NAMES.items()
                    if re.search(spec, label)}
            if (e['spec'] & ~AVTAB_ENABLED) not in want:
                continue
        if perm:
            names = {perm_name(p, e['cls'], b) for b in range(32)
                     if e['data'] is not None and e['data'] & (1 << b)}
            want = set(perm.split(','))
            if not (names & want):
                continue
        out.append(e)
    for e in out:
        print(rule_str(p, e))
    print(f'-- {len(out)} rules', file=sys.stderr)


def cmd_who(tgt, cls, perm):
    p = load()
    tset = _resolve(p, tgt)
    srcs = {}
    for e in all_rules(p):
        if (e['spec'] & ~AVTAB_ENABLED) != AVTAB_ALLOWED:
            continue
        if cname(p, e['cls']) != cls:
            continue
        names = {perm_name(p, e['cls'], b) for b in range(32)
                 if e['data'] is not None and e['data'] & (1 << b)}
        if not (names & set(perm.split(','))):
            continue
        hit = e['tgt'] in tset or bool(p.attr_members.get(e['tgt'], set()) & tset)
        if not hit:
            continue
        srcs.setdefault(e['src'], set()).update(names & set(perm.split(',')))
    for s in sorted(srcs, key=lambda v: tname(p, v)):
        print(f"{tname(p, s):40s} {' '.join(sorted(srcs[s]))}")


def cmd_domain(name):
    p = load()
    sset = expand(p, name)
    if not sset:
        print('unknown domain', name); return
    groups = {}
    for e in all_rules(p):
        if e['src'] not in sset and not (set(p.attr_members.get(e['src'], set())) & sset):
            continue
        spec = parse_policy.SPEC_NAMES.get(e['spec'], hex(e['spec']))
        key = (spec, cname(p, e['cls']))
        groups.setdefault(key, {}).setdefault(tname(p, e['tgt']), set())
        tg = groups[key][tname(p, e['tgt'])]
        if e['xperms'] is not None:
            tg.add(rule_str(p, e).split(' [', 1)[1])
        elif e['spec'] in (AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE):
            tg.add('-> ' + tname(p, e['data']))
        elif e['data'] is not None:
            for b in range(32):
                if e['data'] & (1 << b):
                    tg.add(perm_name(p, e['cls'], b))
    for (spec, cls) in sorted(groups):
        print(f"\n== {spec} {cls}")
        for tgt in sorted(groups[(spec, cls)]):
            perms = groups[(spec, cls)][tgt]
            print(f"   {tgt:42s} {' '.join(sorted(perms))}")


def cmd_props(domain):
    p = load()
    sset = expand(p, domain)
    for e in all_rules(p):
        if e['src'] in sset and cname(p, e['cls']) == 'property_service':
            for b in range(32):
                if e['data'] is not None and e['data'] & (1 << b):
                    print(f"{parse_policy.SPEC_NAMES.get(e['spec'], e['spec']):10s} {tname(p, e['tgt']):24s} {perm_name(p, e['cls'], b)}")


def cmd_trans(frm=None, to=None):
    p = load()
    for e in all_rules(p):
        if e['spec'] not in (AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE):
            continue
        if frm and not (e['src'] in _resolve(p, frm) or tname(p, e['src']) == frm):
            continue
        if to and not (e['tgt'] in _resolve(p, to) or tname(p, e['tgt']) == to):
            continue
        print(rule_str(p, e))
    print('-- filename transitions:', file=sys.stderr)
    for (stype, ttype, tclass, fname, otype) in p.filename_trans:
        if frm and tname(p, stype) != frm and stype not in (expand(p, frm) or set()):
            continue
        if to and tname(p, otype) != to:
            continue
        print(f"type_transition {tname(p, stype)} {tname(p, ttype)}:{cname(p, tclass)} \"{fname}\" -> {tname(p, otype)}")


def cmd_dyntrans(target):
    p = load()
    tset = expand(p, target)
    pc = p.class_perms  # for process class
    for e in all_rules(p):
        if cname(p, e['cls']) != 'process' or e['data'] is None:
            continue
        dyn = False
        for b in range(32):
            if e['data'] & (1 << b) and perm_name(p, e['cls'], b) == 'dyntransition':
                dyn = True
        if dyn and (e['tgt'] in tset):
            print(f"dyntransition {tname(p, e['src'])} -> {tname(p, e['tgt'])}")
        if dyn and e['tgt'] not in tset and any(v in tset for v in expand(p, tname(p, e['tgt']))):
            print(f"dyntransition {tname(p, e['src'])} -> {tname(p, e['tgt'])} (attr)")


def cmd_execs(ftype):
    p = load()
    tset = expand(p, ftype)
    for e in all_rules(p):
        if e['tgt'] not in tset:
            continue
        if cname(p, e['cls']) != 'file':
            continue
        names = {perm_name(p, e['cls'], b) for b in range(32)
                 if e['data'] is not None and e['data'] & (1 << b)}
        if names & {'execute', 'entrypoint', 'execute_no_trans', 'read', 'open'}:
            print(f"{rule_str(p, e)}")
    print('-- transitions targeting this exec type:', file=sys.stderr)
    for e in all_rules(p):
        if e['spec'] in (AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE) and e['tgt'] in tset:
            print(rule_str(p, e))
    for (stype, ttype, tclass, fname, otype) in p.filename_trans:
        if ttype in tset or otype in tset:
            print(f"type_transition {tname(p, stype)} {tname(p, ttype)}:{cname(p, tclass)} \"{fname}\" -> {tname(p, otype)}")


def cmd_fileaccess(label):
    p = load()
    tset = expand(p, label)
    srcs = {}
    for e in all_rules(p):
        if e['spec'] != AVTAB_ALLOWED:
            continue
        if e['tgt'] not in tset:
            continue
        if cname(p, e['cls']) not in ('file', 'dir', 'lnk_file', 'chr_file', 'blk_file'):
            continue
        names = {perm_name(p, e['cls'], b) for b in range(32)
                 if e['data'] is not None and e['data'] & (1 << b)}
        srcs.setdefault((tname(p, e['src']), cname(p, e['cls'])), set()).update(names)
    for (s, cls) in sorted(srcs):
        print(f"{s:36s} {cls:10s} {' '.join(sorted(srcs[(s, cls)]))}")


def main():
    parser = argparse.ArgumentParser(description="Query the bundled vendor SELinux policy.")
    commands = parser.add_subparsers(dest='command', required=True)
    types = commands.add_parser('types', help='list types and attributes')
    types.add_argument('filter', nargs='?')
    for name in ('attrs', 'domain', 'props', 'dyntrans', 'execs', 'fileaccess'):
        command = commands.add_parser(name)
        command.add_argument('name')
    rules = commands.add_parser('rules', help='filter policy rows')
    for name in ('src', 'tgt', 'class', 'perm', 'spec'):
        rules.add_argument('--' + name, dest='cls' if name == 'class' else name)
    rules.add_argument('--flat', action='store_true')
    who = commands.add_parser('who', help='find matching allow-rule sources')
    who.add_argument('--tgt', required=True)
    who.add_argument('--class', dest='cls', required=True)
    who.add_argument('--perm', required=True)
    transitions = commands.add_parser('trans')
    transitions.add_argument('--from', dest='frm')
    transitions.add_argument('--to')
    args = parser.parse_args()
    try:
        if args.command == 'types':
            cmd_types(args.filter)
        elif args.command == 'rules':
            cmd_rules(args.src, args.tgt, args.cls, args.perm, args.spec, args.flat)
        elif args.command == 'who':
            cmd_who(args.tgt, args.cls, args.perm)
        elif args.command == 'trans':
            cmd_trans(args.frm, args.to)
        else:
            globals()['cmd_' + args.command](args.name)
    except (ValueError, re.error) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
