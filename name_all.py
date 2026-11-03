"""Name all plain-region functions by evidence. Saves work/state.pkl for write_out.py."""
import struct, sys, difflib, collections, pickle
sys.path.insert(0, '.')
from match_plain import *
from loose import sk2

PS = P + 'psx/ghidra/'


def w32(b):
    return struct.unpack('<%dI' % (len(b) // 4), b[:len(b) // 4 * 4])


BASES = {'SLUS': 0x80010000, 'OV00': 0x80093420, 'OV02': 0x80093420}
psx = {}
slusname = {}
for nm in BASES:
    data = open(PS + f'{nm}.BIN', 'rb').read()
    for ln in open(PS + f'funcinfo5_{nm}.tsv'):
        f = ln.split()
        if len(f) >= 5 and f[0] == 'F':
            a = int(f[1], 16)
            sz = int(f[4])
            o = a - BASES[nm]
            if sz >= 8 and 0 <= o < len(data):
                psx[(nm, a)] = (f[2], data[o:o + sz])
for (m, a), (n, b) in psx.items():
    if m == 'SLUS':
        slusname[a] = n
F = {o + BASE: b for o, b in funcs()}
order = sorted(F)
old = [l.rstrip('\n').split('\t') for l in list(open(P + 'doapp/public/names.tsv'))[1:]]
conf = {int(r[0], 16): (r[1], r[2]) for r in old}
pair = {int(r[0], 16): int(r[3].split(':')[1], 16) for r in old}
pmod = {int(r[0], 16): r[3].split(':')[0] for r in old}
loose = {}
for l in open(P + 'doapp/work/loose.tsv'):
    f = l.rstrip('\n').split('\t')
    r = f[4].split(':')
    loose[int(f[0], 16)] = (float(f[2]), float(f[3]), r[0], int(r[1], 16), r[2])


def feats(da, key):
    a = w32(F[da])
    b = w32(psx[key][1])
    sm = difflib.SequenceMatcher(None, sk2(F[da]), sk2(psx[key][1]), autojunk=False)
    idx = [(m.a + k, m.b + k) for m in sm.get_matching_blocks() for k in range(m.size)]
    calls = []
    same = tot = 0
    for i, j in idx:
        x, y = a[i], b[j]
        op = x >> 26
        if op == 3:
            calls.append(((x & 0x3ffffff) << 2 | 0x80000000, (y & 0x3ffffff) << 2 | 0x80000000))
        elif op not in (0, 2, 3, 0xf, 1, 4, 5, 6, 7, 0x12):
            tot += 1
            same += (x & 0xffff) == (y & 0xffff)
    return calls, (same / tot if tot else 1.0), len(idx) / max(len(a), len(b))


def callee_check(calls):
    ok = bad = 0
    for x, y in calls:
        if x in pair:
            if pair[x] == y:
                ok += 1
            else:
                bad += 1
    return ok, bad


def accept(da, thr):
    r, sec, m, pa, pn = loose[da]
    key = (m, pa)
    if key not in psx:
        return None
    calls, imm, cov = feats(da, key)
    ok, bad = callee_check(calls)
    if bad:
        return None
    if (r >= thr[0] and r - sec >= 0.03 and imm >= 0.6) or (r >= thr[1] and r - sec >= 0.05 and imm >= 0.75 and ok >= 1) or (r >= thr[2] and imm >= 0.85 and r - sec >= 0.03):
        return key, 'LOOSE r%.2f imm%.2f cov%.2f callees%d/%d' % (r, imm, cov, ok, ok + bad)
    return None


rounds = 0
while True:
    rounds += 1
    add = 0
    for da in order:
        if da in conf or da not in loose:
            continue
        res = accept(da, (0.85, 0.7, 0.8))
        if res:
            key, ev = res
            conf[da] = (psx[key][0], ev)
            pair[da] = key[1]
            pmod[da] = key[0]
            add += 1
    print('loose round', rounds, 'added', add)
    if not add or rounds > 5:
        break
for it in range(5):
    votes = collections.defaultdict(collections.Counter)
    for da, pa in list(pair.items()):
        key = (pmod[da], pa)
        if key not in psx or da not in F:
            continue
        calls, _, _ = feats(da, key)
        for x, y in calls:
            if x in F and x not in conf:
                votes[x][y] += 1
    add = 0
    for x, cnt in votes.items():
        y, v = cnt.most_common(1)[0]
        if len(cnt) > 1 and cnt.most_common(2)[1][1] == v:
            continue
        cands = [k for k in psx if k[1] == y and k[0] in ('OV00', 'OV02')]
        if not cands:
            continue
        key = cands[0]
        r = difflib.SequenceMatcher(None, sk2(F[x]), sk2(psx[key][1]), autojunk=False).ratio()
        if r >= 0.55 and abs(len(F[x]) - len(psx[key][1])) <= 0.35 * len(F[x]):
            calls, imm, cov = feats(x, key)
            ok, bad = callee_check(calls)
            if bad:
                continue
            conf[x] = (psx[key][0], 'CALLVOTE%d r%.2f imm%.2f' % (v, r, imm))
            pair[x] = y
            pmod[x] = key[0]
            add += 1
    print('vote', it, add)
    if not add:
        break
print('named by PSX evidence', len(conf), 'of', len(F))


def stats(b):
    ws = w32(b)
    n = len(ws)
    jal = [(w & 0x3ffffff) << 2 | 0x80000000 for w in ws if w >> 26 == 3]
    back = 0
    for w in ws:
        if w >> 26 in (4, 5, 6, 7, 1):
            off = w & 0xffff
            off -= 0x10000 if off & 0x8000 else 0
            if off < 0:
                back += 1
    return dict(n=n, jal=jal,
                cop2=sum(1 for w in ws if w >> 26 == 0x12),
                md=sum(1 for w in ws if w >> 26 == 0 and (w & 0x3f) in (0x18, 0x19, 0x1a, 0x1b)),
                ld=sum(1 for w in ws if w >> 26 in (0x20, 0x21, 0x23, 0x24, 0x25)),
                st=sum(1 for w in ws if w >> 26 in (0x28, 0x29, 0x2b)),
                jr=sum(1 for w in ws if w >> 26 == 0 and (w & 0x3f) == 8 and (w >> 21 & 31) != 31),
                back=back,
                hw=sum(1 for w in ws if w >> 26 == 0xf and (w & 0xffff) in (0x1f80, 0x1f00, 0xbf80)))


ST = {a: stats(b) for a, b in F.items()}
CM = collections.defaultdict(list)
for a in F:
    for t in set(ST[a]['jal']):
        if t in F:
            CM[t].append(a)
final = {}
idx = {a: i for i, a in enumerate(order)}


def cur(a):
    if a in conf:
        return conf[a][0]
    if a in final:
        return final[a][0]
    return None


def prefix(n):
    return n.split('_')[0]


def ctx(a):
    c = collections.Counter(prefix(cur(cl)) for cl in CM.get(a, []) if cur(cl))
    callersctx = c.most_common(1)[0][0] if c and c.most_common(1)[0][1] * 2 >= len(CM[a]) else None
    i = idx[a]
    prevn = nxtn = None
    for j in range(i - 1, max(i - 6, -1), -1):
        if cur(order[j]) and order[j] in conf:
            prevn = cur(order[j])
            break
    for j in range(i + 1, min(i + 6, len(order))):
        if cur(order[j]) and order[j] in conf:
            nxtn = cur(order[j])
            break
    sand = prefix(prevn) if prevn and nxtn and prefix(prevn) == prefix(nxtn) else None
    cal = collections.Counter(prefix(cur(t)) for t in ST[a]['jal'] if t in F and cur(t))
    calctx = cal.most_common(1)[0][0] if cal else None
    return callersctx, sand, calctx, prevn, nxtn


def role(s):
    n = s['n']
    if s['cop2']:
        return 'gte'
    if s['jr']:
        return 'dispatch'
    if s['hw']:
        return 'gpuio'
    if s['back'] and s['st'] and not s['ld'] and not s['jal']:
        return 'fill'
    if s['back'] and s['st'] and s['ld'] and not s['jal']:
        return 'copy'
    if s['md'] and not s['jal']:
        return 'calc'
    if s['jal'] and n <= 14:
        return 'thunk'
    if not s['jal'] and n <= 8 and s['ld'] and not s['st']:
        return 'get'
    if not s['jal'] and n <= 10 and s['st'] and not s['ld']:
        return 'set'
    if len(s['jal']) >= 8:
        return 'run'
    if s['back'] and s['jal']:
        return 'loop'
    if not s['jal'] and s['ld'] and s['st']:
        return 'step'
    if not s['jal']:
        return 'leaf'
    return 'proc'


def dname(a):
    s = ST[a]
    r = role(s)
    c, sd, cc, pv, nx = ctx(a)
    near = None
    if not (c or sd or cc):
        i = idx[a]
        for d in range(1, 40):
            for j in (i - d, i + d):
                if 0 <= j < len(order) and order[j] in conf:
                    near = prefix(conf[order[j]][0])
                    break
            if near:
                break
    pre = c or sd or cc or near or 'ovl'
    src = 'callers' if c else 'sandwich' if sd else 'callees' if cc else 'nearest-named' if near else 'none'
    ev = 'body %d ins, %d calls, %d ld/%d st, %d back-branches%s%s; ctx %s from %s; neighbours %s | %s' % (
        s['n'], len(s['jal']), s['ld'], s['st'], s['back'], ', cop2 %d' % s['cop2'] if s['cop2'] else '',
        ', mul/div %d' % s['md'] if s['md'] else '', pre, src, pv or '-', nx or '-')
    return '%s_%s_%05x' % (pre, r, a & 0xfffff), ev, src


rest = [a for a in order if a not in conf]
for a in rest:
    final[a] = dname(a)
for rd in range(2, 6):
    ch = 0
    for a in rest:
        x = dname(a)
        if x[0] != final[a][0]:
            ch += 1
        final[a] = x
    print('review round', rd, 'renamed', ch)
    if not ch:
        break
print(collections.Counter(final[a][2] for a in rest))
pickle.dump((conf, pair, pmod, final), open(P + 'doapp/work/state.pkl', 'wb'))
