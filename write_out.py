"""Write public/names.tsv, hand_doapp.txt (batches of 60 committed by caller), globals.tsv from work/state.pkl."""
import pickle, struct, difflib, collections, sys, subprocess
sys.path.insert(0, '.')
from match_plain import *
from loose import sk2
PS = P + 'psx/ghidra/'
conf, pair, pmod, final = pickle.load(open(P + 'doapp/work/state.pkl', 'rb'))
BASES = {'SLUS': 0x80010000, 'OV00': 0x80093420, 'OV02': 0x80093420}
F = {o + BASE: b for o, b in funcs()}
order = sorted(F)
pb = {}
for nm, base in BASES.items():
    data = open(PS + f'{nm}.BIN', 'rb').read()
    for ln in open(PS + f'funcinfo5_{nm}.tsv'):
        f = ln.split()
        if len(f) >= 5 and f[0] == 'F':
            a = int(f[1], 16)
            sz = int(f[4])
            o = a - base
            if sz >= 8 and 0 <= o < len(data):
                pb[(nm, a)] = data[o:o + sz]
G = {}
for nm in ('SLUS', 'OV00', 'OV02'):
    for l in open(PS + f'globals_{nm}.txt'):
        f = l.split(None, 1)
        if len(f) == 2:
            try:
                G.setdefault(int(f[0], 16), f[1].strip())
            except ValueError:
                pass


def w32(b):
    return struct.unpack('<%dI' % (len(b) // 4), b[:len(b) // 4 * 4])


def addrs(ws):
    hi = {}
    out = {}
    for k, w in enumerate(ws):
        op = w >> 26
        rs = w >> 21 & 31
        rt = w >> 16 & 31
        if op == 0xf:
            hi[rt] = (w & 0xffff) << 16
        elif op in (9, 0x20, 0x21, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2b, 0xd) and rs in hi:
            imm = w & 0xffff
            if op != 0xd and imm & 0x8000:
                imm -= 0x10000
            out[k] = (hi[rs] + imm) & 0xffffffff
    return out


gv = collections.defaultdict(collections.Counter)
for da, pa in pair.items():
    key = (pmod[da], pa)
    if key not in pb or da not in F:
        continue
    a = w32(F[da])
    b = w32(pb[key])
    sm = difflib.SequenceMatcher(None, sk2(F[da]), sk2(pb[key]), autojunk=False)
    A = addrs(a)
    B = addrs(b)
    for m in sm.get_matching_blocks():
        for k in range(m.size):
            i, j = m.a + k, m.b + k
            if i in A and j in B and 0x80000000 <= A[i] < 0x80200000 and 0x80000000 <= B[j] < 0x80200000:
                gv[A[i]][B[j]] += 1
use = collections.defaultdict(set)
for da, b in F.items():
    ws = w32(b)
    for k, ad in addrs(ws).items():
        op = ws[k] >> 26
        if 0x80090000 <= ad < 0x80200000:
            use[ad].add((da, 'W' if op in (0x28, 0x29, 0x2b) else 'R' if op in (0x20, 0x21, 0x23, 0x24, 0x25) else 'A'))
cls = collections.Counter()
with open(P + 'doapp/public/globals.tsv', 'w') as o:
    o.write('addr\tclass\tname\tevidence\n')
    for a in sorted(use):
        u = use[a]
        rw = {t for _, t in u}
        if a in gv:
            y, v = gv[a].most_common(1)[0]
            c, nm, ev = 'PROVEN', G.get(y, 'psx_%08x' % y), 'PSXMAP %08x x%d, %d fns' % (y, v, len(u))
        elif 0x80097e18 <= a < 0x80120000 or 0x80117e18 <= a < 0x80138000:
            if 'W' in rw and 'R' not in rw and 'A' not in rw:
                c, nm, ev = 'DEAD', 'g_%08x' % a, 'in-region, written never read (static)'
            elif 'W' in rw:
                c, nm, ev = 'PROVEN', 'var_%08x' % a, 'in-region RW by %d fns (static xrefs)' % len(u)
            else:
                c, nm, ev = 'PROVEN', 'tbl_%08x' % a, 'in-region read-only/addr-taken by %d fns (static xrefs)' % len(u)
        elif 'R' not in rw and 'A' not in rw:
            c, nm, ev = 'DEAD', 'g_%08x' % a, 'written never read (static)'
        else:
            c, nm, ev = 'OPEN', 'g_%08x' % a, 'BLOCKED: lives in encrypted main exe (TPS BIOS coh1002m missing)'
        cls[c] += 1
        o.write('%08x\t%s\t%s\t%s\n' % (a, c, nm, ev))
print(cls)
rows = []
for a in order:
    if a in conf:
        nm, ev = conf[a]
        pm = pmod[a]
        rows.append((a, nm, ev, '%s:%08x' % (pm, pair[a])))
    else:
        nm, ev, src = final[a]
        rows.append((a, nm, 'CODEREAD ' + ev, '-'))
with open(P + 'doapp/public/names.tsv', 'w') as o:
    o.write('addr\tname\tevidence\tpsx_ref\n')
    for r in rows:
        o.write('%08x\t%s\t%s\t%s\n' % r)
un = [r for r in rows if r[3] == '-']
hand = P + 'doapp/public/hand_doapp.txt'
open(hand, 'w').close()
for i in range(0, len(un), 60):
    with open(hand, 'a') as h:
        for r in un[i:i + 60]:
            h.write('0x%08x func %s [review: %s] %s\n' % (r[0], r[1], 'confirm', r[2][9:]))
    subprocess.run(['git', 'add', '-A'], cwd=P + 'doapp', capture_output=True)
    subprocess.run(['git', 'commit', '-qm', 'hand_doapp batch %d (%d/%d code-read names)\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>' % (i // 60 + 1, min(i + 60, len(un)), len(un))], cwd=P + 'doapp', capture_output=True)
print(len(rows), len(un))
