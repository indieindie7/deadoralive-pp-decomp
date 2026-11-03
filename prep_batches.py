"""Split work/dump.c into batches of structural-named functions with names substituted. Writes work/batch_N.txt + work/todo.tsv"""
import pickle, re, struct, difflib, collections, sys
sys.path.insert(0, '.')
from match_plain import *
from loose import sk2
conf, pair, pmod, final = pickle.load(open(P + 'doapp/work/state.pkl', 'rb'))
PS = P + 'psx/ghidra/'
BASES = {'SLUS': 0x80010000, 'OV00': 0x80093420, 'OV02': 0x80093420}
F = {o + BASE: b for o, b in funcs()}
order = sorted(F)
pb = {}
slusname = {}
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
                if nm == 'SLUS':
                    slusname[a] = f[2]


def w32(b):
    return struct.unpack('<%dI' % (len(b) // 4), b[:len(b) // 4 * 4])


exe = collections.defaultdict(collections.Counter)
for da, pa in pair.items():
    key = (pmod[da], pa)
    if key not in pb or da not in F:
        continue
    a = w32(F[da])
    b = w32(pb[key])
    sm = difflib.SequenceMatcher(None, sk2(F[da]), sk2(pb[key]), autojunk=False)
    for m in sm.get_matching_blocks():
        for k in range(m.size):
            x, y = a[m.a + k], b[m.b + k]
            if x >> 26 == 3 and y >> 26 == 3:
                tx = (x & 0x3ffffff) << 2 | 0x80000000
                ty = (y & 0x3ffffff) << 2 | 0x80000000
                if tx < 0x80097e18 and ty in slusname:
                    exe[tx][slusname[ty]] += 1
exename = {t: 'exe_' + c.most_common(1)[0][0] for t, c in exe.items()}
print('exe call targets mapped', len(exename))
name = {}
for a in order:
    name[a] = conf[a][0] if a in conf else final[a][0]
G = {}
for l in list(open(P + 'doapp/public/globals.tsv'))[1:]:
    f = l.rstrip('\n').split('\t')
    if f[1] == 'PROVEN' and not f[2].startswith(('var_', 'tbl_', 'psx_')):
        G[int(f[0], 16)] = f[2]
txt = open(P + 'doapp/work/dump.c', encoding='utf8', errors='replace').read()
chunks = {}
for m in re.finditer(r'// ==== (\S+) @ ([0-9a-f]{8}) size=\d+\n(.*?)(?=\n// ==== |\Z)', txt, re.S):
    chunks[int(m.group(2), 16)] = m.group(3)
callers = collections.defaultdict(set)
for a, b in F.items():
    for w in w32(b):
        if w >> 26 == 3:
            callers[(w & 0x3ffffff) << 2 | 0x80000000].add(a)


def sub(s):
    def f1(m):
        t = int(m.group(1), 16)
        return name.get(t) or exename.get(t) or 'FUN_%08x' % t
    s = re.sub(r'FUN_([0-9a-f]{8})', f1, s)
    s = re.sub(r'func_0x([0-9a-f]{8})', f1, s)

    def f2(m):
        t = int(m.group(1), 16)
        return G.get(t, m.group(0))
    s = re.sub(r'DAT_([0-9a-f]{8})', f2, s)
    return s


todo = [a for a in order if a not in conf]
with open(P + 'doapp/work/todo.tsv', 'w') as o:
    for a in todo:
        o.write('%08x\t%s\n' % (a, name[a]))
N = 56
for bi in range(0, len(todo), N):
    out = []
    for a in todo[bi:bi + N]:
        cl = sorted(callers.get(a, []))
        hdr = '#### %08x %s  (structural name; callers: %s)' % (a, name[a], ', '.join('%s' % name.get(c, '%08x' % c) for c in cl[:4]) or 'none/indirect')
        body = chunks.get(a, '// not decompiled')
        body = '\n'.join(l for l in sub(body).split('\n') if l.strip() and 'WARNING' not in l)
        lines = body.split('\n')
        if len(lines) > 140:
            lines = lines[:140] + ['// ... truncated %d lines' % (len(lines) - 140)]
        out.append(hdr + '\n' + '\n'.join(lines))
    open(P + 'doapp/work/batch_%d.txt' % (bi // N + 1), 'w').write('\n\n'.join(out))
print(len(todo), (len(todo) + N - 1) // N)
