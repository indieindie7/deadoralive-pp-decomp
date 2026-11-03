"""Collapse globals into objects; map PSX names. Output work/gobjs.json. Needs user's own images."""
import struct,re,collections,difflib,json,bisect,sys
sys.path.insert(0,'C:/Users/john/Documents/DeadOrAlive/doapp/tools')
from loose import sk2
P='C:/Users/john/Documents/DeadOrAlive/'
D=open(P+'doapp/work/doapp_full.bin','rb').read();B=0x80010000
hdr=re.findall(r'^// ==== (\S+) @ ([0-9a-f]+) size=(\d+)',open(P+'doapp/work/dump_named3.c').read(),re.M)
F={int(a,16):(n,int(s)) for n,a,s in hdr}
fs=sorted(F)
def fb(a): o=a-B;return D[o:o+F[a][1]]
BASES={'SLUS':0x80010000,'OV00':0x80093420,'OV02':0x80093420}
pb={}
for nm,base in BASES.items():
    d=open(P+f'psx/ghidra/{nm}.BIN','rb').read()
    for ln in open(P+f'psx/ghidra/funcinfo5_{nm}.tsv'):
        f=ln.split()
        if len(f)>=5 and f[0]=='F':
            a=int(f[1],16);sz=int(f[4]);o=a-base
            if sz>=8 and 0<=o<len(d): pb[(nm,a)]=d[o:o+sz]
G={}
for nm in ('SLUS','OV00','OV02'):
    for l in open(P+f'psx/ghidra/globals_{nm}.txt'):
        f=l.split(None,1)
        if len(f)==2:
            try:G.setdefault(int(f[0],16),f[1].strip())
            except:pass
def real(n): return not re.match(r'^(g|var|tbl|psx|DAT|PTR)_[0-9a-fA-F]{8}$',n) and not re.match(r'^(g|var|tbl)_[a-z]+_[0-9a-f]{8}$',n)
def w32(b): return struct.unpack('<%dI'%(len(b)//4),b[:len(b)//4*4])
def addrs(ws):
    hi={};out={}
    for k,w in enumerate(ws):
        op=w>>26;rs=w>>21&31;rt=w>>16&31
        if op==0xf: hi[rt]=(w&0xffff)<<16
        elif op in(9,0x20,0x21,0x23,0x24,0x25,0x28,0x29,0x2b,0xd) and rs in hi:
            imm=w&0xffff
            if op!=0xd and imm&0x8000: imm-=0x10000
            out[k]=((hi[rs]+imm)&0xffffffff,op)
    return out
WID={0x20:1,0x24:1,0x28:1,0x21:2,0x25:2,0x29:2,0x23:4,0x2b:4,9:4,0xd:4}
gv=collections.defaultdict(collections.Counter)
n=0
for l in open(P+'doapp/public/names.tsv'):
    p=l.rstrip('\n').split('\t')
    if len(p)<4 or not p[3] or p[0]=='addr' or ':' not in p[3]: continue
    da=int(p[0],16);m,pa=p[3].split(':');pa=int(pa,16)
    if da not in F or (m,pa) not in pb: continue
    a=w32(fb(da));b=w32(pb[(m,pa)])
    sm=difflib.SequenceMatcher(None,sk2(fb(da)),sk2(pb[(m,pa)]),autojunk=False)
    A=addrs(a);Bx=addrs(b)
    for blk in sm.get_matching_blocks():
        for k in range(blk.size):
            i,j=blk.a+k,blk.b+k
            if i in A and j in Bx and 0x80000000<=A[i][0]<0x80200000 and 0x80000000<=Bx[j][0]<0x80200000:
                gv[A[i][0]][Bx[j][0]]+=1
    n+=1
print('pairs',n)
use=collections.defaultdict(list)
for da in fs:
    ws=w32(fb(da))
    for k,(ad,op) in addrs(ws).items():
        if 0x80090000<=ad<0x80200000:
            use[ad].append((F[da][0],'W' if op in(0x28,0x29,0x2b) else 'R' if op in(0x20,0x21,0x23,0x24,0x25) else 'A',WID.get(op,4)))
rows={}
for l in open(P+'doapp/public/globals.tsv'):
    p=l.rstrip('\n').split('\t')
    if p[0]!='addr': rows[int(p[0],16)]=p
# psx object starts (named, sorted)
gs=sorted(a for a in G if real(G[a]))
objs=[];cur=None
for a in sorted(rows):
    w=max((x[2] for x in use.get(a,[])),default=1)
    py=gv[a].most_common(1)[0][0] if a in gv else None
    pn=G.get(py) if py and real(G.get(py,'')) else None
    # psx object start containing py
    pstart=None
    if py:
        i=bisect.bisect_right(gs,py)-1
        if i>=0 and py-gs[i]<0x400: pstart=gs[i]
    new=cur is None or a>cur['end']+3 or (pstart is not None and cur['pstart'] is not None and pstart!=cur['pstart']) or (w==4 and a%4)==0 and False
    if not new and pstart is None and cur['pstart'] is not None and a>=cur['end']+1 and False: new=True
    if new:
        cur={'start':a,'end':a+w,'pstart':pstart,'pname':G.get(pstart) if pstart is not None and real(G.get(pstart,'')) else None,'members':[],'widths':set()}
        objs.append(cur)
    cur['end']=max(cur['end'],a+w);cur['members'].append(a);cur['widths'].add(w)
    if cur['pname'] is None and pstart is not None and real(G.get(pstart,'')): cur['pname']=G[pstart];cur['pstart']=pstart
out=[]
for o in objs:
    refs=collections.defaultdict(set)
    for m in o['members']:
        for fn,k,_ in use.get(m,[]): refs[fn].add(k)
    cls=[rows[m][1] for m in o['members']]
    out.append({'start':'%08x'%o['start'],'size':o['end']-o['start'],'n':len(o['members']),'widths':sorted(o['widths']),'psx':o['pname'],'psxaddr':'%08x'%o['pstart'] if o['pstart'] else None,'dead':all(c=='DEAD' for c in cls),'refs':{f:''.join(sorted(k)) for f,k in sorted(refs.items(),key=lambda x:-len(x[1]))[:8]},'nref':len(refs)})
json.dump(out,open(P+'doapp/work/gobjs.json','w'),indent=0)
print(len(rows),'rows ->',len(out),'objects; psx-named',sum(1 for o in out if o['psx']),'dead',sum(o['dead'] for o in out))
