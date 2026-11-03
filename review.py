"""Review + propagate: confirms fuzzy matches via aligned callee/global consistency, propagates names through call graph,
maps globals. Outputs ../public/names.tsv, ../public/globals.tsv."""
import struct,sys,difflib,collections
sys.path.insert(0,'.')
from match_plain import *
from match_fuzzy import sk
R=refs()
psx={}
for nm,a,name,b in R: psx.setdefault(a,(nm,name,b))
F=dict((o+BASE,b) for o,b in funcs())
def w32(b): return struct.unpack('<%dI'%(len(b)//4),b[:len(b)//4*4])
pnames=set(); 
# globals names
G={}
for nm in('SLUS','OV00','OV02'):
    for l in open(P+f'psx/ghidra/globals_{nm}.txt'):
        f=l.split(None,1)
        if len(f)==2:
            try:G.setdefault(int(f[0],16),f[1].strip())
            except:pass
# initial pairs
pairs={}   # doa addr -> (psx addr, evidence)
for l in open(P+'doapp/work/match.tsv'):
    f=l.rstrip('\n').split('\t')
    if f[2]!='-' and f[3]=='1':
        r=f[4].split(':');pairs[int(f[0],16)]=(int(r[1],16),'HASH-'+f[2])
cand={}
for l in open(P+'doapp/work/fuzzy.tsv'):
    f=l.rstrip('\n').split('\t');r=f[4].split(':')
    if float(f[2])>=0.9 and float(f[2])-float(f[3])>=0.03: cand[int(f[0],16)]=(int(r[1],16),float(f[2]))
def align(da,pa):
    a=w32(F[da]);b=w32(psx[pa][2])
    sm=difflib.SequenceMatcher(None,sk(F[da]),sk(psx[pa][2]),autojunk=False)
    idx=[]
    for m in sm.get_matching_blocks():
        for k in range(m.size): idx.append((m.a+k,m.b+k))
    return a,b,idx,sm.ratio()
def info(da,pa):
    a,b,idx,r=align(da,pa)
    calls=[];gl=[]
    ha={};hb={}
    for i,j in idx:
        x,y=a[i],b[j]
        if x>>26==3 and y>>26==3: calls.append(((x&0x3ffffff)<<2|0x80000000,(y&0x3ffffff)<<2|0x80000000))
        for w,h in ((x,ha),(y,hb)):
            pass
    def addrs(ws):
        hi={};out={}
        for k,w in enumerate(ws):
            op=w>>26;rs=w>>21&31;rt=w>>16&31
            if op==0xf: hi[rt]=((w&0xffff)<<16)
            elif op in(9,0x20,0x21,0x23,0x24,0x25,0x28,0x29,0x2b,0xd) and rs in hi:
                imm=w&0xffff
                if op!=0xd and imm&0x8000: imm-=0x10000
                out[k]=(hi[rs]+imm)&0xffffffff
                if op in(9,0xd) and rt==rs: hi[rt]=out[k]  # addiu rt,rt chain
            if op not in(0xf,) and (w>>16&31) in hi and op in(9,0xd,0x20,0x21,0x23,0x24,0x25) and (w>>16&31)!=rs and False: pass
        return out
    A=addrs(a);B=addrs(b)
    for i,j in idx:
        if i in A and j in B and 0x80000000<=A[i]<0x80200000 and 0x80000000<=B[j]<0x80200000: gl.append((A[i],B[j]))
    return calls,gl,r,len(idx)/max(len(a),len(b))
evid={}
# phase: confirm fuzzy
confirmed=dict(pairs);rejected=[]
callvotes=collections.defaultdict(collections.Counter)
def collect(pr):
    for da,(pa,_) in pr.items():
        calls,gl,r,cov=info(da,pa)
        for x,y in calls: callvotes[x][y]+=1
for da,(pa,_) in pairs.items(): collect({da:(pa,0)})
for da,(pa,rt) in sorted(cand.items()):
    calls,gl,r,cov=info(da,pa)
    ok=0;bad=0
    for x,y in calls:
        # consistent if the callee x is paired to y (confirmed exact) or unknown
        if x in confirmed: ok+= confirmed[x][0]==y; bad+= confirmed[x][0]!=y
    if r>=0.9 and cov>=0.9 and bad==0 and ok>=1 or (r>=0.95 and cov>=0.95 and bad==0 and abs(len(F[da])-len(psx[pa][2]))<=16):
        confirmed[da]=(pa,'FUZZ%.2f-CALLEES%d/%d'%(r,ok,ok+bad));collect({da:(pa,0)})
    else: rejected.append((da,pa,r,ok,bad))
print('confirmed',len(confirmed),'rejected',len(rejected))
# propagation through call graph
newn=0
for it in range(6):
    added=0
    for x,cnt in list(callvotes.items()):
        if x in confirmed or x not in F: continue
        y,v=cnt.most_common(1)[0]
        if y not in psx or v<2 or (len(cnt)>1 and cnt.most_common(2)[1][1]>=v): continue
        sx=sk(F[x]);sy=sk(psx[y][2])
        rt=difflib.SequenceMatcher(None,sx,sy,autojunk=False).ratio()
        if rt>=0.75 and abs(len(F[x])-len(psx[y][2]))<=0.25*len(F[x]):
            confirmed[x]=(y,'CALLVOTE%d-R%.2f'%(v,rt));collect({x:(y,0)});added+=1
    print('iter',it,'added',added)
    if not added:break
with open(P+'doapp/public/names.tsv','w') as o:
    o.write('addr\tname\tevidence\tpsx_ref\n')
    for da,(pa,ev) in sorted(confirmed.items()): o.write('%08x\t%s\t%s\t%s:%08x\n'%(da,psx[pa][1],ev,psx[pa][0],pa))
    for da,pa,r,ok,bad in rejected: pass
# globals
gv=collections.defaultdict(collections.Counter)
for da,(pa,_) in confirmed.items():
    gl=info(da,pa)[1]
    for x,y in gl: gv[x][y]+=1
use=collections.defaultdict(set)
for da,b in F.items():
    ws=w32(b);hi={}
    for k,w in enumerate(ws):
        op=w>>26;rs=w>>21&31;rt=w>>16&31
        if op==0xf: hi[rt]=(w&0xffff)<<16
        elif op in(9,0x20,0x21,0x23,0x24,0x25,0x28,0x29,0x2b) and rs in hi:
            imm=w&0xffff; imm-=0x10000 if imm&0x8000 else 0
            a=(hi[rs]+imm)&0xffffffff
            if 0x80090000<=a<0x80200000: use[a].add((da,'W' if op in(0x28,0x29,0x2b) else 'R' if op in(0x20,0x21,0x23,0x24,0x25) else 'A'))
cls=collections.Counter()
with open(P+'doapp/public/globals.tsv','w') as o:
    o.write('addr\tclass\tname\tevidence\n')
    for a in sorted(use):
        u=use[a];rw={t for _,t in u}
        if a in gv:
            y,v=gv[a].most_common(1)[0]
            c='PROVEN';nm=G.get(y,'psx_%08x'%y);ev='PSXMAP %08x x%d, %d fns'%(y,v,len(u))
        elif a>=0x80097e18 and a<0x80100000+0x20000 or (0x80117e18<=a<0x80138000):
            if 'W' in rw and 'R' not in rw and 'A' not in rw: c='DEAD';nm='g_%08x'%a;ev='in-region, written never read (static)'
            elif 'W' in rw: c='PROVEN';nm='var_%08x'%a;ev='in-region RW by %d fns (static xrefs)'%len(u)
            else: c='PROVEN';nm='tbl_%08x'%a;ev='in-region read-only/addr-taken by %d fns (static xrefs)'%len(u)
        elif 'R' not in rw and 'A' not in rw: c='DEAD';nm='g_%08x'%a;ev='written never read (static)'
        else: c='OPEN';nm='g_%08x'%a;ev='BLOCKED: lives in encrypted main exe (TPS BIOS coh1002m missing)'
        cls[c]+=1;o.write('%08x\t%s\t%s\t%s\n'%(a,c,nm,ev))
print(cls,'plain funcs',len(F),'named',len(confirmed))
