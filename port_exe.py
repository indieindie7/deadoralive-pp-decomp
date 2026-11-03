"""Port PSX names to the decrypted main exe (needs user's own ROM dump, work/doapp_full.bin + work/dump_full.c).
usage: py -3.13 -I port_exe.py  -> work/exe_match.tsv"""
import re,struct,hashlib,collections,sys
sys.path.insert(0,'C:/Users/john/Documents/DeadOrAlive/doapp/tools')
from match_plain import norm,refs,P
img=open(P+'doapp/work/doapp_full.bin','rb').read()
def ours():
    out=[]
    for ln in open(P+'doapp/work/dump_full.c',errors='replace'):
        m=re.match(r'// ==== (\S+) @ ([0-9a-f]+) size=(\d+)',ln)
        if m:
            a=int(m.group(2),16);sz=int(m.group(3))
            if a<0x80098000 or True:
                o=a-0x80010000
                if 0<=o<len(img): out.append((a,m.group(1),img[o:o+sz]))
    return out

import difflib
def sk2(b):
    ws=struct.unpack('<%dI'%(len(b)//4),b[:len(b)//4*4]);r=[]
    for w in ws:
        op=w>>26
        r.append(w&0x3f if op==0 else 0x100+op)
    return r
def w32(b): return struct.unpack('<%dI'%(len(b)//4),b[:len(b)//4*4])
def score(b,c):
    s,t=sk2(b),sk2(c)
    sm=difflib.SequenceMatcher(None,s,t,autojunk=False)
    r=sm.ratio()
    a,d=w32(b),w32(c);same=tot=0
    for m in sm.get_matching_blocks():
        for k in range(m.size):
            x,y=a[m.a+k],d[m.b+k];op=x>>26
            if op not in (0,2,3,0xf,1,4,5,6,7,0x12):
                tot+=1;same+=(x&0xffff)==(y&0xffff)
    return r,(same/tot if tot else 1.0)
def run():
    O=[o for o in ours() if o[0]<0x80098000]
    R=[r for r in refs() if r[0]=='SLUS']
    O.sort();R.sort(key=lambda r:r[1])
    match={}   # our addr -> (ref tuple, evidence)
    for lvl,tag in ((0,'HASH-L0'),(1,'HASH-L1')):
        rh=collections.defaultdict(list);oh=collections.defaultdict(list)
        for r in R: rh[norm(r[3],lvl)].append(r)
        for o in O:
            if len(o[2])>=12: oh[norm(o[2],lvl)].append(o)
        for h,os_ in oh.items():
            if h in rh and len(os_)==1 and len(rh[h])==1 and os_[0][0] not in match:
                match[os_[0][0]]=(rh[h][0],tag)
    print('exact',len(match))
    # monotonic gap alignment
    used={m[0][1] for m in match.values()}
    anch=sorted((a,m[0][1]) for a,m in match.items())
    # keep anchors monotonic (LIS-ish: drop ones breaking order)
    mono=[];last=-1
    for a,p in anch:
        if p>last: mono.append((a,p));last=p
    print('mono anchors',len(mono),'of',len(anch))
    Od={o[0]:o for o in O};Rd={r[1]:r for r in R}
    bounds=[(0,0)]+mono+[(1<<40,1<<40)]
    for (a1,p1),(a2,p2) in zip(bounds,bounds[1:]):
        og=[o for o in O if a1<o[0]<a2 and o[0] not in match and len(o[2])>=8]
        rg=[r for r in R if p1<r[1]<p2 and r[1] not in used and len(r[3])>=8]
        if not og or not rg: continue
        S={}
        for i,o in enumerate(og):
            for j,r in enumerate(rg):
                if not(0.5*len(o[2])<=len(r[3])<=2*len(o[2])): continue
                rr,im=score(o[2],r[3])
                if rr>=0.8 and im>=0.5: S[(i,j)]=rr*(0.5+0.5*im)
        # monotonic DP
        n,m=len(og),len(rg)
        dp=[[0.0]*(m+1) for _ in range(n+1)]
        for i in range(n-1,-1,-1):
            for j in range(m-1,-1,-1):
                best=max(dp[i+1][j],dp[i][j+1])
                if (i,j) in S: best=max(best,S[(i,j)]+dp[i+1][j+1])
                dp[i][j]=best
        i=j=0
        while i<n and j<m:
            if (i,j) in S and abs(dp[i][j]-(S[(i,j)]+dp[i+1][j+1]))<1e-9:
                r=rg[j];o=og[i]
                match[o[0]]=(r,'ALIGN r%.2f'%score(o[2],r[3])[0]);used.add(r[1]);i+=1;j+=1
            elif dp[i][j]==dp[i+1][j]: i+=1
            else: j+=1
    print('after align',len(match),'of',len(O))
    with open(P+'doapp/work/exe_match.tsv','w') as f:
        for a,(r,ev) in sorted(match.items()):
            f.write('%08x\t%s\t%s\tSLUS:%08x\n'%(a,r[2],ev,r[1]))
    un=[o for o in O if o[0] not in match]
    print('unmatched',len(un),'bytes',sum(len(o[2]) for o in un))
if __name__=='__main__': run()
