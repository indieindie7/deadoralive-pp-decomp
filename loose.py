"""Loose tier: opcode-only skeleton, 4-gram shingle prefilter, SequenceMatcher on top 6. Writes ../work/loose.tsv"""
import struct,sys,difflib,collections
sys.path.insert(0,'.')
from match_plain import *
def sk2(b):
    ws=struct.unpack('<%dI'%(len(b)//4),b[:len(b)//4*4]);r=[]
    for w in ws:
        op=w>>26
        r.append(w&0x3f if op==0 else 0x100+op)
    return r
def sh(s,k=4): return collections.Counter(tuple(s[i:i+k]) for i in range(len(s)-k+1))
R=refs()
RS=[(r,sk2(r[3])) for r in R]
RH=[sh(s) for _,s in RS]
named={int(l.split('\t')[0],16) for l in list(open(P+'doapp/public/names.tsv'))[1:]}
out=open(P+'doapp/work/loose.tsv','w')
for o,b in funcs():
    a=o+BASE
    if a in named: continue
    s=sk2(b);n=len(s)
    if n<8: continue
    h=sh(s);tot=sum(h.values()) or 1
    sc=[]
    for i,(r,t) in enumerate(RS):
        if not(0.6*n<=len(t)<=1.7*n): continue
        ov=sum((h&RH[i]).values())
        sc.append((ov/max(tot,sum(RH[i].values()) or 1),i))
    sc.sort(reverse=True)
    best=[]
    for _,i in sc[:6]:
        r,t=RS[i]
        best.append((difflib.SequenceMatcher(None,s,t,autojunk=False).ratio(),r))
    best.sort(key=lambda x:-x[0])
    if best:
        sec=best[1][0] if len(best)>1 else 0
        r=best[0][1]
        out.write('%08x\t%d\t%.3f\t%.3f\t%s:%08x:%s\n'%(a,n*4,best[0][0],sec,r[0],r[1],r[2]));out.flush()
