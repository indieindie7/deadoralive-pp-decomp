"""Fuzzy tier: opcode+reg skeleton similarity. Writes ../work/fuzzy.tsv (off, size, ratio, second, ref)."""
import struct,sys,difflib
sys.path.insert(0,'.')
from match_plain import *
def sk(b):
    ws=struct.unpack('<%dI'%(len(b)//4),b[:len(b)//4*4]);r=[]
    for w in ws:
        op=w>>26
        if op==0: r.append((w&0x3f)|((w>>11&31)<<8) if False else w&0x03e0003f|0)
        elif op in(2,3): r.append(op<<26)
        else: r.append(w&0xffe00000 if op==0xf else w&0xffff0000)
    return r
R=refs();RS=[(r,sk(r[3])) for r in R]
done={l.split('\t')[0] for l in open(P+'doapp/work/match.tsv') if l.split('\t')[2]!='-'}
out=open(P+'doapp/work/fuzzy.tsv','w')
for o,b in funcs():
    if '%08x'%(o+BASE) in done: continue
    a=sk(b);n=len(a)
    if n<12: continue
    cands=[(r,s) for r,s in RS if 0.8*n<=len(s)<=1.25*n]
    sc=[]
    for r,s in cands:
        sm=difflib.SequenceMatcher(None,a,s,autojunk=False)
        if sm.real_quick_ratio()<0.85 or sm.quick_ratio()<0.85: continue
        sc.append((sm.ratio(),r))
    sc.sort(key=lambda x:-x[0])
    if sc:
        r=sc[0][1];sec=sc[1][0] if len(sc)>1 else 0
        out.write('%08x\t%d\t%.3f\t%.3f\t%s:%08x:%s\n'%(o+BASE,n*4,sc[0][0],sec,r[0],r[1],r[2]))
        out.flush()
