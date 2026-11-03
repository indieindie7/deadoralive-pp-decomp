"""Tier 2/3 for the main exe: global fuzzy skeleton match + call-vote propagation. Reads work/exe_match.tsv, writes work/exe_match2.tsv"""
import sys,collections,struct,difflib
sys.path.insert(0,'C:/Users/john/Documents/DeadOrAlive/doapp/tools')
from port_exe import *
O=[o for o in ours() if o[0]<0x80098000];R=[r for r in refs() if r[0]=='SLUS']
Od={o[0]:o for o in O};Rd={r[1]:r for r in R}
match={}
for l in open(P+'doapp/work/exe_match.tsv'):
    f=l.rstrip('\n').split('\t');match[int(f[0],16)]=(int(f[3].split(':')[1],16),f[2])
def sh(s,k=4): return collections.Counter(tuple(s[i:i+k]) for i in range(len(s)-k+1))
RS={r[1]:sk2(r[3]) for r in R};RH={a:sh(s) for a,s in RS.items()}
used={m[0] for m in match.values()}
def cand(o):
    s=sk2(o[2]);n=len(s);h=sh(s);tot=sum(h.values()) or 1;sc=[]
    for a,t in RS.items():
        if a in used and False: continue
        if not(0.6*n<=len(t)<=1.7*n): continue
        sc.append((sum((h&RH[a]).values())/max(tot,sum(RH[a].values()) or 1),a))
    sc.sort(reverse=True);return sc[:6]
res={}
for o in O:
    if o[0] in match or len(o[2])<12: continue
    best=sorted(((score(o[2],Rd[a][3]),a) for _,a in cand(o)),key=lambda x:-x[0][0])
    if best: res[o[0]]=best
acc={}
for a,b in res.items():
    (r,im),p=b[0];sec=b[1][0][0] if len(b)>1 else 0
    if r>=0.85 and im>=0.6 and r-sec>=0.03: acc[a]=(p,r,im,sec)
# one-to-one
cnt=collections.Counter(v[0] for v in acc.values())
for a,v in list(acc.items()):
    if cnt[v[0]]>1 or v[0] in used: del acc[a]
print('fuzzy accepted',len(acc))
for a,v in acc.items(): match[a]=(v[0],'FUZZ r%.2f imm%.2f m%.2f'%(v[1],v[2],v[1]-v[3]))
# call-vote: for unmatched ours f, calls (jal targets) -> ref callee sets
def calls(b): return [(w&0x3ffffff)<<2|0x80000000 for w in w32(b) if w>>26==3]
for it in range(4):
    used={m[0] for m in match.values()};add={}
    for o in O:
        if o[0] in match: continue
        mc=[match[c][0] for c in calls(o[2]) if c in match]
        if len(mc)<2: continue
        votes=collections.Counter()
        for p in Rd:
            if p in used: continue
            pc=set(calls(Rd[p][3]));votes[p]=sum(1 for c in mc if c in pc)
        top=votes.most_common(2)
        if top and top[0][1]>=2 and (len(top)<2 or top[0][1]>top[1][1]):
            p=top[0][0];r,im=score(o[2],Rd[p][3])
            if r>=0.6 and top[0][1]>=0.6*len(mc): add[o[0]]=(p,'CALLVOTE v%d/%d r%.2f'%(top[0][1],len(mc),r))
    cnt=collections.Counter(v[0] for v in add.values())
    add={a:v for a,v in add.items() if cnt[v[0]]==1}
    print('iter',it,len(add))
    if not add: break
    match.update(add)
with open(P+'doapp/work/exe_match2.tsv','w') as f:
    for a,(p,ev) in sorted(match.items()): f.write('%08x\t%s\t%s\tSLUS:%08x\n'%(a,Rd[p][2],ev,p))
print('matched',len(match),'of',len(O),'unmatched bytes',sum(len(o[2]) for o in O if o[0] not in match))
