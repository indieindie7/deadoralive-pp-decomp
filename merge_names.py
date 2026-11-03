"""Merge hand_batch + review_batch into public/hand_doapp.txt and names.tsv (commit per batch)."""
import re,glob,subprocess,sys
W='work/'
ren={'0x80129a60':'test_RunPadLoopPageWithPlaytime','0x8012a3bc':'test_RunPadLoopPageWithCursor','0x80130b6c':'test_RunViewerPageNoMotion'}
hand={};rev={}
for f in glob.glob(W+'hand_batch_*.txt'):
    for l in open(f,encoding='utf8'):
        m=re.match(r'0x([0-9a-f]{8}) func (\S+) hand (.*)',l.strip())
        if m: hand[m.group(1)]=(m.group(2),m.group(3))
for f in glob.glob(W+'review_batch_*.txt'):
    for l in open(f,encoding='utf8'):
        p=l.strip().split(None,4)
        if len(p)==5 and p[0].startswith('0x'): rev[p[0][2:]]=(p[1],p[2],p[3],p[4])
final={}
for a,(n,ev) in hand.items():
    v,rn,cl,rev_ev=rev[a]
    name=rn
    if '0x'+a in ren: name=ren['0x'+a];v='rename'
    tag='confirm' if v=='confirm' else 'renamed' if v=='rename' else 'confirm-r2'
    final[a]=(name,tag,ev if v=='confirm' else rev_ev,cl)
used=set();dup=[]
for a,(n,*_) in final.items():
    if n in used: dup.append(n)
    used.add(n)
print('dups',dup,len(final))
rows=[l.rstrip('\n').split('\t') for l in open('public/names.tsv')]
hdr=rows[0];body=rows[1:]
oldn={r[1] for r in body if r[3]!='-'}
print('clash',[n for n in used if n in oldn])
todo=[l.split('\t')[0] for l in open(W+'todo.tsv')]
h=open('public/hand_doapp.txt','w');h.close()
for i in range(0,len(todo),56):
    with open('public/hand_doapp.txt','a',encoding='utf8') as h:
        for a in todo[i:i+56]:
            n,t,ev,cl=final[a];h.write('0x%s func %s hand [review %s; callers %s] %s\n'%(a,n,t,cl,ev))
    subprocess.run(['git','add','public/hand_doapp.txt'],capture_output=True)
    subprocess.run(['git','commit','-qm','hand_doapp semantic names %d/%d (reviewed)\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'%(min(i+56,len(todo)),len(todo))],capture_output=True)
out=[]
for r in body:
    a=r[0]
    if r[3]=='-' and a in final:
        n,t,ev,cl=final[a];r=[a,n,'CODEREAD-%s %s'%(t,ev),'-']
    out.append(r)
open('public/names.tsv','w',encoding='utf8').write('\n'.join('\t'.join(r) for r in [hdr]+out)+'\n')
