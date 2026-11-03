"""Split work/dump_named.c FUN_ functions into batches work/ebatch_N.txt with caller names. Writes work/etodo.tsv"""
import re,struct,collections
P='C:/Users/john/Documents/DeadOrAlive/doapp/'
txt=open(P+'work/dump_named.c',encoding='utf8',errors='replace').read()
img=open(P+'work/doapp_full.bin','rb').read()
chunks={};names={};sizes={}
for m in re.finditer(r'// ==== (\S+) @ ([0-9a-f]{8}) size=(\d+)\n(.*?)(?=\n// ==== |\Z)',txt,re.S):
    a=int(m.group(2),16);chunks[a]=m.group(4);names[a]=m.group(1);sizes[a]=int(m.group(3))
order=sorted(chunks)
callers=collections.defaultdict(set)
for a in order:
    o=a-0x80010000
    for i in range(0,sizes[a]&~3,4):
        w=struct.unpack_from('<I',img,o+i)[0]
        if w>>26==3:
            t=(w&0x3ffffff)<<2|0x80000000
            if t in chunks and t!=a: callers[t].add(a)
todo=[a for a in order if names[a].startswith('FUN_')]
open(P+'work/etodo.tsv','w').write('\n'.join('%08x\t%d'%(a,sizes[a]) for a in todo))
prov={l.split('\t')[0]:l.rstrip('\n').split('\t') for l in open(P+'work/exe_prov.tsv') if l.strip()}
b=[];cur=0;n=0
def flush():
    global b,cur,n
    if b:
        n+=1;open(P+'work/ebatch_%d.txt'%n,'w',encoding='utf8').write('\n'.join(b));b=[];cur=0
for a in todo:
    c=sorted(callers[a])[:4]
    cn=', '.join(names[x] for x in c) or 'none (maybe fn-pointer/table)'
    h='#### %08x %s size=%d callers: %s'%(a,names[a],sizes[a],cn)
    pr=prov.get('%08x'%a)
    if pr: h+='\nPSX-HINT (unverified, confirm or reject): %s via %s'%(pr[1],pr[2])
    body=chunks[a]
    if len(body)>9000: body=body[:9000]+'\n/* ...truncated... */'
    item=h+'\n'+body+'\n'
    if cur+len(item)>60000 or len(b)>=60: flush()
    b.append(item);cur+=len(item)
flush()
print(len(todo),'batches',n)
