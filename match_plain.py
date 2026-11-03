"""Match plain-region functions of doapp prog.bin against PSX DOA functions by normalised skeleton.
usage: py -3.13 -I match_plain.py  -> writes ../work/match.tsv"""
import struct,sys,hashlib,collections
P='C:/Users/john/Documents/DeadOrAlive/'
prog=open(P+'doapp/work/prog.bin','rb').read()
BASE=0x7fff7e18
def refs():
    out=[]
    for nm,base in (('SLUS',0x80010000),('OV00',0x80093420),('OV02',0x80093420)):
        data=open(P+f'psx/ghidra/{nm}.BIN','rb').read()
        for ln in open(P+f'psx/ghidra/funcinfo5_{nm}.tsv'):
            f=ln.split()
            if len(f)>=5 and f[0]=='F':
                a=int(f[1],16);sz=int(f[4]);o=a-base
                if sz>=8 and 0<=o<len(data): out.append((nm,a,f[2],data[o:o+sz]))
    return out
def norm(b,level):
    ws=struct.unpack('<%dI'%(len(b)//4),b[:len(b)//4*4]);r=[]
    for w in ws:
        op=w>>26
        if level==0:
            if op in(2,3): w=w&0xfc000000
            elif op==0xf: w=w&0xffff0000        # lui imm masked
            elif op in(0x9,0x23,0x2b,0x21,0x25,0x29,0x20,0x24,0x28,0xc,0xd) and False: pass
        else:
            if op in(2,3): w&=0xfc000000
            elif op==0xf: w&=0xffe00000
            elif op in(8,9,0xc,0xd,0xe,0xa,0xb,0x20,0x21,0x23,0x24,0x25,0x28,0x29,0x2b): w&=0xffff0000
        r.append(w)
    return hashlib.sha1(struct.pack('<%dI'%len(r),*r)).hexdigest()
def funcs():
    # prologue scan: addiu sp,sp,-N (0x27bd....) with negative imm
    res=[];n=len(prog)
    for off in list(range(0xa0000,0x110000,4))+list(range(0x130000,0x150000,4)):
        w=struct.unpack_from('<I',prog,off)[0]
        if (w>>16)==0x27bd and (w&0x8000):
            res.append(off)
    # end = next prologue or jr ra + delay slot
    out=[]
    for i,o in enumerate(res):
        e=res[i+1] if i+1<len(res) else o+0x400
        # find last jr ra before e
        last=None
        for x in range(o,e,4):
            if struct.unpack_from('<I',prog,x)[0]==0x03e00008: last=x+8
        if last: out.append((o,prog[o:last]))
    return out
if __name__=='__main__':
    R=refs();idx=[collections.defaultdict(list),collections.defaultdict(list)]
    for r in R:
        for l in (0,1): idx[l][norm(r[3],l)].append(r)
    F=funcs();hit=0
    with open(P+'doapp/work/match.tsv','w') as f:
        for o,b in F:
            m=[]
            for l in (0,1):
                c=idx[l].get(norm(b,l))
                if c: m=c;lv=l;break
            if m: hit+=1;f.write('%08x\t%d\tL%d\t%d\t%s\n'%(o+BASE,len(b),lv,len(m),';'.join(f'{x[0]}:{x[1]:08x}:{x[2]}' for x in m[:3])))
            else: f.write('%08x\t%d\t-\t0\t\n'%(o+BASE,len(b)))
    print(len(F),'funcs',hit,'matched')
