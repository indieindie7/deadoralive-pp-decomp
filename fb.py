import numpy as np,sys,collections
o=open(sys.argv[1],'rb').read(); s=int(sys.argv[2],16); n=int(sys.argv[3],16)
w=np.frombuffer(o[s:s+n],dtype='<u4')
tg=np.unique(((w[(w>>26)==3]&0x3ffffff)<<2)|0x80000000)
pro=np.nonzero(((w>>16)==0x27bd)&((w&0x8000)!=0))[0]*4+s
c=collections.Counter()
for t in tg:
    d=(int(t)-pro)  # base-from-file-offset: addr = off + K  => K = t - pro
    for k in d[(d>0x7fff0000)&(d<0x80200000)]: c[int(k)]+=1
print(len(tg),len(pro),[(hex(k),v) for k,v in c.most_common(5)])
