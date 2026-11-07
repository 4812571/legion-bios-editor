import sys,re; S=sys.argv[1]
exec(open(S+'/fwdis.py').read())
b=open(S+'/bios/lz/b1.bin','rb').read()
base=int(sys.argv[2],16); p=PE(b,base)
names=sys.argv[3].split(',')
T={}
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,}\x00\x00',p.img): T[m.start()]=m.group()[:-2].decode('utf-16-le')
for nm,va,vs in p.secs:
    pass
# also GUID labels
want={k:v for k,v in T.items() if v in names}
print('size',hex(p.size),'entry',hex(p.entry),'targets',{hex(k):v for k,v in want.items()})
h=refs_to(p,want)
for (a,e),s in sorted(h.items()):
    print(f'\n==== func {a:#x}-{e:#x} refs {sorted(s)}')
    print('\n'.join(disasm(p,a,e)))
