import sys,struct,re
from capstone import *
from capstone.x86 import *
class PE:
    def __init__(s,b,base):
        s.raw=b; s.base=base
        pe=base+struct.unpack_from('<I',b,base+0x3c)[0]
        nsec=struct.unpack_from('<H',b,pe+6)[0]; opt=struct.unpack_from('<H',b,pe+20)[0]
        s.size=struct.unpack_from('<I',b,pe+24+56)[0]
        s.entry=struct.unpack_from('<I',b,pe+24+16)[0]
        s.secs=[]; so=pe+24+opt
        img=bytearray(s.size)
        for i in range(nsec):
            nm,vs,va,rs,ra=struct.unpack_from('<8sIIII',b,so+40*i)
            s.secs.append((nm.rstrip(b'\0').decode(),va,vs))
            img[va:va+min(rs,vs)]=b[base+ra:base+ra+min(rs,vs)]
        hdr=struct.unpack_from('<I',b,pe+24+60)[0]; img[:hdr]=b[base:base+hdr]
        s.img=bytes(img)
    def u16str(s,rva,mx=80):
        e=rva
        while e<len(s.img)-1 and s.img[e:e+2]!=b'\0\0' and e-rva<mx*2: e+=2
        try:
            t=s.img[rva:e].decode('utf-16-le')
            return t if len(t)>=3 and all(32<=ord(c)<127 or c in '\r\n' for c in t) else None
        except: return None
    def astr(s,rva,mx=100):
        e=s.img.find(b'\0',rva,rva+mx)
        t=s.img[rva:e] if e>0 else b''
        return t.decode() if len(t)>=4 and all(32<=c<127 or c in (9,10,13) for c in t) else None
def guid(img,rva):
    import uuid
    try: return str(uuid.UUID(bytes_le=img[rva:rva+16]))
    except: return None
def disasm(p,start,end,names={}):
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    out=[]
    for ins in md.disasm(p.img[start:end],start):
        c=''
        if ins.op_count(X86_OP_MEM):
            for op in ins.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    t=ins.address+ins.size+op.mem.disp
                    c=names.get(t) or (p.u16str(t) and 'L"%s"'%p.u16str(t)) or (p.astr(t) and '"%s"'%p.astr(t)) or f'[{t:#x}]'
        if ins.mnemonic=='call' and ins.operands[0].type==X86_OP_IMM:
            t=ins.operands[0].imm; c=names.get(t,f'sub_{t:x}')
        out.append(f'{ins.address:6x}: {ins.mnemonic:6} {ins.op_str:40} {("; "+c) if c else ""}')
    return out
def funcs(p):
    for nm,va,vs in p.secs:
        if nm in ('','.pdata'):
            fs=[]
            for i in range(0,vs-11,12):
                a,e,u=struct.unpack_from('<III',p.img,va+i)
                if a and e>a: fs.append((a,e))
            if fs: return fs
    return []
def refs_to(p,targets):
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    hits={}
    for a,e in funcs(p):
        for ins in md.disasm(p.img[a:e],a):
            for op in ins.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    t=ins.address+ins.size+op.mem.disp
                    if t in targets: hits.setdefault((a,e),set()).add(targets[t])
    return hits
def funcs_pad(p):
    t=[s for s in p.secs if s[0]=='.text'][0]; a0,sz=t[1],t[2]
    code=p.img[a0:a0+sz]; starts=[a0]
    for m in re.finditer(rb'(?:\xc3|\xcc)\xcc+',code):
        nxt=a0+m.end()
        if nxt<a0+sz: starts.append(nxt)
    starts=sorted(set(starts)); return [(s,(starts[i+1] if i+1<len(starts) else a0+sz)) for i,s in enumerate(starts)]
funcs=lambda p: funcs_pad(p)
