import sys,struct,re
b=open(sys.argv[1],'rb').read()
MODS=[(0xe406ac,0x34620),(0xec1bbc,0xbfae0),(0x17346b4,0x2cb40)]
def ui_name(base,sz):
    after=b[base+sz:base+sz+0x200]
    m=re.search(rb'((?:[\x20-\x7e]\x00){4,})\x00\x00',after)
    return m.group(1).decode('utf-16-le') if m else '?'
def strings(seg):
    res=[]
    for m in re.finditer(rb'en-US\x00',seg):
        p=m.start()-46
        if p<0 or seg[p+3]!=0x04: continue
        ln=int.from_bytes(seg[p:p+3],'little'); hs,sio=struct.unpack_from('<II',seg,p+4)
        if hs!=46 and hs<46: continue
        q=p+sio; sid=1; tab={}
        while q<p+ln:
            t=seg[q]
            if t==0x00: break
            if t==0x14:
                e=q+1
                while seg[e:e+2]!=b'\0\0': e+=2
                tab[sid]=seg[q+1:e].decode('utf-16-le','replace'); sid+=1; q=e+2
            elif t==0x21: sid+=struct.unpack_from('<H',seg,q+1)[0]; q+=3
            elif t==0x22: sid+=seg[q+1]; q+=2
            elif t==0x20: sid+=1; q+=3
            elif t==0x30: q+=seg[q+2]
            elif t==0x31: q+=struct.unpack_from('<H',seg,q+2)[0]
            elif t==0x32: q+=struct.unpack_from('<I',seg,q+2)[0]
            else: break
        res.append((p,len(tab),tab))
    return res
def forms(seg):
    out=[]
    for m in re.finditer(rb'\x0e[\x98-\xff]',seg):
        p=m.start()-4
        if p<0 or seg[p+3]!=0x02: continue
        ln=int.from_bytes(seg[p:p+3],'little')
        if ln<0x40 or p+ln>len(seg): continue
        out.append((p,ln))
    return out
OPN={0x05:'oneof',0x24:'varstore',0x26:'efivarstore',0x09:'option',0x01:'form',0x02:'subtitle',0x0f:'ref',0x5b:'default',0x0a:'suppressif',0x19:'grayoutif',0x0e:'formset',0x29:'end',0x06:'checkbox',0x07:'numeric',0x2a:'expr'}
def walk(seg,p,ln,tab,want):
    q=p+4; vs={}; cur=None; lines=[]
    while q<p+ln:
        op=seg[q]; l=seg[q+1]&0x7f
        if l==0: break
        if op==0x24:
            gid=seg[q+2:q+18]; vid,sz=struct.unpack_from('<HH',seg,q+18); nm=seg[q+22:q+l].split(b'\0')[0].decode()
            vs[vid]=nm
        elif op==0x26:
            vid=struct.unpack_from('<H',seg,q+2)[0]; nm=seg[q+28:q+l].split(b'\0')[0].decode(); vs[vid]=nm
        elif op in (0x05,0x06,0x07):
            pr,hl,qid,vid,voff=struct.unpack_from('<HHHHH',seg,q+2)
            name=tab.get(pr,f'#{pr}')
            cur = any(w in name for w in want)
            if cur: lines.append(f'  {OPN[op]} "{name}" varstore={vs.get(vid,vid)} off=0x{voff:x} qid={qid} flags=0x{seg[q+12]:02x}')
        elif op==0x09 and cur:
            sid,fl,ty=struct.unpack_from('<HBB',seg,q+2)
            val=int.from_bytes(seg[q+6:q+l][:{0:1,1:2,2:4,3:8}.get(ty,1)],'little')
            lines.append(f'      opt "{tab.get(sid,sid)}" = {val}{" [DEFAULT]" if fl&0x10 else ""}{" [MFG]" if fl&0x20 else ""}')
        elif op==0x5b and cur:
            did,ty=struct.unpack_from('<HB',seg,q+2)
            lines.append(f'      default(store {did}) = {int.from_bytes(seg[q+5:q+l],"little")}')
        elif op==0x29: pass
        q+=l
    return vs,lines
want=sys.argv[2].split('|')
for base,sz in MODS:
    seg=b[base:base+sz]
    print('=== module',hex(base),ui_name(base,sz))
    st=max(strings(seg),key=lambda x:x[1],default=None)
    if not st: print(' no strings'); continue
    tab=st[2]
    for p,ln in forms(seg):
        vs,lines=walk(seg,p,ln,tab,want)
        print(f' formpkg@{hex(p)} len={hex(ln)} varstores={vs}')
        print('\n'.join(lines))
