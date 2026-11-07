import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
exec(open(sys.argv[1]).read().split('want=sys.argv')[0].replace("b=open(sys.argv[1],'rb').read()","b=open(sys.argv[2],'rb').read()"))
base,sz=MODS[int(sys.argv[3])]; seg=b[base:base+sz]
tab=max(strings(seg),key=lambda x:x[1])[2]
p=int(sys.argv[4],16); ln=int.from_bytes(seg[p:p+3],'little')
q=p+4; depth=0; vs={}
N={0x01:'FORM',0x02:'SUBTITLE',0x03:'TEXT',0x05:'ONEOF',0x06:'CHECKBOX',0x07:'NUMERIC',0x09:'OPT',0x0a:'SUPPRESSIF',0x0e:'FORMSET',0x0f:'REF',0x12:'EQ_ID_VAL',0x13:'EQ_ID_ID',0x14:'EQ_ID_LIST',0x15:'AND',0x16:'OR',0x17:'NOT',0x19:'GRAYOUTIF',0x1a:'DATE',0x24:'VARSTORE',0x26:'EFIVARSTORE',0x29:'END',0x2a:'FALSE?',0x46:'TRUE',0x47:'FALSE',0x5b:'DEFAULT',0x5f:'GUID',0x27:'DISABLEIF',0x31:'NOT?',0x3d:'ACTION?'}
while q<p+ln:
    op=seg[q]; l=seg[q+1]&0x7f; sc=seg[q+1]>>7
    if l==0: break
    ind='  '*depth; s=''
    if op in (0x05,0x06,0x07,0x0f,0x03,0x02,0x01):
        if op==0x01: s=f'id={struct.unpack_from("<H",seg,q+2)[0]} "{tab.get(struct.unpack_from("<H",seg,q+4)[0])}"'
        elif op==0x02 or op==0x03: s=f'"{tab.get(struct.unpack_from("<H",seg,q+2)[0])}"'
        else:
            pr,hl,qid,vid,voff=struct.unpack_from('<HHHHH',seg,q+2)
            s=f'"{tab.get(pr)}" qid={qid} vs={vs.get(vid,vid)} off=0x{voff:x}'
            if op==0x0f and l>=17: s+=f' -> form {struct.unpack_from("<H",seg,q+15)[0]}'
    elif op==0x12: qid,val=struct.unpack_from('<HH',seg,q+2); s=f'q{qid} == {val}'
    elif op==0x14:
        qid,n=struct.unpack_from('<HH',seg,q+2); s=f'q{qid} in {list(struct.unpack_from("<"+"H"*n,seg,q+6))}'
    elif op==0x13: s=f'q{struct.unpack_from("<H",seg,q+2)[0]} == q{struct.unpack_from("<H",seg,q+4)[0]}'
    elif op==0x09:
        sid,fl,ty=struct.unpack_from('<HBB',seg,q+2); s=f'"{tab.get(sid)}"={int.from_bytes(seg[q+6:q+l][:{0:1,1:2,2:4,3:8}.get(ty,1)],"little")} fl=0x{fl:x}'
    elif op in (0x24,0x26):
        vid=struct.unpack_from('<H',seg,q+(18 if op==0x24 else 2))[0]; nm=seg[q+(22 if op==0x24 else 28):q+l].split(b'\0')[0].decode(); vs[vid]=nm; s=f'{vid}={nm}'
    if op==0x29: depth=max(0,depth-1)
    if op not in (0x29,0x5b): print(f'{ind}{N.get(op,hex(op))} {s}')
    if sc: depth+=1
    q+=l
