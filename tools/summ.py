import sys,re; S=sys.argv[1]
exec(open(S+'/fwdis.py').read())
b=open(S+'/bios/lz/b1.bin','rb').read()
base=int(sys.argv[2],16); p=PE(b,base)
BS={0x28:'AllocatePages',0x40:'AllocatePool',0x48:'FreePool',0x50:'CreateEvent',0x68:'SignalEvent',0x70:'CloseEvent',0x98:'HandleProtocol',0xa8:'RegisterProtocolNotify',0xb0:'LocateHandle',0x140:'LocateProtocol',0x148:'InstallMultipleProtocolInterfaces',0x170:'CreateEventEx',0x138:'LocateHandleBuffer'}
RT={0x48:'GetVariable',0x50:'GetNextVariableName',0x58:'SetVariable',0x68:'ResetSystem'}
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
# find gBS/gRT globals: mov [rip+x], rax after mov rax,[rdx+0x60]/[rdx+0x58]
g={}
for a,e in funcs(p):
    last=None
    for ins in md.disasm(p.img[a:e],a):
        if ins.mnemonic=='mov' and ins.op_count(X86_OP_MEM)==1:
            o=ins.operands
            if o[1].type==X86_OP_MEM and o[1].mem.base in (X86_REG_RDX,X86_REG_RCX,X86_REG_RAX) and o[1].mem.disp in (0x58,0x60) and o[0].type==X86_OP_REG: last=(o[0].reg,o[1].mem.disp)
            elif o[0].type==X86_OP_MEM and o[0].mem.base==X86_REG_RIP and last and o[1].type==X86_OP_REG and o[1].reg==last[0]:
                g[ins.address+ins.size+o[0].mem.disp]='gRT' if last[1]==0x58 else 'gBS'; last=None
print('globals',{hex(k):v for k,v in g.items()})
lo,hi=(int(sys.argv[3],16),int(sys.argv[4],16)) if len(sys.argv)>4 else (0,p.size)
for a,e in funcs(p):
    if not (lo<=a<hi): continue
    regsrc={}; lines=[]
    for ins in md.disasm(p.img[a:e],a):
        c=''
        for op in ins.operands:
            if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                t=ins.address+ins.size+op.mem.disp
                if t in g and ins.mnemonic=='mov' and ins.operands[0].type==X86_OP_REG: regsrc[ins.operands[0].reg]=g[t]
                s=p.u16str(t); s2=p.astr(t)
                if s: c=f'L"{s}"'
                elif s2: c=f'"{s2}"'
        if ins.mnemonic=='call':
            op=ins.operands[0]
            if op.type==X86_OP_MEM and op.mem.base in regsrc:
                tb=regsrc[op.mem.base]; c=(BS if tb=='gBS' else RT).get(op.mem.disp,hex(op.mem.disp)); c=f'{tb}->{c}'
            elif op.type==X86_OP_MEM: c=f'indirect [{ins.reg_name(op.mem.base) if op.mem.base else "rip"}+{op.mem.disp:#x}]'
            elif op.type==X86_OP_IMM: c=f'sub_{op.imm:x}'
            lines.append(f'  {ins.address:6x}: CALL {c}')
        elif c: lines.append(f'  {ins.address:6x}: {ins.mnemonic} {ins.op_str}  ; {c}')
        elif ins.mnemonic in('mov','cmp','and','or') and any(op.type==X86_OP_IMM and op.imm>0xffff and op.imm&0xffffffff not in (0xffffffff,) for op in ins.operands):
            lines.append(f'  {ins.address:6x}: {ins.mnemonic} {ins.op_str}')
        elif ins.mnemonic in ('mov','movzx','cmp') and any(op.type==X86_OP_MEM and op.mem.disp in (0x58,0x59) and op.mem.base not in (X86_REG_RSP,X86_REG_RIP) for op in ins.operands):
            lines.append(f'  {ins.address:6x}: {ins.mnemonic} {ins.op_str}   <-- off 0x58/0x59')
    if lines: print(f'\n== func {a:#x}-{e:#x}'); print('\n'.join(lines))
