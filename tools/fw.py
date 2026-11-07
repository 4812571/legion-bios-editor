import struct,re,uuid
def pe_at(b,off):
    for m in reversed([m.start() for m in re.finditer(b'MZ',b[max(0,off-0x400000):off])]):
        m+=max(0,off-0x400000)
        try:
            pe=struct.unpack_from('<I',b,m+0x3c)[0]
            if pe<0x1000 and b[m+pe:m+pe+4]==b'PE\0\0':
                img=struct.unpack_from('<I',b,m+pe+0x50)[0]
                if m<=off<m+img: return m,img
        except: pass
    # TE images (PEI): 'VZ'
    for m in reversed([m.start() for m in re.finditer(b'VZ',b[max(0,off-0x100000):off])]):
        m+=max(0,off-0x100000)
        return m,None
    return None
def ui_name(b,base,sz):
    after=b[base+sz:base+sz+0x400] if sz else b[base:base+0x40000]
    m=re.search(rb'\x15((?:[\x20-\x7e]\x00){3,})\x00\x00',b[base-0x40:base+(sz or 0)+0x400])
    m2=re.search(rb'((?:[A-Za-z0-9_]\x00){4,})\x00\x00',after)
    return m2.group(1).decode('utf-16-le') if m2 else '?'
