"""PE loading and x86-64 disassembly for firmware modules.

`PeImage` maps a PE32+ image embedded in a firmware volume to its virtual
layout. The disassembly helpers annotate RIP-relative operands with the
strings they point at.
"""

import re
import struct
import uuid
from pathlib import Path
from typing import NamedTuple

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86Op

DXE_VOLUME = Path("bios", "lz", "b1.bin")

# PE/COFF header offsets. COFF fields are relative to the "PE\0\0" signature,
# optional-header fields to the start of the optional header.
_E_LFANEW = 0x3C
_COFF_NUMBER_OF_SECTIONS = 6
_COFF_SIZE_OF_OPTIONAL_HEADER = 20
_OPTIONAL_HEADER = 24
_OPT_ADDRESS_OF_ENTRY_POINT = 16
_OPT_SIZE_OF_IMAGE = 56
_OPT_SIZE_OF_HEADERS = 60
_SECTION_HEADER = struct.Struct("<8sIIII")  # Name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
_SECTION_HEADER_SIZE = 40

# ret or int3, followed by int3 padding: the gap between two functions.
_INTER_FUNCTION_PADDING = re.compile(rb"(?:\xc3|\xcc)\xcc+")


def hex_int(text: str) -> int:
    """argparse type for hex numbers, with or without a 0x prefix."""
    return int(text, 16)


def load_dxe_volume(workdir: str | Path) -> bytes:
    """Read the LZMA-decompressed DXE volume from an extraction directory."""
    return (Path(workdir) / DXE_VOLUME).read_bytes()


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _is_printable_text(text: str) -> bool:
    return all(32 <= ord(c) < 127 or c in "\r\n" for c in text)


def _is_printable_ascii(data: bytes) -> bool:
    return all(32 <= c < 127 or c in (9, 10, 13) for c in data)


class Section(NamedTuple):
    name: str
    rva: int
    virtual_size: int


class PeImage:
    """A PE32+ image found at file offset `base` in `raw`.

    `image` is the image as loaded into memory, indexed by RVA.
    """

    def __init__(self, raw: bytes, base: int) -> None:
        self.raw = raw
        self.base = base

        pe = base + _u32(raw, base + _E_LFANEW)
        section_count = _u16(raw, pe + _COFF_NUMBER_OF_SECTIONS)
        optional_header = pe + _OPTIONAL_HEADER
        section_table = optional_header + _u16(raw, pe + _COFF_SIZE_OF_OPTIONAL_HEADER)

        self.size = _u32(raw, optional_header + _OPT_SIZE_OF_IMAGE)
        self.entry = _u32(raw, optional_header + _OPT_ADDRESS_OF_ENTRY_POINT)
        self.sections: list[Section] = []

        image = bytearray(self.size)
        for i in range(section_count):
            name, virtual_size, rva, raw_size, raw_offset = _SECTION_HEADER.unpack_from(
                raw, section_table + _SECTION_HEADER_SIZE * i
            )
            self.sections.append(Section(name.rstrip(b"\0").decode(), rva, virtual_size))
            length = min(raw_size, virtual_size)
            image[rva : rva + length] = raw[base + raw_offset : base + raw_offset + length]

        headers_size = _u32(raw, optional_header + _OPT_SIZE_OF_HEADERS)
        image[:headers_size] = raw[base : base + headers_size]
        self.image = bytes(image)

    def section(self, name: str) -> Section:
        for section in self.sections:
            if section.name == name:
                return section
        raise KeyError(f"no {name} section")

    def utf16_at(self, rva: int, max_chars: int = 80) -> str | None:
        """The printable UTF-16LE string at `rva` (3+ chars), else None."""
        end = rva
        while (
            end < len(self.image) - 1
            and self.image[end : end + 2] != b"\0\0"
            and end - rva < max_chars * 2
        ):
            end += 2
        try:
            text = self.image[rva:end].decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        return text if len(text) >= 3 and _is_printable_text(text) else None

    def ascii_at(self, rva: int, max_len: int = 100) -> str | None:
        """The printable NUL-terminated ASCII string at `rva` (4+ chars), else None."""
        end = self.image.find(b"\0", rva, rva + max_len)
        data = self.image[rva:end] if end > 0 else b""
        return data.decode() if len(data) >= 4 and _is_printable_ascii(data) else None

    def guid_at(self, rva: int) -> str | None:
        try:
            return str(uuid.UUID(bytes_le=self.image[rva : rva + 16]))
        except ValueError:
            return None


def disassembler() -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def rip_target(ins: CsInsn, op: X86Op) -> int | None:
    """The RVA addressed by a RIP-relative memory operand, else None."""
    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
        return ins.address + ins.size + op.mem.disp
    return None


def string_label(pe: PeImage, rva: int) -> str | None:
    """`L"..."` or `"..."` for a UTF-16 or ASCII string at `rva`, else None."""
    if text := pe.utf16_at(rva):
        return f'L"{text}"'
    if text := pe.ascii_at(rva):
        return f'"{text}"'
    return None


def disassemble(
    pe: PeImage, start: int, end: int, names: dict[int, str] | None = None
) -> list[str]:
    """Disassemble [start, end) into lines, commenting RIP-relative operands and calls.

    `names` maps RVAs to labels that take precedence over string annotations.
    """
    names = names or {}
    lines = []
    for ins in disassembler().disasm(pe.image[start:end], start):
        comment = ""
        for op in ins.operands:
            target = rip_target(ins, op)
            if target is not None:
                comment = names.get(target) or string_label(pe, target) or f"[{target:#x}]"
        if ins.mnemonic == "call" and ins.operands[0].type == X86_OP_IMM:
            target = ins.operands[0].imm
            comment = names.get(target, f"sub_{target:x}")
        suffix = f"; {comment}" if comment else ""
        lines.append(f"{ins.address:6x}: {ins.mnemonic:6} {ins.op_str:40} {suffix}")
    return lines


def find_functions(pe: PeImage) -> list[tuple[int, int]]:
    """Split .text into (start, end) function ranges at int3 padding."""
    text = pe.section(".text")
    text_end = text.rva + text.virtual_size
    starts = {text.rva}
    for m in _INTER_FUNCTION_PADDING.finditer(pe.image[text.rva : text_end]):
        next_start = text.rva + m.end()
        if next_start < text_end:
            starts.add(next_start)
    ordered = sorted(starts)
    return list(zip(ordered, ordered[1:] + [text_end], strict=True))


def functions_referencing(
    pe: PeImage, targets: dict[int, str]
) -> dict[tuple[int, int], set[str]]:
    """Map each function to the labels of the `targets` RVAs it references RIP-relatively."""
    md = disassembler()
    hits: dict[tuple[int, int], set[str]] = {}
    for start, end in find_functions(pe):
        for ins in md.disasm(pe.image[start:end], start):
            for op in ins.operands:
                target = rip_target(ins, op)
                if target in targets:
                    hits.setdefault((start, end), set()).add(targets[target])
    return hits
