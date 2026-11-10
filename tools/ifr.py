"""Find HII questions by prompt in the firmware image's setup modules.

For each module in HII_MODULES, prints the one-of/checkbox/numeric questions
whose prompt contains any of the given substrings, with their varstore,
offset, options and defaults.
"""

import argparse
import re
import struct
from collections.abc import Iterator
from typing import NamedTuple

# (offset, size) of the modules carrying HII packages in the T3CN37WW image.
HII_MODULES = [(0xe406ac, 0x34620), (0xec1bbc, 0xbfae0), (0x17346b4, 0x2cb40)]

PACKAGE_HEADER_SIZE = 4
PACKAGE_TYPE_FORMS = 0x02
PACKAGE_TYPE_STRINGS = 0x04
# String package header up to the language name: package header, HdrSize,
# StringInfoOffset, LanguageWindow[16], LanguageName.
STRING_PACKAGE_FIXED_HEADER = 46

# String block types (EFI_HII_SIBT_*).
SIBT_END = 0x00
SIBT_STRING_UCS2 = 0x14
SIBT_DUPLICATE = 0x20
SIBT_SKIP2 = 0x21
SIBT_SKIP1 = 0x22
SIBT_EXT1 = 0x30
SIBT_EXT2 = 0x31
SIBT_EXT4 = 0x32

# IFR opcodes (EFI_IFR_*_OP).
OP_FORM = 0x01
OP_SUBTITLE = 0x02
OP_TEXT = 0x03
OP_ONE_OF = 0x05
OP_CHECKBOX = 0x06
OP_NUMERIC = 0x07
OP_ONE_OF_OPTION = 0x09
OP_FORM_SET = 0x0e
OP_REF = 0x0f
OP_EQ_ID_VAL = 0x12
OP_EQ_ID_ID = 0x13
OP_EQ_ID_VAL_LIST = 0x14
OP_VARSTORE = 0x24
OP_VARSTORE_EFI = 0x26
OP_END = 0x29
OP_DEFAULT = 0x5b

QUESTION_OPS = (OP_ONE_OF, OP_CHECKBOX, OP_NUMERIC)
VARSTORE_OPS = (OP_VARSTORE, OP_VARSTORE_EFI)

IFR_OPCODE_NAMES = {
    0x01: "FORM",
    0x02: "SUBTITLE",
    0x03: "TEXT",
    0x05: "ONEOF",
    0x06: "CHECKBOX",
    0x07: "NUMERIC",
    0x09: "OPT",
    0x0a: "SUPPRESSIF",
    0x0e: "FORMSET",
    0x0f: "REF",
    0x12: "EQ_ID_VAL",
    0x13: "EQ_ID_ID",
    0x14: "EQ_ID_LIST",
    0x15: "AND",
    0x16: "OR",
    0x17: "NOT",
    0x19: "GRAYOUTIF",
    0x1a: "DATE",
    0x24: "VARSTORE",
    0x26: "EFIVARSTORE",
    0x27: "DISABLEIF",
    0x29: "END",
    0x2a: "FALSE?",
    0x31: "NOT?",
    0x3d: "ACTION?",
    0x46: "TRUE",
    0x47: "FALSE",
    0x5b: "DEFAULT",
    0x5f: "GUID",
}

ONE_OF_OPTION_DEFAULT = 0x10
ONE_OF_OPTION_DEFAULT_MFG = 0x20
# Value width by EFI_IFR_TYPE_NUM_SIZE_8..64; other types are read as one byte.
_OPTION_VALUE_WIDTH = {0: 1, 1: 2, 2: 4, 3: 8}

_LANGUAGE_EN_US = re.compile(rb"en-US\x00")
# FORM_SET opcode with the scope bit set and length >= 0x18.
_FORM_SET_HEADER = re.compile(rb"\x0e[\x98-\xff]")
_UTF16_TEXT = re.compile(rb"((?:[\x20-\x7e]\x00){4,})\x00\x00")


def hex_int(text: str) -> int:
    """argparse type for hex numbers, with or without a 0x prefix."""
    return int(text, 16)


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def package_length(seg: bytes, offset: int) -> int:
    """The 24-bit length field of the HII package header at `offset`."""
    return int.from_bytes(seg[offset : offset + 3], "little")


def ui_name(image: bytes, base: int, size: int) -> str:
    """Best-effort module name: the first UTF-16 string after the module."""
    m = _UTF16_TEXT.search(image[base + size : base + size + 0x200])
    return m.group(1).decode("utf-16-le") if m else "?"


class StringPackage(NamedTuple):
    offset: int
    strings: dict[int, str]  # string id -> text


def find_string_packages(seg: bytes) -> list[StringPackage]:
    """Find en-US HII string packages in `seg` and decode their strings."""
    packages = []
    for m in _LANGUAGE_EN_US.finditer(seg):
        start = m.start() - STRING_PACKAGE_FIXED_HEADER
        if start < 0 or seg[start + 3] != PACKAGE_TYPE_STRINGS:
            continue
        header_size, string_info_offset = struct.unpack_from("<II", seg, start + 4)
        if header_size < STRING_PACKAGE_FIXED_HEADER:
            continue
        end = start + package_length(seg, start)
        packages.append(StringPackage(start, _parse_string_blocks(seg, start + string_info_offset, end)))
    return packages


def largest_string_table(seg: bytes) -> dict[int, str] | None:
    """The strings of the en-US package with the most strings (first on ties), else None."""
    best = max(find_string_packages(seg), key=lambda pkg: len(pkg.strings), default=None)
    return best.strings if best is not None else None


def _parse_string_blocks(seg: bytes, pos: int, end: int) -> dict[int, str]:
    """Decode UCS-2 string blocks, stopping at SIBT_END or an unsupported block type."""
    strings = {}
    string_id = 1
    while pos < end:
        block_type = seg[pos]
        if block_type == SIBT_END:
            break
        if block_type == SIBT_STRING_UCS2:
            text_end = pos + 1
            while seg[text_end : text_end + 2] != b"\0\0":
                text_end += 2
            strings[string_id] = seg[pos + 1 : text_end].decode("utf-16-le", "replace")
            string_id += 1
            pos = text_end + 2
        elif block_type == SIBT_SKIP2:
            string_id += _u16(seg, pos + 1)
            pos += 3
        elif block_type == SIBT_SKIP1:
            string_id += seg[pos + 1]
            pos += 2
        elif block_type == SIBT_DUPLICATE:
            string_id += 1
            pos += 3
        elif block_type == SIBT_EXT1:
            pos += seg[pos + 2]
        elif block_type == SIBT_EXT2:
            pos += _u16(seg, pos + 2)
        elif block_type == SIBT_EXT4:
            pos += struct.unpack_from("<I", seg, pos + 2)[0]
        else:
            break
    return strings


def find_form_packages(seg: bytes) -> list[tuple[int, int]]:
    """(offset, length) of each HII form package in `seg` that starts with a FORM_SET."""
    packages = []
    for m in _FORM_SET_HEADER.finditer(seg):
        start = m.start() - PACKAGE_HEADER_SIZE
        if start < 0 or seg[start + 3] != PACKAGE_TYPE_FORMS:
            continue
        length = package_length(seg, start)
        if length < 0x40 or start + length > len(seg):
            continue
        packages.append((start, length))
    return packages


class Opcode(NamedTuple):
    offset: int
    code: int
    length: int
    opens_scope: bool


def iter_opcodes(seg: bytes, package_offset: int, package_length: int) -> Iterator[Opcode]:
    """Walk the IFR opcodes of a form package, stopping at a zero-length opcode."""
    pos = package_offset + PACKAGE_HEADER_SIZE
    while pos < package_offset + package_length:
        length = seg[pos + 1] & 0x7f
        if length == 0:
            return
        yield Opcode(pos, seg[pos], length, bool(seg[pos + 1] >> 7))
        pos += length


class Question(NamedTuple):
    prompt: int
    help: int
    question_id: int
    varstore_id: int
    varstore_offset: int
    flags: int


def parse_question(seg: bytes, pos: int) -> Question:
    """The statement and question header of a question opcode at `pos`."""
    prompt, help_, question_id, varstore_id, varstore_offset = struct.unpack_from("<HHHHH", seg, pos + 2)
    return Question(prompt, help_, question_id, varstore_id, varstore_offset, flags=seg[pos + 12])


class Option(NamedTuple):
    string_id: int
    flags: int
    value: int


def parse_option(seg: bytes, op: Opcode) -> Option:
    string_id, flags, value_type = struct.unpack_from("<HBB", seg, op.offset + 2)
    width = _OPTION_VALUE_WIDTH.get(value_type, 1)
    value = int.from_bytes(seg[op.offset + 6 : op.offset + op.length][:width], "little")
    return Option(string_id, flags, value)


def parse_varstore(seg: bytes, op: Opcode) -> tuple[int, str]:
    """(varstore id, name) of a VARSTORE or VARSTORE_EFI opcode."""
    id_at, name_at = (18, 22) if op.code == OP_VARSTORE else (2, 28)
    varstore_id = _u16(seg, op.offset + id_at)
    name = seg[op.offset + name_at : op.offset + op.length].split(b"\0")[0].decode()
    return varstore_id, name


def parse_default_value(seg: bytes, op: Opcode) -> int:
    return int.from_bytes(seg[op.offset + 5 : op.offset + op.length], "little")


def find_questions(
    seg: bytes, package_offset: int, package_length: int, strings: dict[int, str], wanted: list[str]
) -> tuple[dict[int, str], list[str]]:
    """Describe the questions whose prompt contains any of `wanted`.

    Returns the package's varstores (id -> name) and the description lines.
    """
    varstores: dict[int, str] = {}
    lines = []
    in_wanted_question = False
    for op in iter_opcodes(seg, package_offset, package_length):
        if op.code in VARSTORE_OPS:
            varstore_id, name = parse_varstore(seg, op)
            varstores[varstore_id] = name
        elif op.code in QUESTION_OPS:
            q = parse_question(seg, op.offset)
            prompt = strings.get(q.prompt, f"#{q.prompt}")
            in_wanted_question = any(w in prompt for w in wanted)
            if in_wanted_question:
                kind = IFR_OPCODE_NAMES[op.code].lower()
                varstore = varstores.get(q.varstore_id, q.varstore_id)
                lines.append(
                    f'  {kind} "{prompt}" varstore={varstore} off=0x{q.varstore_offset:x}'
                    f" qid={q.question_id} flags=0x{q.flags:02x}"
                )
        elif op.code == OP_ONE_OF_OPTION and in_wanted_question:
            opt = parse_option(seg, op)
            default = " [DEFAULT]" if opt.flags & ONE_OF_OPTION_DEFAULT else ""
            mfg = " [MFG]" if opt.flags & ONE_OF_OPTION_DEFAULT_MFG else ""
            lines.append(f'      opt "{strings.get(opt.string_id, opt.string_id)}" = {opt.value}{default}{mfg}')
        elif op.code == OP_DEFAULT and in_wanted_question:
            default_id = _u16(seg, op.offset + 2)
            lines.append(f"      default(store {default_id}) = {parse_default_value(seg, op)}")
    return varstores, lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="firmware image (bios/t3.bin)")
    parser.add_argument("names", help="'|'-separated substrings of question prompts")
    args = parser.parse_args()

    with open(args.image, "rb") as f:
        image = f.read()
    wanted = args.names.split("|")

    for base, size in HII_MODULES:
        seg = image[base : base + size]
        print("=== module", hex(base), ui_name(image, base, size))
        strings = largest_string_table(seg)
        if strings is None:
            print(" no strings")
            continue
        for offset, length in find_form_packages(seg):
            varstores, lines = find_questions(seg, offset, length, strings, wanted)
            print(f" formpkg@{hex(offset)} len={hex(length)} varstores={varstores}")
            print("\n".join(lines))


if __name__ == "__main__":
    main()
