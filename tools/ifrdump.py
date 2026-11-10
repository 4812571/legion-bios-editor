"""Dump one HII form package as an indented opcode tree.

Nesting follows IFR scopes, so suppressif/grayoutif conditions appear above
the statements they apply to.
"""

import argparse
import io
import struct
import sys

import ifr
from ifr import Opcode


def describe(seg: bytes, op: Opcode, strings: dict[int, str], varstores: dict[int, str]) -> str:
    """The operand summary printed after the opcode name ("" if none)."""
    pos = op.offset
    if op.code == ifr.OP_FORM:
        form_id, title = struct.unpack_from("<HH", seg, pos + 2)
        return f'id={form_id} "{strings.get(title)}"'
    if op.code in (ifr.OP_SUBTITLE, ifr.OP_TEXT):
        prompt = struct.unpack_from("<H", seg, pos + 2)[0]
        return f'"{strings.get(prompt)}"'
    if op.code in (*ifr.QUESTION_OPS, ifr.OP_REF):
        q = ifr.parse_question(seg, pos)
        varstore = varstores.get(q.varstore_id, q.varstore_id)
        text = f'"{strings.get(q.prompt)}" qid={q.question_id} vs={varstore} off=0x{q.varstore_offset:x}'
        if op.code == ifr.OP_REF and op.length >= 17:
            text += f" -> form {struct.unpack_from('<H', seg, pos + 15)[0]}"
        return text
    if op.code == ifr.OP_EQ_ID_VAL:
        question_id, value = struct.unpack_from("<HH", seg, pos + 2)
        return f"q{question_id} == {value}"
    if op.code == ifr.OP_EQ_ID_VAL_LIST:
        question_id, count = struct.unpack_from("<HH", seg, pos + 2)
        return f"q{question_id} in {list(struct.unpack_from(f'<{count}H', seg, pos + 6))}"
    if op.code == ifr.OP_EQ_ID_ID:
        left, right = struct.unpack_from("<HH", seg, pos + 2)
        return f"q{left} == q{right}"
    if op.code == ifr.OP_ONE_OF_OPTION:
        opt = ifr.parse_option(seg, op)
        return f'"{strings.get(opt.string_id)}"={opt.value} fl=0x{opt.flags:x}'
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="firmware image (bios/t3.bin)")
    parser.add_argument("module", type=int, help="index into ifr.HII_MODULES")
    parser.add_argument(
        "form", type=ifr.hex_int, help="form package offset within the module (hex), as printed by ifr.py"
    )
    args = parser.parse_args()
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")

    with open(args.image, "rb") as f:
        image = f.read()
    base, size = ifr.HII_MODULES[args.module]
    seg = image[base : base + size]
    strings = ifr.largest_string_table(seg)
    if strings is None:
        sys.exit(f"no en-US string package in module {args.module}")

    varstores: dict[int, str] = {}
    depth = 0
    for op in ifr.iter_opcodes(seg, args.form, ifr.package_length(seg, args.form)):
        if op.code in ifr.VARSTORE_OPS:
            varstore_id, name = ifr.parse_varstore(seg, op)
            varstores[varstore_id] = name
            detail = f"{varstore_id}={name}"
        else:
            detail = describe(seg, op, strings, varstores)

        if op.code == ifr.OP_END:
            depth = max(0, depth - 1)
        elif op.code != ifr.OP_DEFAULT:
            name = ifr.IFR_OPCODE_NAMES.get(op.code, hex(op.code))
            print(f"{'  ' * depth}{name} {detail}")
        if op.opens_scope:
            depth += 1


if __name__ == "__main__":
    main()
