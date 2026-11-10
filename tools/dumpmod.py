"""Disassemble the functions of a DXE module that reference given UTF-16 strings."""

import argparse
import re

import fwdis
from fwdis import PeImage

_UTF16_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){3,}\x00\x00")


def utf16_strings(image: bytes) -> dict[int, str]:
    """Map the RVA of every printable NUL-terminated UTF-16LE string (3+ chars) to its text."""
    return {m.start(): m.group()[:-2].decode("utf-16-le") for m in _UTF16_STRING.finditer(image)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workdir", help="extraction directory containing bios/lz/b1.bin")
    parser.add_argument("base", type=fwdis.hex_int, help="module offset in b1.bin (hex)")
    parser.add_argument("names", help="comma-separated strings, matched exactly")
    args = parser.parse_args()

    pe = PeImage(fwdis.load_dxe_volume(args.workdir), args.base)
    names = args.names.split(",")
    targets = {rva: text for rva, text in utf16_strings(pe.image).items() if text in names}
    print("size", hex(pe.size), "entry", hex(pe.entry), "targets", {hex(k): v for k, v in targets.items()})

    for (start, end), refs in sorted(fwdis.functions_referencing(pe, targets).items()):
        print(f"\n==== func {start:#x}-{end:#x} refs {sorted(refs)}")
        print("\n".join(fwdis.disassemble(pe, start, end)))


if __name__ == "__main__":
    main()
