"""Locate the firmware module enclosing a file offset (library, no CLI)."""

import re
import struct
from collections.abc import Iterator

_PE_SEARCH_WINDOW = 0x400000
_TE_SEARCH_WINDOW = 0x100000
_E_LFANEW = 0x3C
_MAX_E_LFANEW = 0x1000
_PE_SIZE_OF_IMAGE = 0x50  # relative to the "PE\0\0" signature

_UTF16_IDENTIFIER = re.compile(rb"((?:[A-Za-z0-9_]\x00){4,})\x00\x00")


def _rfind_all(data: bytes, needle: bytes, lo: int, hi: int) -> Iterator[int]:
    """Offsets of `needle` within data[lo:hi], nearest to `hi` first."""
    pos = data.rfind(needle, lo, hi)
    while pos != -1:
        yield pos
        pos = data.rfind(needle, lo, pos)


def enclosing_image(data: bytes, offset: int) -> tuple[int, int | None] | None:
    """(start, SizeOfImage) of the nearest preceding PE image that covers `offset`.

    If no PE image covers it, falls back to the nearest preceding TE image
    ("VZ", used by PEI modules) as (start, None), without checking that it
    covers `offset`. Returns None if neither is found.
    """
    for start in _rfind_all(data, b"MZ", max(0, offset - _PE_SEARCH_WINDOW), offset):
        try:
            e_lfanew = struct.unpack_from("<I", data, start + _E_LFANEW)[0]
            pe = start + e_lfanew
            if e_lfanew < _MAX_E_LFANEW and data[pe : pe + 4] == b"PE\0\0":
                size = struct.unpack_from("<I", data, pe + _PE_SIZE_OF_IMAGE)[0]
                if start <= offset < start + size:
                    return start, size
        except struct.error:
            pass

    te_start = next(_rfind_all(data, b"VZ", max(0, offset - _TE_SEARCH_WINDOW), offset), None)
    return (te_start, None) if te_start is not None else None


def ui_name(data: bytes, base: int, size: int | None) -> str:
    """Best-effort module name: the first UTF-16 identifier after the image.

    A module's FFS user-interface section usually follows its image. With no
    size (TE images), searches the 256 KiB starting at `base`.
    """
    window = data[base + size : base + size + 0x400] if size else data[base : base + 0x40000]
    m = _UTF16_IDENTIFIER.search(window)
    return m.group(1).decode("utf-16-le") if m else "?"
