"""Condensed summary of a DXE module's functions.

Lists, per function, its calls (resolving gBS/gRT service calls), string
references, large immediates, and accesses to the AmdSetup memory-speed
bytes.
"""

import argparse

from capstone import CsInsn
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RAX,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RIP,
    X86_REG_RSP,
)

import fwdis
from fwdis import PeImage

# EFI_SYSTEM_TABLE field offsets.
SYSTEM_TABLE_RUNTIME_SERVICES = 0x58
SYSTEM_TABLE_BOOT_SERVICES = 0x60

BOOT_SERVICES = {
    0x28: "AllocatePages",
    0x40: "AllocatePool",
    0x48: "FreePool",
    0x50: "CreateEvent",
    0x68: "SignalEvent",
    0x70: "CloseEvent",
    0x98: "HandleProtocol",
    0xA8: "RegisterProtocolNotify",
    0xB0: "LocateHandle",
    0x138: "LocateHandleBuffer",
    0x140: "LocateProtocol",
    0x148: "InstallMultipleProtocolInterfaces",
    0x170: "CreateEventEx",
}
RUNTIME_SERVICES = {
    0x48: "GetVariable",
    0x50: "GetNextVariableName",
    0x58: "SetVariable",
    0x68: "ResetSystem",
}
SERVICE_TABLES = {"gBS": BOOT_SERVICES, "gRT": RUNTIME_SERVICES}

# AmdSetup bytes that routecfg writes: timing mode and target speed.
AMDSETUP_SPEED_OFFSETS = (0x58, 0x59)

_SYSTEM_TABLE_REGISTERS = (X86_REG_RDX, X86_REG_RCX, X86_REG_RAX)


def find_service_globals(pe: PeImage) -> dict[int, str]:
    """Find the gBS/gRT globals, mapping their RVAs to "gBS"/"gRT".

    Matches `mov reg, [SystemTable+0x58/0x60]` followed later in the same
    function by `mov [rip+X], reg`.
    """
    md = fwdis.disassembler()
    found: dict[int, str] = {}
    for start, end in fwdis.find_functions(pe):
        loaded: tuple[int, int] | None = None  # (register, system-table field)
        for ins in md.disasm(pe.image[start:end], start):
            if ins.mnemonic != "mov" or ins.op_count(X86_OP_MEM) != 1:
                continue
            dest, src = ins.operands
            if (
                src.type == X86_OP_MEM
                and src.mem.base in _SYSTEM_TABLE_REGISTERS
                and src.mem.disp in (SYSTEM_TABLE_RUNTIME_SERVICES, SYSTEM_TABLE_BOOT_SERVICES)
                and dest.type == X86_OP_REG
            ):
                loaded = (dest.reg, src.mem.disp)
            elif (
                dest.type == X86_OP_MEM
                and dest.mem.base == X86_REG_RIP
                and loaded
                and src.type == X86_OP_REG
                and src.reg == loaded[0]
            ):
                global_rva = ins.address + ins.size + dest.mem.disp
                found[global_rva] = "gRT" if loaded[1] == SYSTEM_TABLE_RUNTIME_SERVICES else "gBS"
                loaded = None
    return found


def _call_target(ins: CsInsn, table_for_reg: dict[int, str]) -> str | None:
    op = ins.operands[0]
    if op.type == X86_OP_MEM and op.mem.base in table_for_reg:
        table = table_for_reg[op.mem.base]
        service = SERVICE_TABLES[table].get(op.mem.disp, hex(op.mem.disp))
        return f"{table}->{service}"
    if op.type == X86_OP_MEM:
        base = ins.reg_name(op.mem.base) if op.mem.base else "rip"
        return f"indirect [{base}+{op.mem.disp:#x}]"
    if op.type == X86_OP_IMM:
        return f"sub_{op.imm:x}"
    return None


def _has_large_immediate(ins: CsInsn) -> bool:
    return ins.mnemonic in ("mov", "cmp", "and", "or") and any(
        op.type == X86_OP_IMM and op.imm > 0xFFFF and op.imm & 0xFFFFFFFF != 0xFFFFFFFF
        for op in ins.operands
    )


def _touches_speed_offsets(ins: CsInsn) -> bool:
    return ins.mnemonic in ("mov", "movzx", "cmp") and any(
        op.type == X86_OP_MEM
        and op.mem.disp in AMDSETUP_SPEED_OFFSETS
        and op.mem.base not in (X86_REG_RSP, X86_REG_RIP)
        for op in ins.operands
    )


def summarize_function(
    pe: PeImage, start: int, end: int, service_globals: dict[int, str]
) -> list[str]:
    table_for_reg: dict[int, str] = {}  # register -> "gBS"/"gRT" last loaded into it
    lines = []
    for ins in fwdis.disassembler().disasm(pe.image[start:end], start):
        comment = ""
        for op in ins.operands:
            target = fwdis.rip_target(ins, op)
            if target is None:
                continue
            dest = ins.operands[0]
            if target in service_globals and ins.mnemonic == "mov" and dest.type == X86_OP_REG:
                table_for_reg[dest.reg] = service_globals[target]
            comment = fwdis.string_label(pe, target) or comment

        if ins.mnemonic == "call":
            lines.append(f"  {ins.address:6x}: CALL {_call_target(ins, table_for_reg) or comment}")
        elif comment:
            lines.append(f"  {ins.address:6x}: {ins.mnemonic} {ins.op_str}  ; {comment}")
        elif _has_large_immediate(ins):
            lines.append(f"  {ins.address:6x}: {ins.mnemonic} {ins.op_str}")
        elif _touches_speed_offsets(ins):
            lines.append(f"  {ins.address:6x}: {ins.mnemonic} {ins.op_str}   <-- off 0x58/0x59")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workdir", help="extraction directory containing bios/lz/b1.bin")
    parser.add_argument("base", type=fwdis.hex_int, help="module offset in b1.bin (hex)")
    parser.add_argument("lo", type=fwdis.hex_int, nargs="?", help="only functions starting at or after this RVA (hex)")
    parser.add_argument("hi", type=fwdis.hex_int, nargs="?", help="only functions starting before this RVA (hex)")
    args = parser.parse_args()
    if (args.lo is None) != (args.hi is None):
        parser.error("give both lo and hi, or neither")

    pe = PeImage(fwdis.load_dxe_volume(args.workdir), args.base)
    service_globals = find_service_globals(pe)
    print("globals", {hex(k): v for k, v in service_globals.items()})

    lo, hi = (args.lo, args.hi) if args.hi is not None else (0, pe.size)
    for start, end in fwdis.find_functions(pe):
        if not lo <= start < hi:
            continue
        lines = summarize_function(pe, start, end, service_globals)
        if lines:
            print(f"\n== func {start:#x}-{end:#x}")
            print("\n".join(lines))


if __name__ == "__main__":
    main()
