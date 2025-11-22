"""
linuxExtract.py 

Author: RitchieHollis
Date: 2025-11-22

Refactored for REVcore integration

Script focused on the header section of ELF format files

Returns:
{
    "header_status": "success" || "error",
    "header": {
        "entry_point": entry_point in hex string (e.g. "0x401000"),
        "header_num": number of section headers (e_shnum) in uint,
        "elf_class": "ELF32" | "ELF64" | "Unknown",
        "endian": "little" | "big" | "Unknown",
        "os_abi": OS/ABI field from e_ident[7] in uint,
        "abi_version": ABI version from e_ident[8] in uint,
        "type": "relocatable" | "executable" | "shared" | "core" | "unknown",
        "program_header_count": e_phnum in uint,
        "section_header_count": e_shnum in uint,
        "program_header_offset": e_phoff in uint,
        "section_header_offset": e_shoff in uint,
        "program_header_entry_size": e_phentsize in uint,
        "section_header_entry_size": e_shentsize in uint
    }
}
"""

from misc import LNX_ARCH_MAP, LNX_EI_CLASS, LNX_EI_DATA, LNX_OSABI_MAP, LNX_ET_TYPE
import struct

def linux_headers(file):
    """
    Public entry point used by headerExtract.parse_header()

    On success:
        {"header_status": "success", "header": {...}}

    On error:
        {"header_status": "error", "reason": "<msg>"}
    """
    try:
        elf_class, endian, os_abi, abi_ver, endian_fmt, ei_class = _read_ident(file)

        if ei_class == 1:  # ELF32
            info = _read_header32(file, endian_fmt)
        else:              # ELF64 (or unknown → treat as 64-bit layout)
            info = _read_header64(file, endian_fmt)

        e_type = info.pop("e_type")
        header = {
            "entry_point": f"0x{info['entry_point']:X}",
            "header_num": info["section_header_count"],
            "elf_class": elf_class,
            "endian": endian,
            "os_abi": os_abi,
            "abi_version": abi_ver,
            "type": _etype_to_str(e_type),
            "program_header_count": info["program_header_count"],
            "section_header_count": info["section_header_count"],
            "program_header_offset": info["program_header_offset"],
            "section_header_offset": info["section_header_offset"],
            "program_header_entry_size": info["program_header_entry_size"],
            "section_header_entry_size": info["section_header_entry_size"],
        }

        return {"header_status": "success", "header": header}

    except Exception as e:
        return {"header_status": "error", "reason": str(e)}

def _read_ident(file):
    """Read and validate ELF ident block; return (class, endian, os_abi, abi_ver, endian_fmt)"""
    file.seek(0)
    e_ident = file.read(16)
    if len(e_ident) < 16 or not e_ident.startswith(b"\x7FELF"):
        raise ValueError("Invalid ELF magic")

    ei_class = e_ident[4]
    ei_data  = e_ident[5]
    ei_osabi = e_ident[7]
    ei_abiver = e_ident[8]

    elf_class = LNX_EI_CLASS.get(ei_class, f"Unknown ({ei_class})")
    endian    = LNX_EI_DATA.get(ei_data, "Unknown")
    endian_fmt = "<" if ei_data in (0, 1) else ">"  #default to little if invalid

    os_abi_str = LNX_OSABI_MAP.get(ei_osabi, f"Unknown ({ei_osabi})")

    return elf_class, endian, os_abi_str, ei_abiver, endian_fmt, ei_class

def _etype_to_str(e_type: int) -> str:
    return LNX_ET_TYPE.get(e_type, f"unknown ({e_type})")

def _read_header32(file, endian_fmt: str):
    """
    Read ELF32 header fields starting from offset 0x10

    Returns a dict with the parsed fields
    """
    file.seek(0x10)

    # e_type, e_machine, e_version (we ignore e_machine/e_version here)
    e_type, e_machine = struct.unpack(endian_fmt + "HH", file.read(4))
    file.read(4)  # e_version

    # e_entry, e_phoff, e_shoff
    entry_point, phoff, shoff = struct.unpack(endian_fmt + "III", file.read(12))

    # e_flags
    e_flags = struct.unpack(endian_fmt + "I", file.read(4))[0]

    # e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(
        endian_fmt + "HHHHHH", file.read(12)
    )

    return {
        "e_type": e_type,
        "entry_point": entry_point,
        "program_header_offset": phoff,
        "section_header_offset": shoff,
        "program_header_entry_size": phentsize,
        "section_header_entry_size": shentsize,
        "program_header_count": phnum,
        "section_header_count": shnum,
    }


def _read_header64(file, endian_fmt: str):
    """
    Read ELF64 header fields starting from offset 0x10

    Returns a dict with the parsed fields
    """
    file.seek(0x10)

    e_type, e_machine = struct.unpack(endian_fmt + "HH", file.read(4))
    file.read(4)  # e_version

    entry_point = struct.unpack(endian_fmt + "Q", file.read(8))[0]
    phoff = struct.unpack(endian_fmt + "Q", file.read(8))[0]
    shoff = struct.unpack(endian_fmt + "Q", file.read(8))[0]

    e_flags = struct.unpack(endian_fmt + "I", file.read(4))[0]

    ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(
        endian_fmt + "HHHHHH", file.read(12)
    )

    return {
        "e_type": e_type,
        "entry_point": entry_point,
        "program_header_offset": phoff,
        "section_header_offset": shoff,
        "program_header_entry_size": phentsize,
        "section_header_entry_size": shentsize,
        "program_header_count": phnum,
        "section_header_count": shnum,
    }
