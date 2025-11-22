"""
Name: headerExtract
Date: 2025-11-22

Refactored for REVcore integration

Script focused on the header section of PE format file

Returns: 
{
    "header_status": "succes" || "error",
    "header": 
    {
        "major_linker": major_linker_version in uint,
        "minor_linker": minor_linker_version in uint,
        "entry_point": entry_point in hex,
        "valid_entry_point": entry_point_correct in boolean,
        "header_num": num_sections in uint,
        "timestamp": timestamp in UTC,
        "os_version": os_version in x.x,
        "subsystem": subsystem in string,
        "subsystem_version": subsystem_version in x.x,
        "checksum": checksum in uint,
        "size_of_image": size_of_image in bytes,
        "loader_flags": loader_flags in uint,
        "dll_characteristics": dllchar in list,
        "data_directories" in json {
                                    "rva", 
                                    "size"
                                    } 
        "certificate_table": certificate_table
    }
}
"""

from misc import PE_HEADER_OFFSET, Enum, struct, WindowsSubsystem, format_timestamp, parse_certificate_table, validate_entry_point

def windows_headers(file):
    """Analyses a Windows PE file and extract header information.
    Returns a dict with 'header_status' and 'header' or an error
    """
    try:
        base = _get_pe_header_pointer(file)
        pe_signature = _get_signature(file, base)

        if pe_signature != b"PE\0\0":
            return {"header_status": "error", "reason": "Invalid PE signature"}

        num_sections, timestamp, size_opt = _get_coff_header(file, base)
        opt_info = _get_optional_header(file, base, size_opt)

        sections_info = _get_section_info(file, base, size_opt, num_sections, opt_info.get("entry_point"))
        dirs = _get_data_directories(file, base)
        cert      = _get_certificate(file, dirs[4])

        header = {
            **opt_info,
            **sections_info,
            "timestamp": format_timestamp(timestamp),
            "data_directories": dirs,
            "certificate_table": cert,
        }

        return {"header_status": "success", "header": header}

    except Exception as e:
        return {"header_status": "error", "reason": str(e)}

# ---Helper functions------------------------------------------------

def _get_pe_header_pointer(f):
    f.seek(PE_HEADER_OFFSET)
    return struct.unpack("<I", f.read(4))[0]

def _get_signature(f, base):
    f.seek(base)
    return f.read(4)

def _get_coff_header(f, base):
    """Return (num_sections, timestamp, size_opt)."""
    coff_offset = base + 4  #skip "PE\0\0"
    f.seek(coff_offset)

    # IMAGE_FILE_HEADER layout:
    # WORD  Machine;
    # WORD  NumberOfSections;
    # DWORD TimeDateStamp;
    # DWORD PointerToSymbolTable;
    # DWORD NumberOfSymbols;
    # WORD  SizeOfOptionalHeader;
    # WORD  Characteristics;
    machine       = struct.unpack("<H", f.read(2))[0] 
    num_sec       = struct.unpack("<H", f.read(2))[0]
    timestamp     = struct.unpack("<I", f.read(4))[0]

    f.seek(coff_offset + 16)
    size_opt      = struct.unpack("<H", f.read(2))[0]

    return num_sec, timestamp, size_opt

def _get_optional_header(f, base, size_opt):
    # Optional header start: 4 (signature) + 20 (COFF)
    opt_offset = base + 24
    f.seek(opt_offset)
    data = f.read(size_opt)

    major_linker = data[2]
    minor_linker = data[3]

    # AddressOfEntryPoint at 0x10
    entry_point  = struct.unpack_from("<I", data, 0x10)[0]

    # OS version at 0x40 / 0x42
    os_maj = struct.unpack_from("<H", data, 0x40)[0]
    os_min = struct.unpack_from("<H", data, 0x42)[0]
    os_version = f"{os_maj}.{os_min}"

    # Subsystem version at 0x48 / 0x4A
    sub_maj = struct.unpack_from("<H", data, 0x48)[0]
    sub_min = struct.unpack_from("<H", data, 0x4A)[0]
    subsystem_version = f"{sub_maj}.{sub_min}"

    # SizeOfImage and CheckSum at 0x50 / 0x58
    size_of_image = struct.unpack_from("<I", data, 0x50)[0]
    checksum      = struct.unpack_from("<I", data, 0x58)[0]

    # Subsystem and DllCharacteristics at 0x5C / 0x5E
    subsystem_raw = struct.unpack_from("<H", data, 0x5C)[0]
    try:
        subsystem = WindowsSubsystem(subsystem_raw).name
    except ValueError:
        subsystem = f"Unknown ({subsystem_raw})"

    dll_chars = struct.unpack_from("<H", data, 0x5E)[0]
    dll_list = []
    if dll_chars & 0x0020: dll_list.append("ASLR with 64 bit address space")
    if dll_chars & 0x0040: dll_list.append("Dynamic base")
    if dll_chars & 0x0080: dll_list.append("Force integrity")
    if dll_chars & 0x0100: dll_list.append("NX Compat")
    if dll_chars & 0x0200: dll_list.append("No Isolation")
    if dll_chars & 0x0400: dll_list.append("No SEH")
    if dll_chars & 0x0800: dll_list.append("No bind")
    if dll_chars & 0x1000: dll_list.append("App container")
    if dll_chars & 0x2000: dll_list.append("WDM Driver")
    if dll_chars & 0x4000: dll_list.append("Control flow guard")
    if dll_chars & 0x8000: dll_list.append("Terminal server aware")

    # LoaderFlags at 0x70 (almost always 0, but good to expose)
    loader_flags = struct.unpack_from("<I", data, 0x70)[0]

    return {
        "major_linker": major_linker,
        "minor_linker": minor_linker,
        # nicer hex with 0x prefix – still works with int(va, 16)
        "entry_point": f"0x{entry_point:08X}",
        "os_version": os_version,
        "subsystem": subsystem,
        "subsystem_version": subsystem_version,
        "checksum": checksum,
        "size_of_image": size_of_image,
        "loader_flags": loader_flags,
        "dll_characteristics": dll_list,
    }

def _get_section_info(f, base, size_opt, num_sections, va):
    valid = validate_entry_point(f, int(va,16), base, size_opt, num_sections)
    return {"valid_entry_point": valid, "header_num": num_sections}

def _get_data_directories(f, base: int):
    #Data directories start 120 bytes after the PE header
    dirs = []
    offset = base + 120
    for _ in range(16):
        f.seek(offset)
        rva, size = struct.unpack("<II", f.read(8))
        dirs.append({"rva": hex(rva), "size": size})
        offset += 8
    return dirs

def _get_certificate(f, dir_entry):
    rva = int(dir_entry["rva"], 16)
    size = dir_entry["size"]
    if rva == 0 or size == 0:
        return None
    return parse_certificate_table(f, rva, size)