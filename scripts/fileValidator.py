"""
fileValidator.py

Author: RitchieHollis
Date: 2025-11-22

Refactored for REVcore integration

Given a file path, detect its type, architecture, and header information
and return a single JSON-friendly dict that REVcore can consume.

High-level JSON contract
------------------------
On success:
{
    "status": "success",
    "file_info": {
        "path": "<absolute or given path>",
        "type": "<human readable type, e.g. 'PE (Portable Executable)'>",
        "architecture": "<human readable arch, e.g. 'x86-64'>",
        "format": "PE" | "ELF" | "Mach-O" | "Unknown",
        "magic_number": "<hex-encoded leading bytes>"
        "header_status": "success",
        "header_info": {
            "status": "success" | "error" | "unsupported",
            "data": { ... format-specific header fields ... } | null,
            "reason": "<optional, present when status != 'success'>"
            "data_directories": { ... },
            "certificate_table": {
            "length": 1234,
            "revision": 512,
            "type": 2
        }
    }
}

On error:
{
    "status": "error",
    "reason": "<human readable error>",
    "file_info": null,
    "header_info": null
}
"""

from headerExtract import parse_header
from misc import FILE_TYPES, PE_HEADER_OFFSET, WIN_ARCH_MAP, MAC_ARCH_MAP, LNX_ARCH_MAP
import json
import os
import struct
from typing import Tuple, Optional, Dict, Any

def _error(reason: str) -> Dict[str, Any]:
    """Build a top-level error response for REVcore"""
    return {
        "status": "error",
        "reason": reason,
        "file_info": None,
        "header_info": None,
    }


def check_file_exists(file_path: str) -> Tuple[bool, Optional[str]]:
    """Check if the file exists and is readable"""
    if not os.path.isfile(file_path):
        return False, "File not found"
    if not os.access(file_path, os.R_OK):
        return False, "File is not readable"
    return True, None


def stream_magic_number(file, byte_count: int = 4) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """
    Read the first `byte_count` bytes (magic number) of the file

    Returns:
        (ok, magic_bytes | None, error_reason | None)
    """
    try:
        magic = file.read(byte_count)
        if len(magic) < byte_count:
            return False, None, "File too small to contain a valid magic number"
        return True, magic, None
    except Exception as e:
        return False, None, f"Failed to read file: {str(e)}"


def identify_file_type(magic_number: bytes) -> str:
    """Identify the file type based on the magic number"""
    for key, ftype in FILE_TYPES.items():
        if key.startswith(magic_number) or magic_number.startswith(key):
            return ftype
    return "Unknown"


def identify_architecture(file, file_type: str) -> str:
    """Identify the architecture based on the file type"""
    try:
        if file_type == "PE (Portable Executable)":
            file.seek(PE_HEADER_OFFSET)  # PE header offset
            pe_header_offset = struct.unpack("<I", file.read(4))[0]
            file.seek(pe_header_offset + 4)  # Machine field in COFF header
            machine = struct.unpack("<H", file.read(2))[0]
            return WIN_ARCH_MAP.get(machine, "Unknown Architecture")

        elif file_type == "ELF (Executable and Linkable Format)":
            file.seek(18)  # e_machine field in ELF header
            e_machine = struct.unpack("<H", file.read(2))[0]
            return LNX_ARCH_MAP.get(e_machine, "Unknown Architecture")

        elif file_type.startswith("Mach-O"):
            file.seek(4)  # cputype field in Mach-O header
            cputype = struct.unpack("<I", file.read(4))[0]
            return MAC_ARCH_MAP.get(cputype, "Unknown Architecture")

    except Exception as e:
        return f"Error identifying architecture: {str(e)}"

    return "Unsupported File Type"


def _normalize_format_tag(file_type: str) -> str:
    """Map the human-readable file_type string to a short format tag"""
    if file_type.startswith("PE "):
        return "PE"
    if file_type.startswith("ELF "):
        return "ELF"
    if file_type.startswith("Mach-O"):
        return "Mach-O"
    return "Unknown"


def file_validation(file_path: str) -> Dict[str, Any]:
    """
    Main function to validate the file and build a JSON-friendly dict

    This is the function REVcore should call (via subprocess) and then
    JSON-encode the returned value
    """
    exists, reason = check_file_exists(file_path)
    if not exists:
        return _error(reason or "File check failed")

    try:
        with open(file_path, "rb") as file:
            # Step 1: stream magic number
            ok, magic_bytes, magic_err = stream_magic_number(file)
            if not ok or magic_bytes is None:
                return _error(magic_err or "Could not read magic number")

            file_type = identify_file_type(magic_bytes)

            architecture = identify_architecture(file, file_type)

            raw_header = parse_header(file, file_type)
            # raw_header is expected to be {"header_status": "...", "header": {...}} or error-json

            header_status = raw_header.get("header_status", "error")
            header_reason = raw_header.get("reason")
            header_data = raw_header.get("header")

            header_info = {
                "status": header_status if header_status in ("success", "error") else "error",
                "format": _normalize_format_tag(file_type),
                "data": header_data if header_status == "success" else None,
            }
            if header_status != "success" and header_reason:
                header_info["reason"] = header_reason

            file_info = {
                "path": file_path,
                "type": file_type,
                "architecture": architecture,
                "magic_number": magic_bytes.hex(),
            }

            return {
                "status": "success",
                "file_info": file_info,
                "header_info": header_info,
            }

    except Exception as e:
        return _error(f"Failed to process file: {str(e)}")

# Local testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 fileValidator.py <path-to-file>")
        sys.exit(1)

    path = sys.argv[1]
    result = file_validation(path)
    print(json.dumps(result, indent=4))
