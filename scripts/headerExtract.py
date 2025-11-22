"""
headerExtract.py

Author: RitchieHollis
Date: 2025-11-22

Refactored for REVcore integration

Focus on the *header section* of executable files.

Given an opened file object and a detected file_type string,
parse_header() dispatches to a format-specific extractor and
returns a JSON-friendly dict:

On success:
{
    "header_status": "success",
    "header": { ... format-specific fields ... }
}

On error:
{
    "header_status": "error",
    "reason": "<human readable reason>"
}

Recognized formats:
    - PE (Portable Executable)  [windowsExtract.windows_headers]
    - ELF (Executable and Linkable Format)  [linuxExtract.linux_headers]

TODO:
    - Add Mach-O headers
    - Extend ELF fields (sections etc.)
"""

from windowsExtract import windows_headers
from linuxExtract import linux_headers 


def parse_header(file, file_type):
    """
    Parse the file header to extract information, depending on the type
    of executable

    Args:
        file: open file object in binary mode, positioned anywhere.
              Implementations are responsible for seeking where needed
        file_type: string as returned by fileValidator / FILE_TYPES, e.g.
                   "PE (Portable Executable)", "ELF (Executable and Linkable Format)",
                   "Mach-O (64-bit)", ...

    Returns:
        dict with:
            - header_status: "success" or "error"
            - header: dict with fields (on success)
            - reason: str (on error)
    """
    try:
        ftype = str(file_type)

        if ftype == "PE (Portable Executable)":
            return windows_headers(file)

        if ftype == "ELF (Executable and Linkable Format)":
            return linux_headers(file)

        if ftype.startswith("Mach-O"):
            # Placeholder for future Mach-O support
            return {
                "header_status": "error",
                "reason": "Mach-O header parsing not implemented yet",
            }

    except Exception as e:
        return {
            "header_status": "error",
            "reason": str(e),
        }

    return {
        "header_status": "error",
        "reason": "Unsupported file type, can't determine header section",
    }
