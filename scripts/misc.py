"""
misc.py

Author: RitchieHollis
Date: 2025-11-22

Refactored for REVcore integration

A packet of scripts used among major scripts:

    - format_timestamp(timestamp): Returns a datetime from Unix to UTC YYYY-mm-dd H:M:S
    - parse_certificate_table(file, rva, size): Returns json format such as:
        certificate_info: 
            "lenght": Uint
            "revision": Uint
            "type": Uint
            "certificate_date": Hex
    - validate_entry_point(file, entry_point, pe_header_offset, size_optional_header, num_sections): Returns boolean if entry_point is valid
"""
from enum import Enum
import struct
from datetime import datetime, timezone


#---------------------------------General purpose------------------------------------------------------------
FILE_TYPES = {
        b"MZ": "PE (Portable Executable)",        
        b"\x7FELF": "ELF (Executable and Linkable Format)",  
        b"\xCA\xFE\xBA\xBE": "Mach-O (Fat Binary)",  
        b"\xFE\xED\xFA\xCE": "Mach-O (32-bit)",    
        b"\xFE\xED\xFA\xCF": "Mach-O (64-bit)"    
    }

#---------------------------------Constants used for Windows--------------------------------------------------
PE_HEADER_OFFSET = 0x3C

WIN_ARCH_MAP = {
                0x8664: "x86-64",
                0x014C: "x86 (32-bit)",
                0x0200: "IA64 (Itanium)"
                }
class WindowsSubsystem(Enum):

    Windows_exe             = 0
    Native                  = 1
    Windows_GUI             = 2
    Windows_Console         = 3
    Windows_CUI             = 5
    Posix_CUI               = 7
    Windows_CE_GUI          = 9
    EFI_Application         = 10
    EFI_Boot_Service_Driver = 11
    EFI_Runtime_Driver      = 12
    EFI_ROM                 = 13
    Xbox                    = 14
    Boot_Application        = 16

#-----------------------Constants used for Linux (ELF)-----------------------
LNX_ARCH_MAP = {
    0x03: "x86 (32-bit)",         
    0x3E: "x86-64",               
    0x28: "ARM",                  
    0xB7: "AArch64 (ARM 64-bit)", 
}

LNX_EI_CLASS = {
    0: "Invalid",
    1: "ELF32",
    2: "ELF64",
}

LNX_EI_DATA = {
    0: "Invalid",
    1: "little",
    2: "big",
}

LNX_OSABI_MAP = {
    0: "System V",
    3: "Linux",
    6: "Solaris",
    9: "FreeBSD",
    12: "OpenBSD",
}

LNX_ET_TYPE = {
    0: "none",
    1: "relocatable",
    2: "executable",
    3: "shared",
    4: "core",
}

#---------------------------------Constants used for Mac--------------------------------------------------
MAC_ARCH_MAP = {
                0x07: "x86",
                0x01000007: "x86-64",
                0x12: "ARM",
                0x01000012: "ARM64"
                }

#---------------------------------Functions-------------------------------------------------------------
def format_timestamp(timestamp):
    """Convert Unix timestamp to a readable UTC date and time."""
    #treat any negative timestamp as invalid
    if timestamp < 0:
        return "Invalid Timestamp"
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError) as e:
        return "Invalid Timestamp"
    
def parse_certificate_table(file, rva, size):
    """Extract details of the Certificate Table if present."""
    try:
        if rva == 0 or size == 0:
            return None  # No certificate table
        
        # Seek to the Certificate Table (RVA is raw file offset for certificates)
        file.seek(rva)
        certificate_data = file.read(size)
        
        # Parse the WIN_CERTIFICATE structure
        if len(certificate_data) < 8:
            return {"error": "Invalid Certificate Table"}
        
        dwLength, wRevision, wCertificateType = struct.unpack("<IHH", certificate_data[:8])
        certificate_info = {
            "length": dwLength,
            "revision": wRevision,
            "type": wCertificateType,
            #"certificate_data": certificate_data[8:dwLength].hex()  # Hex representation of the cert -> to decrypt
        }
        return certificate_info

    except Exception as e:
        return {"error": f"Failed to parse certificate: {str(e)}"}
    
def validate_entry_point(file, entry_point, pe_header_offset, size_optional_header, num_sections):
    """Check if entry point of header is valid"""
    #print("entered the validate_entry_point")
    section_table_offset = pe_header_offset + 24 + size_optional_header
    for _ in range(num_sections):
        file.seek(section_table_offset)
        section = file.read(40)
        virtual_address = struct.unpack("<I", section[12:16])[0]
        virtual_size = struct.unpack("<I", section[8:12])[0]

        #print(virtual_address)
        #print(virtual_size)

        if virtual_address <= entry_point < (virtual_address + virtual_size):
            return True
        section_table_offset += 40

    return False
