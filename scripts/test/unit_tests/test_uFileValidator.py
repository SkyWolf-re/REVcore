import os
import stat
import io
import struct
import pytest
import fileValidator 
from fileValidator import (
    check_file_exists,
    stream_magic_number,
    identify_file_type,
    identify_architecture,
    file_validation,
)

# ---check_file_exists tests--------------------------------------------------------------------------------

def test_check_file_exists_valid(tmp_path):
    """Unit test of check_file_exists function for an existing file"""
    f = tmp_path / "ok.bin"
    f.write_bytes(b"\x00")
    assert check_file_exists(str(f)) == {"file exists": "success"}

def test_check_file_exists_not_found(tmp_path):
    """Unit test of check_file_exists function for a non-existing file"""
    missing = tmp_path / "none.bin"
    assert check_file_exists(str(missing)) == {
        "status": "error",
        "reason": "File not found"
    }

def test_check_file_exists_not_readable(monkeypatch, tmp_path):
    """Unit test of check_file_exists function for a non-readable file (permission, restriction etc.)
    Uses monkeypatch to bypass os configs for cross-platform testing
    """
    f = tmp_path / "nope.bin"
    f.write_bytes(b"\x00")
    f.chmod(0)

    # force os.access to think it's unreadable
    monkeypatch.setattr(os, "access", lambda path, mode: False)
    try:
        assert check_file_exists(str(f)) == {
            "status": "error",
            "reason": "File is not readable"
        }
    finally:
        # restore so cleanup can run
        f.chmod(stat.S_IRUSR | stat.S_IWUSR)

# ---stream_magic_number tests--------------------------------------------------------------------------------

def test_stream_magic_number_file_too_small(dummy_file):
    """Unit test of stream_magic_number function for a non-existent magic number (file too small)"""
    f = dummy_file(b"0")
    result = stream_magic_number(f)
    assert result == {
        "status": "error", 
        "reason": "File too small to contain a valid magic number"
    }

def test_stream_magic_number_file_unreadable(tmp_path):
    """Unit test of stream_magic_number function for an unreadable file"""
    f = tmp_path / "nope.bin"
    result = stream_magic_number(f)

    assert result["status"] == "error"
    #Prefix of message for all messages
    assert result["reason"].startswith("Failed to read file: ")

@pytest.mark.parametrize("data,byte_count,expected", [(b"ABCD", 2, b"AB"),(b"\x00\xFFhello", 3, b"\x00\xFFh"),(b"xy", 2, b"xy"),])
def test_stream_magic_number_success(dummy_file, data, byte_count, expected):
    """Unit test of stream_magic_number function for a valid file with valid magic number.
    Uses mark.parametrize to simulate a file
    """
    f = dummy_file(data)
    result = stream_magic_number(f, byte_count=byte_count)
    assert result == {"status": "success", "magic_number": expected}

# ---identify_file_type--------------------------------------------------------------------------------

def test_identify_file_type_against_map(file_type_map):
    """Unit test of identify_file_type for each known magic number, even with extra trailing bytes
    """
    for magic, expected in file_type_map.items():
        padded = magic + b"EXTRA"
        assert identify_file_type(padded) == expected, f"{magic!r} → {expected}"

    # unknown cases
    assert identify_file_type(b"") == "Unknown"
    assert identify_file_type(b"\x00\x11\x22\x33") == "Unknown"

# ---identify_architecture--------------------------------------------------------------------------------

# PE tests
@pytest.mark.parametrize("code,expected", [
    (0x8664, "x86-64"),
    (0x014C, "x86 (32-bit)"),
    (0x0200, "IA64 (Itanium)"),
])
def test_identify_architecture_pe_known(make_pe_file, code, expected):
    """Unit test of identify_architecture for each supported windows PE 
    """
    f = make_pe_file(code)
    assert identify_architecture(f, "PE (Portable Executable)") == expected

# ELF tests
@pytest.mark.parametrize("code,expected", [
    (0x03,   "x86 (32-bit)"),
    (0x3E,   "x86-64"),
    (0x28,   "ARM"),
    (0xB7,   "AArch64 (ARM 64-bit)"),
])
def test_identify_architecture_elf_known(make_elf_file, code, expected):
    """Unit test of identify_architecture for each supported linux ELF
    """
    f = make_elf_file(code)
    assert identify_architecture(f, "ELF (Executable and Linkable Format)") == expected

# Mach‑O tests
@pytest.mark.parametrize("code,expected", [
    (0x07,       "x86"),
    (0x01000007, "x86-64"),
    (0x12,       "ARM"),
    (0x01000012, "ARM64"),
])
def test_identify_architecture_macho_known(make_macho_file, code, expected):
    """Unit test of identify_architecture for each supported macOS Mach-O
    """
    f = make_macho_file(code)
    assert identify_architecture(f, "Mach-O (Fat Binary)") == expected

def test_identify_architecture_unsupported_file_type():
    """Unit test of identify_architecture for unknown (unsupported) type
    """
    fake_file = io.BytesIO(b"")  
    result = identify_architecture(fake_file, "NOT_A_REAL_TYPE")
    assert result == "Unsupported File Type"


def test_identify_architecture_catches_any_exception():
    """Unit test of identify_architecture for any error that may occur
    """
    class BrokenFile:
        def seek(self, *args, **kwargs):
            raise RuntimeError("boom")

    result = identify_architecture(BrokenFile(), "PE (Portable Executable)")
    assert result.startswith("Error identifying architecture: boom")

# ---file_validator----------------------------------------------------------------------

ERROR_CASES = [
    ("check_file_exists",
     {"status": "error", "reason": "File not found"},
     {"status": "error", "reason": "File not found"},
     None),

    ("stream_magic_number",
     {"status": "error", "reason": "bad magic"},
     {"status": "error", "reason": "bad magic"},
     "real"),

    ("parse_header",
     {"status": "error", "reason": "wonky header"},
     {"status": "error", "reason": "wonky header"},
     "real"),
]

@pytest.mark.parametrize("func_name,fake_ret,expected,path_mode", ERROR_CASES)
def test_file_validation_errors(func_name, fake_ret, expected, path_mode, tmp_path, monkeypatch):
    """Unit test for file_validation that checks potential errors that may occur"""
    # patches the target
    monkeypatch.setattr(fileValidator, func_name,
                        lambda *args, **kwargs: fake_ret)

    # patches earlier steps
    if func_name != "check_file_exists":
        monkeypatch.setattr(fileValidator, "check_file_exists",
                            lambda path: {"file exists": "success"})
    if func_name == "parse_header":
        # also bypass magic/type/arch
        monkeypatch.setattr(fileValidator, "stream_magic_number",
                            lambda f: {"status":"success","magic_number":b"AB"})
        monkeypatch.setattr(fileValidator, "identify_file_type",
                            lambda magic:"PE (Portable Executable)")
        monkeypatch.setattr(fileValidator, "identify_architecture",
                            lambda f,t:"x86-64")

    if path_mode == "real":
        p = tmp_path / "d.bin"; p.write_bytes(b"\x00"); path = str(p)
    else:
        path = "no_such.bin"

    res = file_validation(path)

    # only assert the things that every error _must_ have:
    assert res["status"] == expected["status"]
    assert res["reason"] == expected["reason"]

def test_file_validation_success(monkeypatch, tmp_path):
    """Unit test for file_validation that checks a valid file"""
    # simulate check_file_exists success
    monkeypatch.setattr(fileValidator, "check_file_exists",
                        lambda path: {"file exists": "success"})

    # simulate magic‐number step
    monkeypatch.setattr(fileValidator, "stream_magic_number",
                        lambda f: {"status": "success", "magic_number": b"AB"})

    # simulate type detection
    monkeypatch.setattr(fileValidator, "identify_file_type",
                        lambda magic: "PE (Portable Executable)")

    # simulate arch detection
    monkeypatch.setattr(fileValidator, "identify_architecture",
                        lambda f, t: "x86-64")

    # simulate header parsing
    fake_header = {"header_status": "ok", "header": {"sections": 5}}
    monkeypatch.setattr(fileValidator, "parse_header",
                        lambda f, t: fake_header)

    p = tmp_path / "dummy.bin"
    p.write_bytes(b"\x00\x01\x02")

    result = file_validation(str(p))

    assert result == {
        "status": "success",
        "file_info": {
            "path": str(p),
            "type": "PE (Portable Executable)",
            "architecture": "x86-64",
            "magic_number": "4142",  # b"AB".hex()
        },
        **fake_header
    }