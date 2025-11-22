import io
import struct
import pytest
import windowsExtract
from misc import PE_HEADER_OFFSET
from windowsExtract import (windows_headers, 
                            _get_pe_header_pointer, 
                            _get_signature,
                            _get_coff_header,
                            _get_optional_header,
                            _get_section_info,
                            _get_data_directories,
                            _get_certificate)

# ---_get_pe_header_pointer tests----------------------------------------------------------------------------

def test_get_pe_header_pointer_valid(dummy_file):
    """Unit test of _get_pe_header_pointer with a valid header section"""
    # fake header offset
    expected_offset = 0x12345678
    data = bytearray(PE_HEADER_OFFSET + 4)
    struct.pack_into('<I', data, PE_HEADER_OFFSET, expected_offset)
    f = dummy_file(data)

    result = _get_pe_header_pointer(f)
    assert result == expected_offset

def test_get_pe_header_pointer_read_error(dummy_file):
    """Unit test of _get_pe_header_pointer with a file too short to contain a header"""
    data = bytearray(PE_HEADER_OFFSET + 2)
    f = dummy_file(data)

    with pytest.raises(struct.error):
        _get_pe_header_pointer(f)


def test_get_pe_header_pointer_non_zero_positioning(dummy_file, monkeypatch):
    """Unit test of _get_pe_header_pointer to check if function uses the PE_HEADER_OFFSET constant correctly"""
    
    test_offset = 0x10
    data = bytearray(test_offset + 4)
    struct.pack_into('<I', data, test_offset, 0xDEADBEEF)
    f = dummy_file(data)

    monkeypatch.setattr(windowsExtract, "PE_HEADER_OFFSET", test_offset)

    result = _get_pe_header_pointer(f)
    assert result == 0xDEADBEEF

# ---_get_signature tests----------------------------------------------------------------------------

def test_get_signature_valid(dummy_file):
    """Unit test of _get_signature when there are at least 4 bytes available at base"""
    data = b"FUCKING_HELL"
    f = dummy_file(data)
    # signature at offset 0…4
    sig = _get_signature(f, 0)
    assert sig == b"FUCK"
    # 8... 
    sig2 = _get_signature(f, 8)
    assert sig2 == b"HELL"

def test_get_signature_short(dummy_file):
    """Unit test of _get_signature with less than 4 bytes available at base"""
    data = b"XYZ"
    f = dummy_file(data)
    sig = _get_signature(f, 1)
    # only 'YZ' remains
    assert sig == b"YZ"
    sig_empty = _get_signature(f, 10)
    assert sig_empty == b""

# ---_get_coff_header tests----------------------------------------------------------------------------

def test_get_coff_header_valid(dummy_file):
    """Unit test of _get_coff_header with correct info"""
    base = 0x20
    timestamp = 0xA1B2C3D4
    num_sec = 0x1234
    size_opt = 0x0050
    length = base + 20 + 16 + 2
    data = bytearray(length)
    struct.pack_into('<I', data, base + 4, timestamp)
    struct.pack_into('<H', data, base + 8, num_sec)
    struct.pack_into('<H', data, base + 20 + 16, size_opt)
    f = dummy_file(data)
    result = _get_coff_header(f, base)
    assert result == (num_sec, timestamp, size_opt)


def test_get_coff_header_timestamp_short(dummy_file):
    """Unit test of _get_coff_header with incorrect timestamp info"""
    base = 0x20
    length = base + 6
    data = bytearray(length)
    f = dummy_file(data)
    with pytest.raises(struct.error):
        _get_coff_header(f, base)

def test_get_coff_header_num_sections_short(dummy_file):
    """Unit test of _get_coff_header with incorrect num_sections"""
    base = 0x20
    timestamp = 0xA1B2C3D4
    # buffer covers timestamp but only 1 byte of num_sections
    length = base + 4 + 4 + 1
    data = bytearray(length)
    struct.pack_into('<I', data, base + 4, timestamp)
    f = dummy_file(data)
    with pytest.raises(struct.error):
        _get_coff_header(f, base)

def test_get_coff_header_size_opt_short(dummy_file):
    """Unit test of _get_coff_header with incorrect size_opt"""
    base = 0x20
    timestamp = 0xA1B2C3D4
    num_sec = 0x1234
    length = base + 8 + 2  # covers timestamp & num_sec but not size_opt
    data = bytearray(length)
    struct.pack_into('<I', data, base + 4, timestamp)
    struct.pack_into('<H', data, base + 8, num_sec)
    f = dummy_file(data)
    with pytest.raises(struct.error):
        _get_coff_header(f, base)

# ---_get_optional_header tests----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field,     offset, pack_fmt,    value",
    [
        ("major_linker",       2,   "B",        7),
        ("minor_linker",       3,   "B",        8),
        ("entry_point",       16,  "<I",  0xCAFEBABE),
        ("size_of_image",     56,  "<I",  0x01020304),
        ("checksum",          64,  "<I",  0x0A0B0C0D),
        ("loader_flags",      92,  "<I",  0x11223344),
    ]
)
def test_get_optional_header_fields(dummy_file, field, offset, pack_fmt, value):
    """Unit test of _get_optional_header for static fields of header.
    That should pick up each field correctly when its bytes are placed at base + 24 + offset"""
    base, size_opt = 0x10, 128
    buf = bytearray(base + 24 + size_opt)

    # pack the target field
    struct.pack_into(pack_fmt, buf, base + 24 + offset, value)

    # stub DLL characteristics only if not loader_flags
    if field != "loader_flags":
        struct.pack_into("<H", buf, base + 24 + 92, 0)

    f = dummy_file(buf)
    got = _get_optional_header(f, base, size_opt)

    if field == "entry_point":
        assert int(got[field], 16) == value
    else:
        assert got[field] == value

def test_optional_header_version_and_dlls(dummy_file):
    """Unit test of _get_optional_header for dynamic fields of header.
    That should pick up each field correctly when its bytes are placed at base + 24 + offset"""
    base, size_opt = 0x10, 100
    buf = bytearray(base + 24 + size_opt)
    start = base + 24

    # OS = 3.14, Subsys = 5.6
    struct.pack_into("<H", buf, start + 32, 3)
    struct.pack_into("<H", buf, start + 34, 14)
    struct.pack_into("<H", buf, start + 36, 5)
    struct.pack_into("<H", buf, start + 38, 6)

    # DLL bits 0x0020 + 0x0040
    struct.pack_into("<H", buf, start + 92, 0x0020 | 0x0040)

    got = _get_optional_header(dummy_file(buf), base, size_opt)
    assert got["os_version"]        == "3.14"
    assert got["subsystem_version"] == "5.6"
    assert set(got["dll_characteristics"]) == {
        "ASLR with 64 bit address space",
        "Dynamic base"
    }

def test_get_optional_header_too_short(dummy_file):
    """Unit test of _get_optional_header for header too short to be considered"""
    base = 0x10
    size_opt = 1  #way too small to reach offset 16 or 32
    f = dummy_file(bytearray(base + 24 + size_opt))
    with pytest.raises((struct.error, IndexError)):
        _get_optional_header(f, base, size_opt)

# ---_get_section_info tests----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "stub_return, va, num_secs, expected_valid",
    [
        (True,  "0x1000", 1, True),
        (False, "0xDEAD",  3, False),
    ],
)
def test_get_section_info_parametrized(
    dummy_file, monkeypatch, stub_return, va, num_secs, expected_valid
):
    """
    Parametrized unit test for _get_section_info:
      - stub validate_entry_point to return stub_return
      - check that valid_entry_point == stub_return
      - header_num always echoes num_secs
      - also verify that hex‐string VA is int(va,16)
    """
    called = {}

    def fake_validate(f_obj, entry_point, base, size_opt, num_sections):
        called["args"] = (f_obj, entry_point, base, size_opt, num_sections)
        return stub_return

    monkeypatch.setattr(windowsExtract, "validate_entry_point", fake_validate)
    f = dummy_file(b"")

    #Fake args correct/incorrect values for right section
    result = _get_section_info(f,
                               base=0x20,
                               size_opt=0x10,
                               num_sections=num_secs,
                               va=va)

    assert result == {
        "valid_entry_point": expected_valid,
        "header_num": num_secs
    }

    #all args test
    _, entry_arg, base_arg, size_opt_arg, num_sec_arg = called["args"]
    assert entry_arg == int(va, 16)
    assert base_arg      == 0x20
    assert size_opt_arg  == 0x10
    assert num_sec_arg   == num_secs

def test_get_section_info_true(monkeypatch, dummy_file):
    """Unit test of _get_section info when validate_entry_point returns True. 
    _get_section_info should reflect that in valid_entry_point and echo header_num
    """
    f = dummy_file(b"")

    #Fake args
    called = {}
    def fake_validate(file_obj, entry_point, base, size_opt, num_sections):
        called['args'] = (file_obj, entry_point, base, size_opt, num_sections)
        return True

    monkeypatch.setattr(windowsExtract, "validate_entry_point", fake_validate)

    #Fake args correct values for right section
    base = 0x20
    size_opt = 0x10
    num_sections = 5
    va = "0x1000"
    result = _get_section_info(f, base, size_opt, num_sections, va)
    file_obj, entry_point, b2, so2, ns2 = called['args']
    
    #all args True
    assert result == {"valid_entry_point": True, "header_num": num_sections}
    assert file_obj is f
    assert entry_point == int(va, 16)
    assert b2 == base and so2 == size_opt and ns2 == num_sections

def test_get_section_info_false(monkeypatch, dummy_file):
    """Unit test of _get_section info when validate_entry_point returns False. valid_entry_point should be False"""
    f = dummy_file(b"\x00\x01\x02")
    monkeypatch.setattr(windowsExtract, "validate_entry_point", lambda *args, **kwargs: False)
    res = _get_section_info(f, base=0, size_opt=0, num_sections=3, va="FF")
    assert res == {"valid_entry_point": False, "header_num": 3}

# ---_get_data_directories tests----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "count, should_raise",
    [
        (16, False),  # exactly enough entries → success
        (15, True),   # one entry short      → struct.error
    ],
)
def test_get_data_directories_parametrized(dummy_file, count, should_raise):
    """
    Parametrized unit test for _get_data_directories:
      - count entries packed into the buffer
      - should_raise indicates whether unpacking 16 entries should fail
    """
    base = 0x10
    entry_size = 8
    total_len = base + 120 + count * entry_size
    buf = bytearray(total_len)

    #(rva=i, size=i*10)
    for i in range(count):
        struct.pack_into("<II", buf, base + 120 + i * entry_size, i, i * 10)

    f = dummy_file(buf)

    if should_raise:
        with pytest.raises(struct.error):
            _get_data_directories(f, base)
    else:
        result = _get_data_directories(f, base)
        # We expect exactly 16 entries, each matching our pack pattern
        assert isinstance(result, list) and len(result) == 16
        for i, entry in enumerate(result):
            assert entry["rva"]  == hex(i)
            assert entry["size"] == i * 10

# ---_get_certificate tests----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "dir_entry",
    [
        ({"rva": "0x0",  "size":  10}),  #zero RVA 
        ({"rva": "0x10", "size":   0}),  #zero size
    ]
)
def test_get_certificate_none(dummy_file, dir_entry):
    """
    Parametrized unit test for _get_certificate.
    If either the RVA or size is zero, _get_certificate should return None without calling parse_certificate_table
    """
    f = dummy_file(b"irrelevant")
    assert _get_certificate(f, dir_entry) is None

def test_get_certificate_delegates_to_parser(dummy_file, monkeypatch):
    """
    Unit test for _get_certificate when both RVA and size are non-zero. _get_certificate should
    call parse_certificate_table(f, rva, size) and return its result
    """
    f = dummy_file(b"\xAA"*100)
    dir_entry = {"rva": "0x20", "size": 16}

    #Fake args
    called = {}
    def fake_parse(file_obj, rva_arg, size_arg):
        called["args"] = (file_obj, rva_arg, size_arg)
        return {"ass": "hole"}

    monkeypatch.setattr(windowsExtract, "parse_certificate_table", fake_parse)

    result = _get_certificate(f, dir_entry)

    assert result == {"ass": "hole"}
    assert called["args"] == (f, int(dir_entry["rva"], 16), dir_entry["size"])

# ---windows_headers tests----------------------------------------------------------------------------

def test_windows_headers_invalid_signature(make_pe_file):
    """Unit test of windows_headers with invalid signature. The 4-byte PE signature isn’t b'PE\\0\\0' at the header offset"""
    f = make_pe_file(machine_code=0x014C)
    f.seek(0)
    out = windows_headers(f)
    assert out == {"header_status": "error", "reason": "Invalid PE signature"}

