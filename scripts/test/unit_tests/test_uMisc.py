from datetime import datetime
import io
import struct
import pytest
import fileValidator 
import misc
from misc import (
    format_timestamp,
    parse_certificate_table,
    validate_entry_point,
)

# ---format_timestamp tests--------------------------------------------------------------------------------

def test_format_timestamp_epoch_start():
    """Unit test of format_timestamp with Unix epoch start in UTC"""
    assert format_timestamp(0) == "1970-01-01 00:00:00 UTC"

@pytest.mark.parametrize("bad_ts", [-1, 10**20])
def test_format_timestamp_catches_overflowError(bad_ts):
    """Unit test of format_timestamp with forced overflow Error"""
    out = format_timestamp(bad_ts)
    assert out == "Invalid Timestamp"

def test_format_timestamp_catches_valueError(monkeypatch):
    """Unit test of format_timestamp with forced valueError"""
    class DummyDateTime:
        @classmethod
        def fromtimestamp(cls, ts, tz=None):
            raise ValueError("tung tung tung sahur")
    
    monkeypatch.setattr(misc, "datetime", DummyDateTime)
    assert format_timestamp(123456) == "Invalid Timestamp"

def test_format_timestamp_catches_oserror(monkeypatch):
    """Unit test of format_timestamp with forced OSError"""
    class DummyDateTime:
        @classmethod
        def fromtimestamp(cls, ts, tz=None):
            raise OSError("womp womp")
        
    monkeypatch.setattr(misc, "datetime", DummyDateTime)
    assert format_timestamp(123456) == "Invalid Timestamp"

def test_format_timestamp_valid_date():
    """Unit test of format_timestamp with a correct date"""
    # 2069‑04‑20 01:02:34 UTC
    ts = 3133645354
    assert format_timestamp(ts) == "2069-04-20 01:02:34 UTC"

# ---parse_certificate_table tests-------------------------------------------------------------------------

def test_parse_certificate_table_no_rva(dummy_file):
    """Unit test of parse_certificate_table with rva equals 0"""
    f = dummy_file(b"0")
    rva = 0
    assert parse_certificate_table(f,0,69) == None

def test_parse_certificate_table_no_size(dummy_file):
    """Unit test of parse_certificate_table with size equals 0"""
    f = dummy_file(b"0")
    size = 0
    assert parse_certificate_table(f,69,0) == None

def test_parse_certificate_table_invalid_cert(dummy_file):
    """Unit test of parse_certificate_table with too short file to contain a certificate"""
    data = b"\x01" * 7
    f = dummy_file(data)
    result = parse_certificate_table(f,1,len(data))
    assert result == {"error": "Invalid Certificate Table"}

def test_parse_certificate_table_any_exception():
    """Unit test of parse_certificate_table with any exception catched"""
    class BadFile(io.BytesIO):
        def seek(self, offset, whence=0):
            raise RuntimeError("seek bomb")

    f = BadFile(b"\x00" * 20)
    result = parse_certificate_table(f, rva=10, size=8)
    assert result == {"error": "Failed to parse certificate: seek bomb"}

def test_parse_certificate_table_valid(dummy_file):
    """Unit test of parse_certificate_table with correct certificate format"""
    #dwLength=12
    header = struct.pack("<IHH", 12, 3, 5)
    body   = b"\xAA\xBB\xCC\xDD"  #extra cert data beyond the header
    f = dummy_file(header+body)

    result = parse_certificate_table(f,1,len(header) + len(body))
    assert result == {
        "length":   50331648,
        "revision": 1280,
        "type":     43520,
    } #data for 12 length ,3 revision, 5 cert type

# ---validate_entry_point tests----------------------------------------------------------------------------

def test_validate_entry_point_inside_single_section(dummy_file, make_section):
    """Unit test of validate_entry_point with single section settled"""
    # pe_header_offset=0, size_optional_header=0 --> section_table_offset=24
    data = b"\x00" * 24 + make_section(0x1000, 0x200)
    f = dummy_file(data)
    # 0x1100 lies within [0x1000, 0x1200)
    assert validate_entry_point(f, entry_point=0x1100,
                                pe_header_offset=0,
                                size_optional_header=0,
                                num_sections=1)

def test_validate_entry_point_outside_single_section(dummy_file, make_section):
    """Unit test of validate_entry_point with single section and outside of it"""
    data = b"\x00" * 24 + make_section(0x1000, 0x100)
    f = dummy_file(data)
    # 0x2000 is well outside [0x1000, 0x1100)
    assert not validate_entry_point(f, entry_point=0x2000,
                                    pe_header_offset=0,
                                    size_optional_header=0,
                                    num_sections=1)

def test_validate_entry_point_multiple_sections(dummy_file, make_section):
    """Unit test of validate_entry_point with multiple sections settled"""
    # Two sections back-to-back
    # Section 1: [0x0000, 0x0064)
    # Section 2: [0x1000, 0x1100)
    data = (
        b"\x00" * 24
        + make_section(0x0000, 0x0064)
        + make_section(0x1000, 0x0100)
    )
    f1 = dummy_file(data)
    # 0x1050 is in section 2
    assert validate_entry_point(f1, entry_point=0x1050,
                                pe_header_offset=0,
                                size_optional_header=0,
                                num_sections=2)
    # 0x0064 is exactly at the end of section 1 (exclusive), so should be False
    f2 = dummy_file(data)
    assert not validate_entry_point(f2, entry_point=0x0064,
                                    pe_header_offset=0,
                                    size_optional_header=0,
                                    num_sections=2)

def test_validate_entry_point_zero_sections(dummy_file):
    """Unit test of validate_entry_point with no sections settled"""
    f = dummy_file(b"0")
    assert not validate_entry_point(f, entry_point=0x0,
                                    pe_header_offset=0,
                                    size_optional_header=0,
                                    num_sections=0)

def test_validate_entry_point_with_nonzero_offsets(dummy_file, make_section):
    """Unit test of validate_entry_point with a present offset"""
    # pe_header_offset=10, size_optional_header=2 -> offset=10+24+2=36
    data = b"\x00" * 36 + make_section(0x2000, 0x0100)
    f = dummy_file(data)
    # 0x20F0 falls within [0x2000, 0x2100)
    assert validate_entry_point(f, entry_point=0x20F0,
                                pe_header_offset=10,
                                size_optional_header=2,
                                num_sections=1)
