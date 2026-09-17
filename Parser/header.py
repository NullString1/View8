"""Decode V8 code-cache (.jsc) headers in pure Python without external binaries.

Two known layouts:
Legacy (24 bytes): magic, version_hash, source_hash, flag_hash, payload_length, checksum
Modern (28 bytes): magic, version_hash, source_hash, flag_hash, ro_snapshot_checksum, payload_length, checksum
"""

import os
import struct
from typing import Dict, Optional, Union

MAGIC_XOR = 0xC0DE0000
LEGACY_SIZE = 24
MODERN_SIZE = 28


def decode_header(data: bytes, total_size: Optional[int] = None) -> Dict[str, Union[str, int, None]]:
    """Decode the header of raw .jsc bytes."""
    if len(data) < LEGACY_SIZE:
        raise ValueError(f"file too small for a header: {len(data)} bytes")
    
    file_len = total_size if total_size is not None else len(data)

    for size in (MODERN_SIZE, LEGACY_SIZE):
        if len(data) < size:
            continue
        aligned = (size + 7) & ~7  # POINTER_SIZE_ALIGN on 64-bit
        if size == MODERN_SIZE:
            (magic_m, ver, src, flags, ro, pay, chk) = struct.unpack_from("<7I", data, 0)
            if pay <= file_len - aligned:
                return {
                    "layout": "modern",
                    "magic": magic_m,
                    "version_hash": ver,
                    "source_hash": src,
                    "flag_hash": flags,
                    "ro_snapshot_checksum": ro,
                    "payload_length": pay,
                    "checksum": chk,
                    "header_size": aligned,
                    "payload_offset": aligned,
                    "trailing_bytes": file_len - aligned - pay,
                }
        else:
            (magic_l, ver, src, flags, pay, chk) = struct.unpack_from("<6I", data, 0)
            if pay <= file_len - aligned:
                return {
                    "layout": "legacy",
                    "magic": magic_l,
                    "version_hash": ver,
                    "source_hash": src,
                    "flag_hash": flags,
                    "ro_snapshot_checksum": None,
                    "payload_length": pay,
                    "checksum": chk,
                    "header_size": aligned,
                    "payload_offset": aligned,
                    "trailing_bytes": file_len - aligned - pay,
                }
    raise ValueError(
        f"payload length fits neither header layout (file size {file_len}). Not a V8 code cache, or truncated."
    )


def read_header_from_file(file_path: str) -> Dict[str, Union[str, int, None]]:
    """Read and decode header directly from a file path."""
    total_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        data = f.read(64)
    return decode_header(data, total_size=total_size)
