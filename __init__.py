import sys
import os

_view8_dir = os.path.dirname(os.path.abspath(__file__))
if _view8_dir not in sys.path:
    sys.path.append(_view8_dir)

from view8 import decompile_dump, decompile, disassemble
from Parser.parse_v8cache import parse_disassembled_file, parse_disassembled_text
from Parser.poolinfo import enrich_functions_from_jsc, clean_pool_value

__all__ = [
    "decompile_dump",
    "decompile",
    "disassemble",
    "parse_disassembled_file",
    "parse_disassembled_text",
    "enrich_functions_from_jsc",
    "clean_pool_value",
]