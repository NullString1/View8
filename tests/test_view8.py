import os
import unittest

from Parser.header import decode_header, read_header_from_file
from Parser.poolinfo import clean_pool_value, is_valid_js_identifier
from Parser.parse_v8cache import parse_disassembled_file
from Parser.sfi_file_parser import parse_bytecode_line, parse_file
from Translate.translate_table import get_typeof_value, operands
from Parser.shared_function_info import GlobalVars, SharedFunctionInfo


class TestView8Header(unittest.TestCase):
    def test_decode_header_legacy_and_modern(self):
        # 32 bytes modern header
        modern_data = (
            (0xC0DE0000).to_bytes(4, 'little') +
            (0x12345678).to_bytes(4, 'little') +
            (100).to_bytes(4, 'little') +
            (0xABCDEF01).to_bytes(4, 'little') +
            (0x55555555).to_bytes(4, 'little') +
            (256).to_bytes(4, 'little') +
            (0x99999999).to_bytes(4, 'little') +
            b"\x00" * 4 +  # pad to 32
            b"\x00" * 256  # payload
        )
        h = decode_header(modern_data)
        self.assertEqual(h["layout"], "modern")
        self.assertEqual(h["payload_length"], 256)
        self.assertEqual(h["version_hash"], 0x12345678)

    def test_fixture_headers(self):
        fixture = "/mdata/NS/Projects/jsc-edit/tests/fixtures/check.jsc"
        if os.path.exists(fixture):
            h = read_header_from_file(fixture)
            self.assertIn(h["layout"], ("modern", "legacy"))
            self.assertGreater(h["payload_length"], 0)

    def test_detect_version(self):
        from Parser.header import find_version_info, detect_and_print_version
        fixture = "/mdata/NS/Projects/jsc-edit/tests/fixtures/check.jsc"
        if os.path.exists(fixture):
            h = read_header_from_file(fixture)
            info = find_version_info(h)
            self.assertEqual(info["v8"], "13.6.233.17")
            self.assertIn("v24", info["node"])
            self.assertIn("v35", info["electron"])
            self.assertTrue(detect_and_print_version(fixture))


class TestPoolInfo(unittest.TestCase):
    def test_clean_pool_value_strings(self):
        self.assertEqual(clean_pool_value("<String[5]: #hello>"), '"hello"')
        self.assertEqual(clean_pool_value("<String[12]: #hello world>"), '"hello world"')

    def test_clean_pool_value_roots(self):
        self.assertEqual(clean_pool_value('<root: console_string = "console">'), '"console"')
        self.assertEqual(clean_pool_value('<root: process_string = "process">'), '"process"')
        self.assertEqual(clean_pool_value('<ro-heap [0,61616] = "log">'), '"log"')
        self.assertEqual(clean_pool_value('<root: undefined_value>'), 'undefined')
        self.assertEqual(clean_pool_value('<root: null_value>'), 'null')
        self.assertEqual(clean_pool_value('<root: true_value>'), 'true')
        self.assertEqual(clean_pool_value('<root: false_value>'), 'false')

    def test_is_valid_js_identifier(self):
        self.assertTrue(is_valid_js_identifier("console"))
        self.assertTrue(is_valid_js_identifier("argv"))
        self.assertTrue(is_valid_js_identifier("_$foo123"))
        self.assertFalse(is_valid_js_identifier("123abc"))
        self.assertFalse(is_valid_js_identifier("hello world"))


class TestTranslateTable(unittest.TestCase):
    def test_typeof_values(self):
        self.assertEqual(get_typeof_value("#0"), "number")
        self.assertEqual(get_typeof_value("#1"), "string")
        self.assertEqual(get_typeof_value("#2"), "symbol")
        self.assertEqual(get_typeof_value("#3"), "boolean")
        self.assertEqual(get_typeof_value("#4"), "bigint")
        self.assertEqual(get_typeof_value("#5"), "undefined")
        self.assertEqual(get_typeof_value("#6"), "function")
        self.assertEqual(get_typeof_value("#7"), "object")

    def test_bytecode_regex_no_swallowing(self):
        line = "  487 E> 0x1dcbb30c015f @   39 : 69 f9 f6 06       CallUndefinedReceiver1 r0, r3, [6]"
        parsed = parse_bytecode_line(line)
        self.assertEqual(parsed.line_num, 39)
        self.assertEqual(parsed.v8_opcode, "69 f9 f6 06")
        self.assertEqual(parsed.v8_instruction, "CallUndefinedReceiver1 r0, r3, [6]")


class TestEndToEndDecompilation(unittest.TestCase):
    def test_decompile_fixture_check(self):
        fixture = "/mdata/NS/Projects/jsc-edit/tests/fixtures/check.jsc"
        if not os.path.exists(fixture):
            self.skipTest("check.jsc fixture not found")
        from view8 import disassemble, decompile
        all_func = disassemble(fixture, False, None)
        self.assertGreater(len(all_func), 0)
        decompile(all_func)
        # Check that check function is present
        found_check = any("check" in name for name in all_func)
        self.assertTrue(found_check)

    def test_decompile_dump_with_pool_overrides(self):
        dump_text = """
[SharedFunctionInfo] in OldSpace: 0x3f6b9aaafa49 <SharedFunctionInfo check>
 - name: <String[5]: #check>
Parameter count 2
Register count 3
Constant pool (size = 8)
0x1a8e8c680299: [FixedArray] in OldSpace
 - length: 8
           0: <unknown>
           1: <unknown>
           2: <unknown>
           3: 0x3f6b9aaafaa1 <String[28]: #usage: node check.js <input>>
           4: 0x3f6b9aaafa19 <String[6]: #SECRET>
           5: 0x3f6b9aaafad1 <String[16]: #ACCESS GRANTED: >
           6: 0x3f6b9aaafa31 <String[4]: #FLAG>
           7: 0x3f6b9aaafaf1 <String[6]: #denied>
Handler Table (size = 0)
Bytecode (size = 91)
@    0 : 0b 03                Ldar a0
@    2 : 22 01                TestTypeOf #1
@    4 : a3 0d                JumpIfFalse [13]
@    6 : 33 03 00 00          GetNamedProperty a0, [0], [0]
@   10 : ce                   Star0 
@   11 : 0c                   LdaZero 
@   12 : 74 f9 02             TestEqualStrict r0, [2]
@   15 : a3 15                JumpIfFalse [21]
@   17 : 23 01 03             LdaGlobal [1], [3]
@   20 : cd                   Star1 
@   21 : 33 f8 02 05          GetNamedProperty r1, [2], [5]
@   25 : ce                   Star0 
@   26 : 13 03                LdaConstant [3]
@   28 : cc                   Star2 
@   29 : 65 f9 f8 f7 07       CallProperty1 r0, r1, r2, [7]
@   34 : 0e                   LdaUndefined 
@   35 : b3                   Return 
@   36 : 19 02                LdaImmutableCurrentContextSlot [2]
@   38 : b4 04                ThrowReferenceErrorIfHole [4]
@   40 : 74 03 09             TestEqualStrict a0, [9]
@   43 : a3 1d                JumpIfFalse [29]
@   45 : 23 01 03             LdaGlobal [1], [3]
@   48 : cd                   Star1 
@   49 : 33 f8 02 05          GetNamedProperty r1, [2], [5]
@   53 : ce                   Star0 
@   54 : 13 05                LdaConstant [5]
@   56 : cc                   Star2 
@   57 : 19 03                LdaImmutableCurrentContextSlot [3]
@   59 : b4 06                ThrowReferenceErrorIfHole [6]
@   61 : 3f f7 0a             Add r2, [10]
@   64 : cc                   Star2 
@   65 : 65 f9 f8 f7 0b       CallProperty1 r0, r1, r2, [11]
@   70 : 93 13                Jump [19]
@   72 : 23 01 03             LdaGlobal [1], [3]
@   75 : cd                   Star1 
@   76 : 33 f8 02 05          GetNamedProperty r1, [2], [5]
@   80 : ce                   Star0 
@   81 : 13 07                LdaConstant [7]
@   83 : cc                   Star2 
@   84 : 65 f9 f8 f7 0d       CallProperty1 r0, r1, r2, [13]
@   89 : 0e                   LdaUndefined 
@   90 : b3                   Return 
"""
        from view8 import decompile_dump
        # With pool overrides
        overrides = {
            "3f6b9aaafa49": [
                (0, '<root: length_string = "length">'),
                (1, '<root: console_string = "console">'),
                (2, '<ro-heap [0,61616] = "log">'),
            ]
        }
        res = decompile_dump(dump_text, pool_overrides=overrides)
        self.assertIn("a0.length === 0", res)
        self.assertIn('console.log("usage: node check.js <input")', res)
        self.assertNotIn("<unknown>", res)


if __name__ == '__main__':
    unittest.main()
