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
        check_fn = [f for name, f in all_func.items() if "check" in name]
        self.assertTrue(len(check_fn) > 0)
        exported = check_fn[0].export()
        self.assertIn("typeof a0 === 'string'", exported)


if __name__ == '__main__':
    unittest.main()
