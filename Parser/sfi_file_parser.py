import json
import re
from typing import Dict, List, Optional

from Parser.shared_function_info import SharedFunctionInfo, CodeLine
from Parser.poolinfo import clean_pool_value

all_functions: Dict[str, SharedFunctionInfo] = {}
repeat_last_line = False


def set_repeat_line_flag(flag: bool):
    global repeat_last_line
    repeat_last_line = flag


def get_next_line(file: str):
    with open(file, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield line
            if repeat_last_line:
                set_repeat_line_flag(False)
                yield line
    yield None


def parse_array(lines, func_name: str) -> str:
    line = next(lines)
    if "Start " not in line:
        raise Exception(f"Error got line \"{line}\" not Start Array")
    const_list = parse_const_array(lines, func_name)
    array_literal = "[" + ", ".join(const_list) + "]"
    while True:
        line = next(lines)
        if line is None or "End " in line:
            break
    line = next(lines)
    if line != ">" and line is not None:
        set_repeat_line_flag(True)
    return array_literal


def parse_object(lines, func_name: str) -> str:
    line = next(lines)
    if "Start " not in line:
        raise Exception(f"Error got line \"{line}\" not Start Object")
    const_arr = parse_const_array(lines, func_name)
    items = const_arr[1:] if len(const_arr) > 1 else []
    const_list = iter(items)
    pairs = []
    while True:
        try:
            key = next(const_list)
            val = next(const_list)
            pairs.append(f"{key}: {val}")
        except StopIteration:
            break
    object_literal = "{" + ", ".join(pairs) + "}"
    while True:
        line = next(lines)
        if line is None or "End " in line:
            break
    return object_literal


def parse_bytecode_line(line: str) -> CodeLine:
    match = re.search(r"^[^@]*@\s*(\d+)\s*:\s*([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s+([A-Za-z]\S*.*)$", line)
    if match:
        offset, opcode, inst = match.groups()
        return CodeLine(opcode=opcode.strip(), line=int(offset), inst=inst.strip())
    # Try simpler fallback match
    match_fallback = re.search(r"@\s*(\d+)\s*:\s*(.+)$", line)
    if match_fallback:
        offset, rest = match_fallback.groups()
        parts = rest.strip().split(None, 1)
        opcode = parts[0] if parts else ""
        inst = parts[1] if len(parts) > 1 else opcode
        return CodeLine(opcode=opcode, line=int(offset), inst=inst)
    raise ValueError(f"Invalid bytecode line format: {line}")


def parse_bytecode(line: str, lines) -> List[CodeLine]:
    code_list = []
    while line and " @ " in line:
        code_list.append(parse_bytecode_line(line))
        line = next(lines)
    set_repeat_line_flag(True)
    return code_list


def parse_const_line(lines, func_name: str):
    var_line = next(lines)
    match = re.search(r"^(\d+(?:\-\d+)?):\s*(0x[0-9a-fA-F]+\s*)?(.+)", var_line)
    if not match:
        raise ValueError(f"Invalid constant line format: {var_line}")

    idx_range, address, value = match.groups()
    var_idx = int(idx_range.split('-')[-1]) + 1
    value = value.strip()

    if not address:
        return var_idx, value
    if value.startswith("<String"):
        return var_idx, clean_pool_value(value)
    if value.startswith("<SharedFunctionInfo"):
        sfi_match = re.search(r"<SharedFunctionInfo\s*([^>]*)>", value)
        sfi_name = sfi_match.group(1).strip() if sfi_match else ""
        return var_idx, parse_shared_function_info(lines, sfi_name, func_name)
    if value.startswith("<ArrayBoilerplateDescription") or value.startswith("<FixedArray"):
        return var_idx, parse_array(lines, func_name)
    if value.startswith("<ObjectBoilerplateDescription"):
        return var_idx, parse_object(lines, func_name)
    if value.startswith("<Odd Oddball") or value.startswith("<Oddball:"):
        return var_idx, clean_pool_value(value)
    if "<root:" in value or "<ro-heap" in value:
        return var_idx, clean_pool_value(value)
    return var_idx, value.rstrip('>').split(" ", 1)[-1]


def parse_const_array(lines, func_name: str) -> List[str]:
    while True:
        line = next(lines)
        if line is None:
            return []
        if "- length:" in line or "length:" in line:
            break
    m = re.search(r"length:\s*(\d+)", line)
    size = int(m.group(1)) if m else 0
    if not size:
        return []

    while True:
        line = next(lines)
        if line is None:
            return []
        if line.startswith("0") or re.match(r"^\d+:", line):
            break
    set_repeat_line_flag(True)

    value = ""
    next_idx = 0
    const_list = []

    for idx in range(size):
        if next_idx != idx:
            const_list.append(value)
            continue
        next_idx, value = parse_const_line(lines, func_name)
        const_list.append(value)

    return const_list


def parse_const_pool(line: str, lines, func_name: str) -> List[str]:
    if "size = 0" in line:
        return []
    return parse_const_array(lines, func_name)


def parse_exception_table_line(line: str):
    m = re.search(r"\((\d+)\s*,\s*(\d+)\)\s*->\s*(\d+)", line)
    if m:
        from_, to_, key = m.group(1), m.group(2), m.group(3)
        return int(key), [int(from_), int(to_)]
    return 0, [0, 0]


def parse_handler_table(line: str, lines) -> Dict[int, List[int]]:
    if "size = 0" in line:
        return {}
    exception_table = {}
    next(lines)
    while True:
        line = next(lines)
        if not line or " -> " not in line:
            break
        key, value = parse_exception_table_line(line)
        exception_table[key] = value
    set_repeat_line_flag(True)
    return exception_table


def parse_parameter_count(line: str) -> int:
    m = re.search(r"Parameter count\s*(\d+)", line, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def parse_register_count(line: str) -> int:
    m = re.search(r"Register count\s*(\d+)", line, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def parse_address(line: str) -> str:
    m = re.search(r"^(0x[0-9a-fA-F]+)", line)
    if m:
        return m.group(1)
    parts = line.split(":", 1)
    return parts[0].strip()


def parse_shared_function_info(lines, name: str = "", declarer=None) -> str:
    sfi = SharedFunctionInfo()
    sfi.declarer = declarer
    sfi.name = 'func_unknown'
    real_name = name.strip() if name else ""
    address = ""

    while True:
        line = next(lines)
        if line is None or line == "End SharedFunctionInfo":
            break

        if "Parameter count" in line or "parameter_count:" in line:
            sfi.argument_count = parse_parameter_count(line)
        elif "Register count" in line or "register_count:" in line:
            sfi.register_count = parse_register_count(line)
        elif "Constant pool" in line or "constant_pool:" in line:
            sfi.const_pool = parse_const_pool(line, lines, sfi.name)
        elif "Handler Table" in line or "handler_table:" in line:
            sfi.exception_table = parse_handler_table(line, lines)
        elif "@    0 : " in line or re.match(r"^[^@]*@\s*0\s*:\s*", line):
            sfi.code = parse_bytecode(line, lines)
        elif "- name:" in line:
            nm = re.search(r"- name:\s*<String\[\d+\]:\s*#([^>]*)>", line)
            if nm and nm.group(1).strip():
                real_name = nm.group(1).strip()
        elif "[SharedFunctionInfo]" in line or "[BytecodeArray]" in line:
            address = parse_address(line)
            # Check for embedded SFI name in bracket line
            sfi_m = re.search(r"<SharedFunctionInfo\s*([^>]*)>", line)
            if sfi_m and sfi_m.group(1).strip() and not real_name:
                real_name = sfi_m.group(1).strip()

    func_id = real_name if real_name else "unknown"
    if address:
        sfi.name = f'func_{func_id}_{address}'
    else:
        sfi.name = f'func_{func_id}'

    sfi.real_name = real_name
    all_functions[sfi.name] = sfi

    if not sfi.is_fully_parsed():
        # Fill defaults if missing
        if sfi.argument_count is None:
            sfi.argument_count = 0
        if sfi.register_count is None:
            sfi.register_count = 0
        if sfi.const_pool is None:
            sfi.const_pool = []
        if sfi.exception_table is None:
            sfi.exception_table = {}
        if sfi.code is None:
            sfi.code = []

    return sfi.name


def parse_file(file: str = "test.txt") -> Dict[str, SharedFunctionInfo]:
    global all_functions
    all_functions = {}
    lines = get_next_line(file)
    while True:
        line = next(lines)
        if line is None:
            break
        if line == "Start SharedFunctionInfo" or "SharedFunctionInfo" in line or "[BytecodeArray]" in line:
            set_repeat_line_flag(True)
            parse_shared_function_info(lines, "start")
            break

    return all_functions


if __name__ == '__main__':
    parse_file()
