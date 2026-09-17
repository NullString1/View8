"""Constant pool resolution, root table lookup, and deserialization oracle for View8."""

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple, Union

_TABLES = None

_ORACLE_JS = r"""
const fs = require('fs'), vm = require('vm'), v8 = require('v8');
v8.setFlagsFromString('--trace-deserialization');
const data = Buffer.from(fs.readFileSync(process.argv[2]));
try {
  const d0 = Buffer.from(
      new vm.Script('"x"', { produceCachedData: true }).createCachedData());
  d0.subarray(12, 16).copy(data, 12);
} catch (e) { console.error('ORACLE-LOAD-FAIL ' + e.message); process.exit(3); }
const srclen = data.readUInt32LE(8);
try {
  const s = new vm.Script(
      '"' + '\u200b'.repeat(srclen - 2) + '"', { cachedData: data });
  if (s.cachedDataRejected) { console.error('ORACLE-REJECTED'); process.exit(4); }
  s.runInThisContext();
} catch (e) { console.error('ORACLE-LOAD-FAIL ' + e.message); process.exit(3); }
console.error('ORACLE-DONE');
"""

_RRO = re.compile(
    r"ReadOnlyHeapRef \[(\d+),\s*(\d+)\]\s*:\s*\S+\s+<String\[(\d+)\]:\s*#((?:[^>]|\\>)*)>")


def get_root_tables_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "root_tables.json")


def load_tables(version: Optional[str] = None) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return (roots, string_contents) for a V8 version (or default/latest available)."""
    global _TABLES
    if _TABLES is None:
        path = get_root_tables_path()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                _TABLES = json.load(f)
        else:
            _TABLES = {}

    if not _TABLES:
        return {}, {}

    if version and version in _TABLES:
        entry = _TABLES[version]
        return entry.get("roots", {}), entry.get("strings", {})

    # Default to first entry or empty
    first_key = next(iter(_TABLES.keys()))
    entry = _TABLES[first_key]
    return entry.get("roots", {}), entry.get("strings", {})


def _string_kind(map_name: str) -> Optional[str]:
    """'one' | 'two' | None from a map root name."""
    if not map_name.endswith("_string_map"):
        return None
    if "two_byte" in map_name:
        return "two"
    return "one"


def decode_string(rb, obj: dict, map_name: str) -> Tuple[int, str]:
    """Decode a string object: (char_length, text). Raises ValueError."""
    kind = _string_kind(map_name)
    if kind is None:
        raise ValueError(f"{map_name} is not a string map")
    payload = bytes(rb.payload)
    runs = [e for e in rb.events
            if e["op"] in ("FixedRawData", "VariableRawData")
            and "raw_start" in e
            and obj["content_start"] <= e["pos"]
            and e["end"] <= obj["content_end"]]
    if not runs:
        raise ValueError("string object has no raw runs")
    rs, re_ = runs[0]["raw_start"], runs[0]["raw_end"]
    if re_ - rs < 8:
        raise ValueError("string header truncated")
    length = struct.unpack_from("<I", payload, rs + 4)[0]
    need = length * (2 if kind == "two" else 1)
    if rs + 8 + need > re_:
        raise ValueError("string body overruns its raw run")
    raw = payload[rs + 8:rs + 8 + need]
    text = raw.decode("utf-16-le") if kind == "two" else raw.decode("latin1")
    if len(text) != length:
        raise ValueError("string length mismatch")
    return length, text


def _fmt_string(length: int, text: str) -> str:
    return f"0x0 <String[{length}]: #{text}>"


def _printable_ascii(text: str) -> bool:
    return bool(text) and all(0x20 <= ord(c) < 0x7F for c in text)


_NODE_V8 = None


def _node_v8() -> Optional[str]:
    """Cached `process.versions.v8` of PATH node (None when absent)."""
    global _NODE_V8
    if _NODE_V8 is None:
        node = shutil.which("node")
        if not node:
            return None
        try:
            proc = subprocess.run(
                [node, "-p", "process.versions.v8"], capture_output=True,
                text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        _NODE_V8 = proc.stdout.strip() if proc.returncode == 0 else ""
    return _NODE_V8 or None


def query_oracle_status(data: bytes, version: Optional[str] = None, timeout: int = 60) -> Tuple[dict, str]:
    node = shutil.which("node")
    if not node:
        return {}, "no-node"
    if version and not (_node_v8() or "").startswith(version):
        return {}, "version-mismatch"
    with tempfile.TemporaryDirectory() as tmp:
        prog = os.path.join(tmp, "oracle.js")
        target = os.path.join(tmp, "t.jsc")
        with open(prog, "w", encoding="utf-8") as f:
            f.write(_ORACLE_JS)
        with open(target, "wb") as f:
            f.write(data)
        try:
            proc = subprocess.run(
                [node, prog, target], capture_output=True, text=True,
                timeout=timeout)
        except (OSError, subprocess.SubprocessError) as e:
            return {}, f"failed: {e}"
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return {}, f"failed: {err[-1] if err else f'exit {proc.returncode}'}"
    out = {}
    for m in _RRO.finditer(proc.stdout):
        chunk, off, length, content = m.groups()
        if int(length) != len(content) or not _printable_ascii(content):
            continue
        out[(chunk, off)] = content
    return out, "ok"


def query_oracle(data: bytes, version: Optional[str] = None, timeout: int = 60) -> dict:
    found, _ = query_oracle_status(data, version, timeout)
    return found


def _content_slots(rb, pool: dict) -> list:
    children = rb.direct_children(pool)
    ops = []
    for ev in sorted(rb.events, key=lambda e: e["pos"]):
        if not (pool["content_start"] <= ev["pos"]
                and ev["end"] <= pool["content_end"]):
            continue
        if any(c["start"] < ev["pos"] and ev["end"] <= c["end"]
               for c in children):
            continue
        ops.append(ev)
    return ops


def describe_pool(rb, pool: dict, version: str) -> list:
    roots, contents = load_tables(version)
    slots: list = []
    for ev in _content_slots(rb, pool):
        op = ev["op"]
        if op in ("FixedRawData", "VariableRawData") and "raw_start" in ev:
            slots.extend([("raw", ev["raw_start"] + i * 8)
                          for i in range(ev["slots"])])
        elif op in ("FixedRepeatRoot", "VariableRepeatRoot"):
            m = re.search(r"root=(\d+)", ev["detail"])
            root = int(m.group(1)) if m else -1
            slots.extend([("repeat", root)] * ev["slots"])
        elif op == "Backref":
            slots.append(("backref", int(ev["detail"][1:-1])))
        elif op in ("RootArray", "RootArrayConstants"):
            slots.append(("root", int(ev["detail"][1:-1])))
        elif op == "ReadOnlyHeapRef":
            slots.append(("roref", ev["detail"][1:-1]))
        elif op == "HotObject":
            ident = rb.hot_identities()[ev["pos"]]
            slots.append(("backref", ident[1]) if ident[0] == "backref"
                         else ("root", ident[1]))
        elif op.startswith("NewObject"):
            slots.append(("object", ev["pos"]))
        elif op in ("WeakPrefix", "ProtectedPointerPrefix",
                    "IndirectPointerPrefix", "ResolvePendingForwardRef",
                    "Synchronize", "Nop"):
            pass
        elif op == "RegisterPendingForwardRef":
            slots.append(("pending",))
        elif op == "ClearedWeakReference":
            slots.append(("cleared",))
        else:
            raise ValueError(f"unexpected pool content op {op}")

    if len(slots) != pool["size"] - 1:
        raise ValueError(f"pool slot miscount ({len(slots)} != {pool['size'] - 1})")
    payload = bytes(rb.payload)
    return [(j, _describe_slot(rb, pool, s, payload, roots, contents))
            for j, s in enumerate(slots[1:])]


def _describe_slot(rb, pool, slot, payload, roots, contents):
    kind = slot[0]
    if kind in ("root", "repeat"):
        name = roots.get(str(slot[1]), f"root#{slot[1]}")
        if name in contents:
            return f"<root: {name} = \"{contents[name]}\">"
        return f"<root: {name}>"
    if kind == "roref":
        return f"<ro-heap [{slot[1]}]>"
    if kind == "raw":
        word = struct.unpack_from("<Q", payload, slot[1])[0]
        if word & 1 == 0:
            return f"<smi {word >> 1}>"
        return None
    if kind in ("backref", "object"):
        if kind == "backref":
            targets = [o for o in rb.objects if o["backref"] == slot[1]]
            if not targets:
                return None
            target = targets[0]
        else:
            target = next((o for o in rb.objects if o["start"] == slot[1]), None)
            if target is None:
                return None
        return _describe_object(rb, target, roots, contents)
    return None


def _describe_object(rb, obj: dict, roots, contents):
    try:
        _, rid = rb.map_root(obj)
    except Exception:
        return None
    name = roots.get(str(rid), f"root#{rid}")
    if _string_kind(name) is not None:
        try:
            length, text = decode_string(rb, obj, name)
        except ValueError:
            return None
        return _fmt_string(length, text)
    return f"[{name}]"


_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$")


def is_valid_js_identifier(s: str) -> bool:
    return bool(_IDENTIFIER_RE.match(s))


def clean_pool_value(raw_value: str) -> str:
    if not raw_value:
        return ""

    raw_str = raw_value.strip()

    # If it has a comment with a resolved value (e.g. "<unknown> ; <root: length_string = \"length\">")
    if ";" in raw_str:
        parts = raw_str.split(";", 1)
        if parts[0].strip() == "<unknown>":
            c_val = clean_pool_value(parts[1])
            if c_val and c_val != parts[1].strip():
                return c_val

    # 1. Match string formats: <String[19]: #amber-7749-octarine>
    if "<String" in raw_str:
        match = re.search(r"<String\[\d+\]:\s*#(.*?)>", raw_str)
        if match:
            s_content = match.group(1)
            return json.dumps(s_content)
        if "#" in raw_str:
            raw = raw_str.split("#", 1)[-1]
            if raw.endswith(">"):
                raw = raw[:-1]
            return json.dumps(raw)

    # 2. Match root table string mappings: <root: console_string = "console">
    root_match = re.search(r'<root:\s*[^=>]+=\s*"([^"]+)"', raw_str)
    if root_match:
        return json.dumps(root_match.group(1))

    # 3. Match read-only heap string references: <ro-heap [0,61616] = "log">
    ro_match = re.search(r'<ro-heap\s*\[[^\]]+\]\s*=\s*"([^"]+)"', raw_str)
    if ro_match:
        return json.dumps(ro_match.group(1))

    # 4. Standard root values
    if "undefined_value" in raw_str or "<Oddball: undefined>" in raw_str:
        return "undefined"
    if "null_value" in raw_str or "<Oddball: null>" in raw_str or raw_str.startswith("<Odd Oddball"):
        return "null"
    if "true_value" in raw_str or "<Oddball: true>" in raw_str:
        return "true"
    if "false_value" in raw_str or "<Oddball: false>" in raw_str:
        return "false"
    if "the_hole_value" in raw_str or "<Oddball: the_hole>" in raw_str or "the_hole" in raw_str:
        return "undefined"
    if "nan_value" in raw_str:
        return "NaN"

    # 5. Root string identifiers e.g. <root: console_string>
    if raw_str.startswith("<root:"):
        root_name = raw_str[6:].rstrip(">").strip()
        if root_name.endswith("_string"):
            ident = root_name[:-7]
            return json.dumps(ident)
        return root_name

    # 6. Already quoted JSON string (e.g. '"length"')
    if (raw_str.startswith('"') and raw_str.endswith('"')) or (raw_str.startswith("'") and raw_str.endswith("'")):
        return raw_str

    # 7. Numbers or raw literals
    if raw_str.startswith("0x") or raw_str.isdigit() or (raw_str.startswith("-") and raw_str[1:].isdigit()):
        return raw_str

    # 8. SFI names
    if "<SharedFunctionInfo" in raw_str:
        sfi_match = re.search(r"<SharedFunctionInfo\s*([^>]*)>", raw_str)
        if sfi_match:
            sfi_n = sfi_match.group(1).strip()
            if sfi_n:
                return sfi_n
        return "func_unknown"

    return raw_str


def enrich_functions_from_jsc(
    all_functions: dict,
    jsc_source: Optional[Union[str, bytes]] = None,
    version: str = "13.6.233.17",
    pool_overrides: Optional[dict] = None,
):
    """Enrich constant pools of parsed functions using raw .jsc bytes or direct pool overrides."""
    if pool_overrides:
        for fn_name, sfi in all_functions.items():
            overrides = None
            if fn_name in pool_overrides:
                overrides = pool_overrides[fn_name]
            elif hasattr(sfi, "name") and sfi.name in pool_overrides:
                overrides = pool_overrides[sfi.name]
            else:
                addr_m = re.search(r"0x[0-9a-fA-F]+", fn_name)
                if addr_m:
                    hex_val = addr_m.group(0).lower()
                    clean_hex = hex_val.removeprefix("0x")
                    if clean_hex in pool_overrides:
                        overrides = pool_overrides[clean_hex]
                    elif hex_val in pool_overrides:
                        overrides = pool_overrides[hex_val]

            if overrides:
                new_pool = list(sfi.const_pool) if sfi.const_pool else []
                for item in overrides:
                    if isinstance(item, (tuple, list)) and len(item) == 2:
                        idx, val = item
                        while len(new_pool) <= idx:
                            new_pool.append("<unknown>")
                        new_pool[idx] = clean_pool_value(str(val))
                    elif isinstance(item, str):
                        new_pool.append(clean_pool_value(item))
                sfi.const_pool = new_pool

    if not jsc_source:
        return

    data = None
    if isinstance(jsc_source, bytes):
        data = jsc_source
    elif isinstance(jsc_source, str) and os.path.isfile(jsc_source):
        with open(jsc_source, "rb") as f:
            data = f.read()

    if not data:
        return

    try:
        from Parser.rebuilder import Rebuilder
        rb = Rebuilder(data)
        ro_map, _ = query_oracle_status(data, version)

        # Match bytecode array for each function
        for sfi_name, sfi in all_functions.items():
            if not sfi.code or not sfi.const_pool:
                continue
            if not any(val == "<unknown>" for val in sfi.const_pool):
                continue

            try:
                raw_bytes = b"".join(
                    bytes.fromhex(getattr(line, "v8_opcode", None) or getattr(line, "opcode", "") or "")
                    for line in sorted(sfi.code, key=lambda l: l.line_num)
                )
                if not raw_bytes:
                    continue

                _, bc = rb.bc_for_stream(raw_bytes)
                pool_obj = rb.pool_of_bc(bc)
                resolved_slots = dict(describe_pool(rb, pool_obj, version))

                new_pool = []
                for idx, val in enumerate(sfi.const_pool):
                    if val.strip() == "<unknown>":
                        res_val = resolved_slots.get(idx)
                        if res_val:
                            # If it's a ro-heap ref, check oracle
                            ro_m = re.search(r"<ro-heap\s*\[(\d+),\s*(\d+)\]>", res_val)
                            if ro_m and (ro_m.group(1), ro_m.group(2)) in ro_map:
                                str_val = ro_map[(ro_m.group(1), ro_m.group(2))]
                                res_val = f"<ro-heap [{ro_m.group(1)},{ro_m.group(2)}] = \"{str_val}\">"
                            new_pool.append(clean_pool_value(res_val))
                        else:
                            new_pool.append(val)
                    else:
                        new_pool.append(clean_pool_value(val))
                sfi.const_pool = new_pool
            except Exception:
                continue
    except Exception as e:
        sys.stderr.write(f"[poolinfo] enrichment skipped: {e}\n")
