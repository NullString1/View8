# View8 (Enhanced)

**View8** is a static analysis and reverse engineering tool designed to decompile serialized V8 bytecode objects (`.jsc` files / Bytenode caches) into readable, high-level JavaScript-like pseudocode.

This enhanced version brings major decompilation improvements, pure Python snapshot and header analysis, and cross-platform Linux / macOS / Windows support.

---

## Before vs After Comparison

### Original View8 Output
```javascript
function func_unknown_0x1338ca92f959(a0, a1, a2, a3, a4)
{
    r1 = Scope[0]
    Scope[1][2] = "amber-7749-octarine"
    Scope[1][3] = "FLAG{jsc_round_trip_works}"
    ACCU = func_unknown_0x1338ca92fa49(process["argv"][2])
    return undefined
}
function func_unknown_0x1338ca92fa49(a0)
{
    if (!(typeof(a0) == string))
        || (a0[<unknown>] === 0)
    {
        ACCU = <unknown>[<unknown>]("usage: node check.js <input")
        return undefined
    }
    if (a0 === Scope[1][2])
    {
        ACCU = <unknown>[<unknown>](("ACCESS GRANTED: " + Scope[1][3]))
    }
    else
    {
        ACCU = <unknown>[<unknown>]("denied")
    }
    return undefined
}
```

### Enhanced View8 Output
```javascript
function func_unknown_0x1338ca92f959(a0, a1, a2, a3, a4)
{
    r1 = Scope[0]
    Scope[1][2] = "amber-7749-octarine"
    Scope[1][3] = "FLAG{jsc_round_trip_works}"
    func_check_0x1338ca92fa49(process.argv[2])
    return undefined
}
function func_check_0x1338ca92fa49(a0)
{
    if (!(typeof a0 === 'string') || (a0.length === 0))
    {
        console.log("usage: node check.js <input>");
        return undefined
    }
    if (a0 === Scope[1][2])
    {
        console.log(("ACCESS GRANTED: " + Scope[1][3]));
    }
    else
    {
        console.log("denied");
    }
    return undefined
}
```

---

## Key Improvements

1. **Pure Python Header Parsing & Cross-Platform Support**:
   - Native Python decoder (`Parser/header.py`) for both legacy (24-byte) and modern (28/32-byte) `.jsc` headers.
   - Removed Windows-only `VersionDetector.exe` requirement; works seamlessly across Linux, macOS, and Windows.
   - Flexible disassembler CLI options: `--d8`, `--d8-dir`, and `--node` with automatic PATH / directory scanning.

2. **Constant Pool & Root Table Enrichment**:
   - Automatically resolves `<unknown>` pool slots using snapshot bytecode deserialization and root table lookup (`Parser/poolinfo.py`, `Parser/root_tables.json`).
   - Identifies runtime globals (`console`, `process`, `Math`), read-only heap strings (`log`, `length`), and oddballs (`undefined`, `null`, `true`, `false`, `NaN`).

3. **Accurate SFI Function Name Resolution**:
   - Resolves actual function names from `[SharedFunctionInfo]` metadata and string pools (e.g. `check`, `alpha`, `beta`) rather than generic `func_unknown_<address>`.

4. **Modern JavaScript Syntax Translation**:
   - **`TestTypeOf`**: Translates opcode type flags (#0..#7) to standard strict JavaScript expressions (e.g. `typeof a0 === 'string'`).
   - **Dot Property Notation**: Automatically formats property lookups using standard dot notation (`process.argv[2]`, `a0.length`, `console.log`) instead of bracketed strings.
   - **Call Expression Folding**: Eliminates redundant intermediate `ACCU = ...` lines for standalone statement calls.
   - **Zero External Dependencies**: Pure standard-library Python without requiring 3rd-party packages.

---

## Requirements

- Python 3.8+ (Standard Library only)
- A compatible `d8` binary or V8 disassembler (e.g. V8 9.x, 10.x, 11.x, 12.x, 13.x).

---

## Usage

### Command-Line Arguments

- `--inp`, `-i`: Path to input file (raw `.jsc` or disassembled text).
- `--out`, `-o`: Path to output file or directory tree.
- `--input_format`, `-f`: `raw` (default), `disassembled`, or `serialized`.
- `--export_format`, `-e`: `decompiled` (default), `v8_opcode`, `translated`, `serialized`.
- `--d8`: Path to `d8` executable.
- `--d8-dir`: Directory containing versioned `d8` binaries (auto-selected by version).
- `--node`: Path to `node` executable.
- `--path`, `-p`: Path to custom disassembler binary.
- `--scope`: Propagate scope arguments (default: `1`).
- `--normalize`: Rebase address-based function names deterministically.
- `--normalize-map [CSV]`: Output CSV mapping original names to normalized names.
- `--tree`, `-t`: Export as hierarchical directory tree starting from root function.

### Quick Start

```bash
# Decompile a .jsc file directly
python3 view8.py --inp app.jsc --out app.decompiled.js

# Decompile using a specific d8 binary
python3 view8.py --inp app.jsc --d8 /path/to/d8 --out app.decompiled.js

# Decompile an already disassembled dump
python3 view8.py --inp dump.txt --input_format disassembled --out app.decompiled.js
```

---

## Running Tests

```bash
python3 -m unittest discover -s tests -p "*.py"
```
