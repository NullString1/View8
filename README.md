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

## Requirements & Node.js V8 Version Matching

### Base Requirements
- **Python 3.8+** (Standard Library only; no `pip` dependencies required).
- A compatible **`d8` binary** or V8 disassembler matching target versions (e.g. V8 9.x, 10.x, 11.x, 12.x, 13.x).

### Node.js Oracle & Strict V8 Version Matching
While header decoding, root table lookup, function name discovery, and code simplification work natively in Python without Node, **resolving arbitrary read-only heap strings** relies on a Node.js deserialization oracle:

- **Which feature uses Node?**
  - Resolving opaque read-only heap string content (e.g. converting `<ro-heap [0,61616]>` into `"log"`) via runtime deserialization tracing (`--trace-deserialization`).
- **Strict V8 Version Requirement:**
  - The Node.js binary **must be built with the exact same major/minor V8 version** as the target `.jsc` bytecode. V8's internal read-only heap allocations and chunk offsets vary between engine releases.
  - **Version Reference**:
    - **V8 13.6.x** bytecode &rarr; requires **Node.js v24.x** (V8 13.6).
    - **V8 11.3.x** bytecode &rarr; requires **Node.js v20.x** (V8 11.3).
    - **V8 10.2.x** bytecode &rarr; requires **Node.js v18.x** (V8 10.2).
    - **V8 9.4.x** bytecode &rarr; requires **Node.js v16.x** (V8 9.4).
- **Graceful Fallback**:
  - If a matching Node binary is absent or has a mismatched V8 version, View8 automatically falls back to static root tables and snapshot parsing without crashing, leaving readable `<ro-heap [chunk,offset]>` references.
  - You can pass a specific Node binary via `--node /path/to/node`.

---

## Usage

### Command-Line Arguments

- `--inp`, `-i`: Path to input file (raw `.jsc` or disassembled text).
- `--out`, `-o`: Path to output file or directory tree.
- `--input_format`, `-f`: `raw` (default), `disassembled`, or `serialized`.
- `--export_format`, `-e`: `decompiled` (default), `v8_opcode`, `translated`, `serialized`.
- `--d8`: Path to `d8` executable.
- `--d8-dir`: Directory containing versioned `d8` binaries (auto-selected by version).
- `--node`: Path to `node` executable (must match target V8 version for read-only heap oracle).
- `--path`, `-p`: Path to custom disassembler binary.
- `--scope`: Propagate scope arguments (default: `1`).
- `--normalize`: Rebase address-based function names deterministically.
- `--normalize-map [CSV]`: Output CSV mapping original names to normalized names.
- `--detect-version`, `-V`: Detect V8 version, matching Node.js release, and Electron release from input JSC file and exit.
- `--tree`, `-t`: Export as hierarchical directory tree starting from root function.

### Quick Start

```bash
# Detect V8, Node.js, and Electron versions from a .jsc file and exit
python3 view8.py --inp app.jsc --detect-version

# Decompile a .jsc file directly (using auto-detected d8/node)
python3 view8.py --inp app.jsc --out app.decompiled.js

# Decompile using a specific d8 and matching Node.js binary
python3 view8.py --inp app.jsc --d8 /path/to/d8-13.6 --node /path/to/node-v24 --out app.decompiled.js

# Decompile an already disassembled dump
python3 view8.py --inp dump.txt --input_format disassembled --out app.decompiled.js
```

---

## Running Tests

```bash
python3 -m unittest discover -s tests -p "*.py"
```
