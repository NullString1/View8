import os
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

from Parser.header import read_header_from_file
from Parser.sfi_file_parser import parse_file


def find_d8_binary(d8_path: Optional[str] = None, d8_dir: Optional[str] = None) -> Optional[str]:
    """Find a usable d8 binary from arguments, environment variables, PATH, or known pools."""
    candidates = []
    if d8_path and os.path.isfile(d8_path):
        return d8_path

    env_d8 = os.environ.get("JSC_D8") or os.environ.get("D8_PATH") or os.environ.get("JSC_EDIT_D8")
    if env_d8 and os.path.isfile(env_d8):
        return env_d8

    # Search directory candidates
    search_dirs = []
    if d8_dir and os.path.isdir(d8_dir):
        search_dirs.append(d8_dir)
    env_d8_dir = os.environ.get("JSC_EDIT_D8_DIR")
    if env_d8_dir and os.path.isdir(env_d8_dir):
        search_dirs.append(env_d8_dir)
    search_dirs.extend(["/tmp/opencode/d8pool", "/tmp/opencode/d8-13.6", "/tmp/opencode"])

    for sdir in search_dirs:
        if os.path.isdir(sdir):
            for entry in sorted(os.listdir(sdir), reverse=True):
                full = os.path.join(sdir, entry)
                if os.path.isfile(full) and os.access(full, os.X_OK) and ("d8" in entry):
                    return full

    which_d8 = shutil.which("d8")
    if which_d8:
        return which_d8

    return None


def run_disassembler_binary(binary_path: str, file_name: str, out_file_name: str):
    if not os.path.isfile(binary_path):
        raise FileNotFoundError(
            f"The binary '{binary_path}' does not exist. "
            "Specify a disassembler or d8 path with --d8 or --path (-p)."
        )

    real_bin = os.path.realpath(os.path.abspath(binary_path))
    bin_home = os.path.dirname(real_bin)
    bin_name = os.path.basename(real_bin).lower()

    with open(out_file_name, 'w', encoding="utf-8", errors="replace") as outfile:
        # If it is a d8 binary, run loadjsc
        if "d8" in bin_name:
            abs_input = os.path.abspath(file_name)
            cmd = [real_bin, "-e", f"loadjsc('{abs_input}')"]
            result = subprocess.run(
                cmd,
                cwd=bin_home,
                stdout=outfile,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
            )
        else:
            cmd = [real_bin, file_name]
            result = subprocess.run(
                cmd,
                cwd=bin_home,
                stdout=outfile,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
            )

        if result.returncode != 0:
            err = (result.stderr or "").strip()
            raise RuntimeError(
                f"Binary execution failed with status code {result.returncode}." + (f" Stderr: {err}" if err else "")
            )

        if result.stderr:
            sys.stderr.write(f"[!] Disassembler stderr: {result.stderr.strip()}\n")


def parse_v8cache_file(file_name: str, out_name: str, view8_dir: str, binary_path: Optional[str] = None):
    if not binary_path:
        # Try finding d8 or disassembler binary
        binary_path = find_d8_binary()
        if not binary_path:
            # Check Bin directory for any binary
            bin_dir = os.path.join(view8_dir, 'Bin')
            if os.path.isdir(bin_dir):
                for f in os.listdir(bin_dir):
                    candidate = os.path.join(bin_dir, f)
                    if os.path.isfile(candidate) and (candidate.endswith('.exe') or os.access(candidate, os.X_OK)):
                        binary_path = candidate
                        break

    if not binary_path:
        raise FileNotFoundError(
            "No disassembler or d8 binary found. Please specify --d8 <path> or --path <path>."
        )

    print(f"Executing disassembler binary: {binary_path}.")
    run_disassembler_binary(binary_path, file_name, out_name)
    print(f"Disassembly completed successfully.")


def parse_disassembled_file(out_name: str):
    print(f"Parsing disassembled file.")
    all_func = parse_file(out_name)
    print(f"Parsing completed successfully ({len(all_func)} functions found).")
    return all_func


def parse_disassembled_text(text: str):
    return parse_file(text)
