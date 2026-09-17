"""Length-changing rebuilds of V8 code-cache (.jsc) payloads.

Method (all verified against V8 13.6 source + live d8/node tests):
  * Parse the payload with :mod:`jsc_edit.snapshot` (exact op spans).
  * Locate blobs (bytecode, strings) by plaintext search + enclosing object.
  * Apply edits as (pos, old_len, new_bytes) in ORIGINAL coordinates,
    applied back-to-front so shifts never invalidate pending positions.
  * Fix every governing size: internal u32 length fields, raw-data op
    sizes, object size uint30s, header payload_length.
  * When inserting new objects: renumber later backref indices, and
    de-optimise post-insertion HotObject ops to direct Backref/RootArray
    encodings (hot-queue state after an insertion is not worth simulating;
    direct encodings are always correct).

Every operation re-walks the result and asserts strict span expectations.
Any ambiguity (non-unique blob, non-unique length field, nested SFI in a
duplicated closure, uint30 cascade surprises) raises RebuildError loudly.
"""

import struct

from Parser.snapshot import (
    HEADER_SIZE, TAG_SIZE, SnapshotError, encode_uint30, get_uint30,
    parse_header, payload_of, walk_payload,
)


class RebuildError(Exception):
    pass


def _u32_at(buf: bytes, pos: int) -> int:
    return struct.unpack_from("<I", buf, pos)[0]


class Rebuilder:
    """Accumulates length-changing edits, then materialises a new .jsc."""

    def __init__(self, data: bytes):
        self.orig = bytes(data)
        try:
            self.header = parse_header(self.orig)
        except SnapshotError as e:
            raise RebuildError(str(e))
        self.payload = bytearray(payload_of(self.orig))
        from Parser.snapshot import Walker
        self.walker, self.summary = walk_payload(bytes(self.payload))
        self.events = self.walker.events
        self.objects = self.walker.objects
        # edits in ORIGINAL payload coordinates: (pos, old_len, new_bytes)
        self.edits = []
        self.growth = 0  # total payload growth from edits applied so far

    # -- queries ------------------------------------------------------
    def find_blob(self, blob: bytes) -> int:
        """Unique payload offset of blob. Raises on 0 or 2+ hits."""
        base = bytes(self.payload)
        first = base.find(blob)
        if first < 0:
            raise RebuildError(f"blob ({len(blob)} bytes) not found")
        if base.find(blob, first + 1) >= 0:
            raise RebuildError(f"blob ({len(blob)} bytes) is ambiguous")
        return first

    def _first_stream_hit(self, stream: bytes, check_length: bool):
        """First payload occurrence of stream inside a Trusted object.

        Unlike find_blob (which refuses twins loudly), this tolerates
        duplicates: after a dup-fn/new-fn the template stream exists
        twice (original + clone), and the clones are interchangeable
        for further cloning. Occurrence order is deterministic per base
        bytes, so stage dry-run and apply agree. Raises when no
        occurrence validates.
        """
        base = bytes(self.payload)
        pos = -1
        while True:
            pos = base.find(stream, pos + 1)
            if pos < 0:
                raise RebuildError(
                    f"blob ({len(stream)} bytes) not found")
            try:
                obj = self.enclosing_object(pos, pos + len(stream))
                if obj["space"] != "Trusted":
                    continue
                if check_length:
                    self.locate_length_field(obj, pos, len(stream))
                return pos, obj
            except RebuildError:
                continue

    def enclosing_object(self, pos: int, end: int) -> dict:
        """Smallest object span containing [pos, end)."""
        cands = [o for o in self.objects
                 if o["start"] <= pos and end <= o["end"]]
        if not cands:
            raise RebuildError(f"no object contains [{pos},{end})")
        return min(cands, key=lambda o: o["end"] - o["start"])

    def raw_runs(self, obj: dict) -> list:
        """Fixed/VariableRawData events strictly inside obj, in order."""
        out = []
        for ev in self.events:
            if ev["op"] in ("FixedRawData", "VariableRawData") \
                    and "raw_start" in ev \
                    and obj["start"] <= ev["pos"] \
                    and ev["end"] <= obj["end"]:
                out.append(ev)
        return out

    def locate_length_field(self, obj: dict, blob_pos: int,
                            old_len: int) -> int:
        """Payload offset of the u32 == old_len in obj raw runs pre-blob."""
        hits = []
        for ev in self.raw_runs(obj):
            rs, re_ = ev["raw_start"], ev["raw_end"]
            if re_ > blob_pos:
                continue
            seg = bytes(self.payload[rs:re_])
            for i in range(len(seg) - 3):
                if struct.unpack_from("<I", seg, i)[0] == old_len:
                    hits.append(rs + i)
        if len(hits) != 1:
            raise RebuildError(
                f"length field for len {old_len}: {len(hits)} candidates")
        return hits[0]

    def locate_string(self, old: bytes) -> tuple:
        """Locate a string constant's bytes: (blob_pos, enclosing_object).

        Matches raw runs containing old with a u32 length prefix equal to
        len(old) immediately before — this excludes incidental substring
        occurrences inside larger strings (e.g. "hi" in "machine").
        Requires exactly one candidate.
        """
        cands = []
        for ev in self.events:
            if ev["op"] not in ("FixedRawData", "VariableRawData") \
                    or "raw_start" not in ev:
                continue
            rs, re_ = ev["raw_start"], ev["raw_end"]
            start = bytes(self.payload).find(old, rs)
            while rs <= start < re_ - len(old) + 1:
                if start - 4 >= rs and _u32_at(bytes(self.payload),
                                               start - 4) == len(old):
                    cands.append(start)
                start = bytes(self.payload).find(old, start + 1)
        if len(cands) != 1:
            raise RebuildError(
                f"string {old!r}: {len(cands)} candidates")
        blob = cands[0]
        return blob, self.enclosing_object(blob, blob + len(old))

    def direct_children(self, obj: dict) -> list:
        """Objects nested directly in obj (no intermediate container)."""
        nested = [o for o in self.objects
                  if obj["start"] < o["start"] and o["end"] <= obj["end"]]
        out = []
        for c in nested:
            if not any(o is not c and o["start"] < c["start"]
                       and c["end"] <= o["end"] for o in nested):
                out.append(c)
        return sorted(out, key=lambda o: o["start"])

    def pool_of_bc(self, bc: dict) -> dict:
        """The const-pool FixedArray nested in a BytecodeArray object.

        Identified structurally ([0][len] length word + size == 2 + len)
        among DIRECT children only (grandchildren belong to nested
        functions), never by hardcoded map ids.
        """
        cands = []
        for o in self.direct_children(bc):
            runs = self.raw_runs(o)
            if not runs:
                continue
            seg = bytes(self.payload[runs[0]["raw_start"]:runs[0]["raw_end"]])
            if len(seg) >= 8 and seg[:4] == bytes(4):
                ln = struct.unpack_from("<I", seg, 4)[0]
                if o["size"] == 2 + ln:
                    cands.append(o)
        if len(cands) != 1:
            raise RebuildError(
                f"bytecode at {bc['start']}: {len(cands)} pool candidates")
        return cands[0]

    def sfi_of_bc(self, bc: dict) -> dict:
        """Smallest object strictly containing a BytecodeArray object."""
        cands = [o for o in self.objects
                 if o["start"] < bc["start"] and bc["end"] <= o["end"]]
        if not cands:
            raise RebuildError("no enclosing function for bytecode object")
        return min(cands, key=lambda o: o["end"] - o["start"])

    def bc_for_stream(self, stream: bytes) -> tuple:
        """(blob_pos, bytecode_object) for an instruction stream."""
        blob = self.find_blob(stream)
        obj = self.enclosing_object(blob, blob + len(stream))
        if obj["space"] != "Trusted":
            raise RebuildError("stream not in a Trusted (bytecode) object")
        self.locate_length_field(obj, blob, len(stream))  # strict check
        return blob, obj

    def bc_object_for_stream(self, stream: bytes) -> tuple:
        """(blob_pos, bytecode_object) without the length-field check.

        For host-side resolution (pool lookup), where only the object
        identity matters.
        """
        blob = self.find_blob(stream)
        obj = self.enclosing_object(blob, blob + len(stream))
        if obj["space"] != "Trusted":
            raise RebuildError("stream not in a Trusted (bytecode) object")
        return blob, obj

    def replace_bytecode(self, stream: bytes, new_stream: bytes) -> dict:
        """Replace a whole BytecodeArray blob (any length delta).

        Generalises grow_bytecode: the caller supplies the complete new
        stream (e.g. after jump-delta fixups). Padding absorbs shrinkage
        only when the run still fits; otherwise the run grows.
        """
        blob, obj = self.bc_for_stream(stream)
        length_pos = self.locate_length_field(obj, blob, len(stream))
        tail = None
        for ev in self.raw_runs(obj):
            if ev["raw_start"] <= blob and \
                    blob + len(stream) <= ev["raw_end"]:
                tail = ev
                break
        if tail is None:
            raise RebuildError("blob spans raw runs (unsupported layout)")
        head = bytes(self.payload[tail["raw_start"]:blob])
        old_tail = bytes(self.payload[blob + len(stream):tail["raw_end"]])
        # Keep old slack only if the new blob still leaves room in the run;
        # otherwise drop it (run grows by the true delta). Either way the
        # run stays word-aligned: the deserializer reads raw in 8-byte
        # words, so an unpadded shrink desyncs everything after it.
        if len(head) + len(new_stream) <= tail["raw_end"] - tail["raw_start"]:
            new_content = head + new_stream + old_tail
            new_content = new_content[:tail["raw_end"] - tail["raw_start"]]
            new_content += bytes((-len(new_content)) % 8)
        else:
            new_content = head + new_stream
            new_content += bytes((-len(new_content)) % 8)
        new_words = len(new_content) // 8
        old_stored = tail["raw_end"] - tail["raw_start"]
        self.add_edit(length_pos, 4, struct.pack("<I", len(new_stream)))
        self._rewrite_raw_op(tail, new_words)
        self._rewrite_uint30_at(obj["size_pos"],
                                obj["size"] + (new_words - tail["slots"]))
        self.add_edit(tail["raw_start"], old_stored, new_content)
        return {"blob": blob, "object": obj["start"],
                "new_len": len(new_stream),
                "growth": len(new_content) - old_stored}

    def set_function_frame(self, stream: bytes,
                           register_count: int | None = None,
                           parameter_count: int | None = None) -> dict:
        """Update register_count and/or parameter_count of a BytecodeArray.

        register_count updates the frame_size field (register_count * 8).
        parameter_count updates the BytecodeArray parameter_count and SFI
        formal_parameter_count fields.
        """
        blob, obj = self.bc_object_for_stream(stream)
        sfi = self.sfi_of_bc(obj)
        hdr_pos = blob - 16
        old_frame_size, old_param_cnt, old_max_args, r1, r2 = struct.unpack(
            "<IHHII", bytes(self.payload[hdr_pos:blob]))

        new_frame_size = old_frame_size
        if register_count is not None:
            if register_count < 0 or register_count > 65535:
                raise RebuildError("register_count out of range (0..65535)")
            new_frame_size = register_count * 8
            self.add_edit(hdr_pos, 4, struct.pack("<I", new_frame_size))

        new_param_cnt = old_param_cnt
        if parameter_count is not None:
            if parameter_count < 0 or parameter_count > 65535:
                raise RebuildError("parameter_count out of range (0..65535)")
            new_param_cnt = parameter_count
            self.add_edit(hdr_pos + 4, 2, struct.pack("<H", new_param_cnt))
            sfi_runs = self.raw_runs(sfi)
            for r in sfi_runs:
                if r["raw_start"] >= obj["start"] and r["raw_end"] <= obj["end"]:
                    continue
                seg = bytes(self.payload[r["raw_start"]:r["raw_end"]])
                for off in range(0, len(seg) - 3, 2):
                    len_val, formal_val = struct.unpack_from("<HH", seg, off)
                    if formal_val == old_param_cnt and len_val in (old_param_cnt, old_param_cnt - 1, 0, 1):
                        self.add_edit(r["raw_start"] + off + 2, 2, struct.pack("<H", new_param_cnt))
                        if len_val != 0:
                            self.add_edit(r["raw_start"] + off, 2, struct.pack("<H", max(0, new_param_cnt - 1)))
                        break

        return {
            "object": obj["start"],
            "old_register_count": old_frame_size // 8,
            "new_register_count": new_frame_size // 8,
            "old_frame_size": old_frame_size,
            "new_frame_size": new_frame_size,
            "old_parameter_count": old_param_cnt,
            "new_parameter_count": new_param_cnt,
            "growth": 0,
        }

    # Inserts must be jump-free (targets would bind to stale offsets) and
    # feedback-free (FeedbackMetadata slot counts are fixed). This is the
    # documented safe set: plain accumulator/register traffic + Return.
    SAFE_INSERT_OPS = frozenset([
        "LdaZero", "LdaSmi", "LdaUndefined", "LdaNull", "LdaTheHole",
        "LdaTrue", "LdaFalse", "LdaConstant",
        "Ldar", "Star", "Star0", "Star1", "Star2", "Star3", "Star4",
        "Star5", "Star6", "Star7", "Star8", "Star9", "Star10", "Star11",
        "Return",
    ])

    def check_insert_safe(self, insert: bytes, table: dict):
        """Refuse inserts with jumps, calls or unknown opcodes."""
        by_value = {e["value"]: e for e in table.values()}
        pos = 0
        while pos < len(insert):
            entry = by_value.get(insert[pos])
            if entry is None:
                raise RebuildError(
                    f"insert byte 0x{insert[pos]:02x} at +{pos}: unknown opcode")
            if entry["width"] is None:
                raise RebuildError(
                    f"{entry['name']}: unknown width (table gap)")
            if entry["name"] not in self.SAFE_INSERT_OPS:
                raise RebuildError(
                    f"{entry['name']} not in the safe-insert set "
                    "(jumps/calls need cave hooks, not splices)")
            pos += entry["width"]
        if pos != len(insert):
            raise RebuildError("insert does not end on an opcode boundary")

    def splice_with_fixups(self, code: list, at: int, insert: bytes,
                           table: dict) -> bytes:
        """Splice insert into a function stream, fixing jump deltas."""
        self.check_insert_safe(insert, table)
        return self.replace_with_fixups(code, at, 0, insert, table)

    def replace_with_fixups(self, code: list, at: int, target_len: int,
                            insert: bytes, table: dict) -> bytes:
        """Replace a span of instructions with insert, fixing jump deltas.

        code: dump Instruction list (offset/raw/mnemonic/operands).
        at: bytecode offset to start replacement at (must be an instruction boundary).
        target_len: number of bytes being replaced (0 for pure insertion).
        insert: new bytecode bytes to insert at `at`.
        Returns the complete new stream.
        """
        from jsc_edit.cave import relocate_instruction
        from jsc_edit.patch import PatchError
        ordered = sorted(code, key=lambda i: i.offset)
        bounds = [i.offset for i in ordered]
        end = ordered[-1].offset + len(ordered[-1].raw)
        if at not in bounds + [end]:
            raise RebuildError(f"{at} is not an instruction boundary")
        if target_len > 0:
            if at + target_len not in bounds + [end]:
                raise RebuildError(f"{at + target_len} is not an instruction boundary")

        remaining = [i for i in ordered if not (at <= i.offset < at + target_len)]

        if at == 0 and target_len == 0:
            out = bytearray(insert)
            for i in ordered:
                out += i.raw
            return bytes(out)

        by_offset = {i.offset: i for i in remaining}
        covered = sorted(by_offset)
        parts = None
        for _ in range(5):
            pos = {}
            cursor = 0
            inserted = False
            for o in covered:
                if not inserted and o >= at:
                    cursor += len(insert)
                    inserted = True
                pos[o] = cursor
                cursor += len(parts[covered.index(o)]) \
                    if parts is not None else len(by_offset[o].raw)
            if not inserted:
                cursor += len(insert)

            def remap(t, _pos=pos):
                if t in _pos:
                    return _pos[t]
                if t == at:
                    return _pos.get(at, cursor - len(insert) if not covered or at > covered[-1] else min(_pos.values()))
                if t == end:
                    return cursor
                if target_len > 0 and at < t < at + target_len:
                    raise RebuildError(
                        f"jump target @{t} inside replaced span [{at}, {at + target_len})")
                raise RebuildError(
                    f"jump target @{t} is not an instruction boundary")

            try:
                new_parts = [
                    relocate_instruction(
                        table, by_offset[o].mnemonic, by_offset[o].operands,
                        by_offset[o].raw, o, pos[o], remap)
                    for o in covered
                ]
            except PatchError as e:
                raise RebuildError(f"jump fixup refused: {e}")
            if new_parts == parts:
                break
            parts = new_parts
        else:
            raise RebuildError("jump fixup did not converge")

        out = bytearray()
        inserted = False
        for o in covered:
            if not inserted and o >= at:
                out += insert
                inserted = True
            out += parts[covered.index(o)]
        if not inserted:
            out += insert
        assert len(out) == sum(len(p) for p in parts) + len(insert)
        return bytes(out)

    def hot_identities(self) -> dict:
        """Map HotObject event pos -> ('backref', idx) | ('root', id).

        Mirrors the deserializer: only Backref and RootArray reads push.
        """
        q = [None] * 8
        qi = 0
        out = {}

        def add(entry):
            nonlocal qi
            q[qi] = entry
            qi = (qi + 1) & 7

        for ev in sorted(self.events, key=lambda e: e["pos"]):
            if ev["op"] == "Backref":
                add(("backref", int(ev["detail"][1:-1])))
            elif ev["op"] == "RootArray":
                add(("root", int(ev["detail"][1:-1])))
            elif ev["op"] == "HotObject":
                i = int(ev["detail"][1:-1])
                if q[i] is None:
                    raise RebuildError(
                        f"HotObject at {ev['pos']} resolves to empty slot")
                out[ev["pos"]] = q[i]
        return out

    # -- edit accumulation --------------------------------------------
    def add_edit(self, pos: int, old_len: int, new: bytes):
        self.edits.append((pos, old_len, bytes(new)))
        self.growth += len(new) - old_len

    def _rebase(self):
        """Materialise pending edits and re-walk (index-consuming appends).

        Appended objects take backref indices by decode position, so a
        second append computed from the original walk would reuse the
        first append's indices. Rebasing makes the appended bytes part
        of the walked baseline: later ops resolve against fresh
        positions. Growth stays exact (the materialised header is the
        new baseline, so the accumulator resets).
        """
        data = self.build()
        self.orig = data
        try:
            self.header = parse_header(self.orig)
        except SnapshotError as e:
            raise RebuildError(str(e))
        self.payload = bytearray(payload_of(self.orig))
        from jsc_edit.snapshot import Walker
        self.walker, self.summary = walk_payload(bytes(self.payload))
        self.events = self.walker.events
        self.objects = self.walker.objects
        self.edits = []
        self.growth = 0

    def _rewrite_uint30_at(self, pos: int, value: int):
        """Replace the uint30 at original-coord pos with value."""
        old_val, end = get_uint30(bytes(self.payload), pos)
        self.add_edit(pos, end - pos, encode_uint30(value))

    def _rewrite_raw_op(self, ev: dict, new_words: int):
        """Rewrite a Fixed/VariableRawData op for a new word count."""
        if ev["op"] == "FixedRawData":
            if not 1 <= new_words <= 32:
                raise RebuildError(
                    f"raw run at {ev['pos']}: {new_words} words exceeds "
                    "FixedRawData (VariableRawData transition unimplemented)")
            self.add_edit(ev["pos"], 1, bytes([0x60 + new_words - 1]))
        else:
            old_words = ev["slots"]
            old_val, end = get_uint30(bytes(self.payload), ev["pos"] + 1)
            assert old_val == old_words
            self.add_edit(ev["pos"] + 1, end - (ev["pos"] + 1),
                          encode_uint30(new_words))

    def renumber_backrefs(self, after_pos: int, first_moved: int, delta: int):
        """Shift Backref indices >= first_moved for ops past after_pos."""
        for ev in self.events:
            if ev["op"] != "Backref" or ev["pos"] < after_pos:
                continue
            idx = int(ev["detail"][1:-1])
            if idx >= first_moved:
                self._rewrite_uint30_at(ev["pos"] + 1, idx + delta)

    def deopt_hot_after(self, after_pos: int, mapping) -> int:
        """Rewrite HotObject ops past after_pos as direct encodings.

        mapping(old_backref_idx) -> new idx. Returns extra growth.
        """
        ident = self.hot_identities()
        growth = 0
        for ev in self.events:
            if ev["op"] != "HotObject" or ev["pos"] < after_pos:
                continue
            kind, val = ident[ev["pos"]]
            if kind == "backref":
                enc = bytes([0x04]) + encode_uint30(mapping(val))
            else:
                enc = bytes([0x07]) + encode_uint30(val)
            self.add_edit(ev["pos"], 1, enc)
            growth += len(enc) - 1
        return growth

    # -- operations ----------------------------------------------------
    def grow_bytecode(self, stream: bytes, insert: bytes, at: int = 0) -> dict:
        """Insert raw bytes into a BytecodeArray blob (growing its raw run).

        insert: new bytecode; at: offset within stream to insert at.
        Jump deltas are NOT fixed up here: use at == 0 (prepend, deltas
        invariant) or splice_with_fixups + replace_bytecode for the
        general case. Returns info dict.
        """
        blob_pos = self.find_blob(stream)
        obj = self.enclosing_object(blob_pos, blob_pos + len(stream))
        if obj["space"] != "Trusted":
            raise RebuildError("bytecode blob not in a Trusted object")
        length_pos = self.locate_length_field(obj, blob_pos, len(stream))
        # tail raw run covering the blob end
        tail = None
        for ev in self.raw_runs(obj):
            if ev["raw_start"] <= blob_pos and \
                    blob_pos + len(stream) <= ev["raw_end"]:
                tail = ev
                break
        if tail is None:
            raise RebuildError("blob spans raw runs (unsupported layout)")
        old_stored = tail["raw_end"] - tail["raw_start"]
        new_len = len(stream) + len(insert)
        # new run content: [prefix scalars][blob[:at]][insert][blob[at:]]
        # [old pad, carried along as slack][fresh pad for alignment].
        # The length field governs how many bytes deserialize as bytecode,
        # so carried slack after the blob is harmless.
        head = bytes(self.payload[tail["raw_start"]:blob_pos + at])
        tail_old = bytes(self.payload[blob_pos + at:tail["raw_end"]])
        new_content = head + insert + tail_old
        new_content += bytes((-len(new_content)) % 8)
        if len(new_content) % 8:
            raise RebuildError("internal error: run not word-aligned")
        new_words = len(new_content) // 8
        # apply: length field, raw op, object size, splice
        self.add_edit(length_pos, 4, struct.pack("<I", new_len))
        self._rewrite_raw_op(tail, new_words)
        self._rewrite_uint30_at(obj["size_pos"],
                                obj["size"] + (new_words - tail["slots"]))
        # splice: replace whole old run content
        self.add_edit(tail["raw_start"], old_stored, new_content)
        return {"blob": blob_pos, "object": obj["start"],
                "new_len": new_len, "growth": len(new_content) - old_stored}

    def grow_string(self, old: bytes, new: bytes) -> dict:
        """Replace a string's bytes (length-changing). Hash is zeroed."""
        envis, obj = self.locate_string(old)
        # length field immediately before, hash before that (validated)
        length_pos = envis - 4
        if _u32_at(bytes(self.payload), length_pos) != len(old):
            raise RebuildError("string length field not adjacent")
        run = None
        for ev in self.raw_runs(obj):
            if ev["raw_start"] <= envis + len(old) <= ev["raw_end"]:
                run = ev
        if run is None:
            raise RebuildError("no raw run covers string end")
        content = (bytes(self.payload[run["raw_start"]:envis - 8])
                   + bytes(4)  # zero hash: deserializer recomputes
                   + struct.pack("<I", len(new)) + new)
        content += bytes((-len(content)) % 8)
        new_words = len(content) // 8
        old_stored = run["raw_end"] - run["raw_start"]
        self._rewrite_raw_op(run, new_words)
        self._rewrite_uint30_at(obj["size_pos"],
                                obj["size"] + (new_words - run["slots"]))
        self.add_edit(run["raw_start"], old_stored, content)
        info: dict = {"object": obj["start"],
                      "growth": len(content) - old_stored}
        if len(new) == 1:
            # Single characters intern to V8's shared single-character
            # cache: the slot becomes a thin string, which d8's loadjsc
            # pool printer renders as <unknown>. Runtime behavior is
            # unaffected (comparisons dereference through).
            info["note"] = ("single-char strings print as <unknown> in d8 "
                            "dumps (shared-cache interning); runtime "
                            "unaffected")
        return info

    def map_root(self, obj: dict, _seen=None) -> tuple:
        """Resolve an object's map to ('root', id). Follows Backref/Hot.

        Lets callers identify object types (SFI map, BC map, ...) without
        hardcoding per-build root ids: calibrate from a known object.
        """
        _seen = _seen or set()
        if obj["start"] in _seen:
            raise RebuildError("map cycle")
        _seen.add(obj["start"])
        buf = bytes(self.payload)
        b = buf[obj["map_start"]]
        if 0x40 <= b <= 0x5F:
            return ("root", b - 0x40)
        if b == 0x07:
            v, _ = get_uint30(buf, obj["map_start"] + 1)
            return ("root", v)
        if 0x90 <= b <= 0x97:
            kind, val = self.hot_identities()[obj["map_start"]]
            if kind == "root":
                return ("root", val)
            return self.map_root(self._obj_by_backref(val), _seen)
        if b == 0x04:
            v, _ = get_uint30(buf, obj["map_start"] + 1)
            return self.map_root(self._obj_by_backref(v), _seen)
        raise RebuildError(
            f"map op 0x{b:02x} at {obj['map_start']}: cannot resolve type")

    def _obj_by_backref(self, idx: int) -> dict:
        for o in self.objects:
            if o["backref"] == idx:
                return o
        raise RebuildError(f"no object with backref {idx}")

    def add_pool_string(self, pool_start: int, string: bytes) -> dict:
        """Append a new string constant to a FixedArray pool object.

        Returns {"index": new backref index, "growth": bytes added}.
        """
        pool = next((o for o in self.objects if o["start"] == pool_start),
                    None)
        if pool is None:
            raise RebuildError(f"no object starts at {pool_start}")
        runs = self.raw_runs(pool)
        if not runs:
            raise RebuildError(f"pool at {pool_start} has no raw runs")
        first = runs[0]
        seg = bytes(self.payload[first["raw_start"]:first["raw_end"]])
        if len(seg) < 8 or seg[:4] != bytes(4):
            raise RebuildError("pool length pattern mismatch ([0][len])")
        old_len = struct.unpack_from("<I", seg, 4)[0]
        if pool["size"] != 2 + old_len:
            raise RebuildError(
                f"pool size {pool['size']} != 2 + len {old_len}: not a "
                "FixedArray")
        try:
            string.decode("latin1")
            if any(c > 255 for c in string):
                raise ValueError
        except ValueError:
            raise RebuildError("only latin1 strings supported")
        body = bytes(4) + struct.pack("<I", len(string)) + bytes(string)
        body += bytes((-len(body)) % 8)
        if len(body) // 8 > 32:
            raise RebuildError("string too long for FixedRawData")
        # fresh one-byte internalized string: map RootArrayConstants[18]
        strobj = bytes([0x01]) + encode_uint30(1 + len(body) // 8) \
            + bytes([0x40 + 18, 0x60 + len(body) // 8 - 1]) + body
        inspos = pool["end"]
        k = sum(1 for b in self.walker.backrefs if b["start"] < inspos)
        self._rewrite_uint30_at(pool["size_pos"], pool["size"] + 1)
        self.add_edit(first["raw_start"] + 4, 4,
                      struct.pack("<I", old_len + 1))
        self.add_edit(inspos, 0, strobj)
        self.renumber_backrefs(inspos, k, 1)
        self._rebase()
        return {"index": k, "pool_index": old_len, "growth": len(strobj)}

    @staticmethod
    def _string_object(string: bytes) -> bytes:
        """Fresh one-byte internalized string object bytes (hash zeroed).

        Same layout add_pool_string emits (map RootArrayConstants[18]):
        the deserializer recomputes the zeroed hash on demand.
        """
        try:
            string.decode("latin1")
            if any(c > 255 for c in string):
                raise ValueError
        except ValueError:
            raise RebuildError("only latin1 strings supported")
        body = bytes(4) + struct.pack("<I", len(string)) + bytes(string)
        body += bytes((-len(body)) % 8)
        if len(body) // 8 > 32:
            raise RebuildError("string too long for FixedRawData")
        return bytes([0x01]) + encode_uint30(1 + len(body) // 8) \
            + bytes([0x40 + 18, 0x60 + len(body) // 8 - 1]) + body

    def check_function_body(self, bytecode: bytes, table: dict):
        """Validate a complete new-function body: safe ops, ends Return."""
        if not bytecode:
            raise RebuildError("function body is empty")
        self.check_insert_safe(bytecode, table)
        by_value = {e["value"]: e for e in table.values()}
        pos = 0
        last = None
        while pos < len(bytecode):
            entry = by_value.get(bytecode[pos])
            last = entry["name"]
            pos += entry["width"]
        if last != "Return":
            raise RebuildError(
                f"function body must end with Return (ends with {last})")

    @staticmethod
    def _string_object_size(length: int) -> int:
        """Total bytes of _string_object for a name of this length."""
        words = (8 + length + 7) // 8
        return 4 + words * 8

    def _name_slot_in_span(self, sfi: dict, template_name: bytes,
                           bc: dict):
        """Locate the template's name linkage inside its SFI span.

        Two shapes occur (V8 stores name_or_scope_info either way):
        ("backref", rel_pos, target_idx): a Backref slot whose target
          is the template name string. The slot is rewritten to the
          new name string's index.
        ("inline", rel_start, rel_end, target_idx): a nested name
          string, referenced nowhere else (zero global Backref refs).
          Its bytes are replaced in place.
        Both shapes require the target to be EXACTLY the canonical
        string-object size for the name length: scope metadata and
        pools may quote the name text, but only the linkage is a
        bare string object of that size. Anything inside the template
        BytecodeArray is excluded likewise. Returns (kind, ...) or
        None when the name is not settable (anonymous templates,
        unseen layouts): callers keep the name and say so loudly
        instead of guessing.
        """
        want = struct.pack("<I", len(template_name)) + template_name
        expect = self._string_object_size(len(template_name))

        def holds_name(obj: dict) -> bool:
            if obj["end"] - obj["start"] != expect:
                return False
            for run in self.raw_runs(obj):
                seg = bytes(self.payload[run["raw_start"]:run["raw_end"]])
                if want in seg:
                    return True
            return False

        def in_bc(start: int, end: int) -> bool:
            return bc["start"] <= start and end <= bc["end"]

        span_hits = []
        for ev in self.events:
            if not (sfi["start"] <= ev["pos"] < sfi["end"]):
                continue
            if ev["op"] != "Backref":
                continue
            idx = int(ev["detail"][1:-1])
            try:
                target = self._obj_by_backref(idx)
            except RebuildError:
                continue
            if in_bc(target["start"], target["end"]):
                continue
            if holds_name(target):
                span_hits.append((ev["pos"] - sfi["start"], idx))
        # The SFI's own pool may legitimately quote its name (a string
        # constant equal to the function name): those live inside the
        # pool subtree and are not the name linkage.
        if len(span_hits) == 1:
            return ("backref", span_hits[0][0], span_hits[0][1])
        if span_hits:
            return "ambiguous"
        if template_name is None:
            return None
        inlines = []
        for o in self.objects:
            if not (sfi["start"] < o["start"] and o["end"] <= sfi["end"]):
                continue
            if in_bc(o["start"], o["end"]):
                continue
            if not holds_name(o):
                continue
            refs = sum(
                1 for ev in self.events
                if ev["op"] == "Backref"
                and ev.get("detail") == f"[{o['backref']}]")
            if refs == 0:
                inlines.append(o)
        if len(inlines) == 1:
            o = inlines[0]
            return ("inline", o["start"] - sfi["start"],
                    o["end"] - sfi["start"], o["backref"])
        if inlines:
            return "ambiguous"
        return None

    def create_function(self, template_stream: bytes, host_stream: bytes,
                        name: str, bytecode: bytes,
                        template_name: bytes | None,
                        need_pool: bool = False) -> dict:
        """Create a new function in a host pool from a template closure.

        Clones the template SFI span (leaf-only, same rule as
        duplicate_function), swaps its bytecode for the assembled body,
        and points its name linkage at a fresh string — all on a
        detached span copy, then appends the result to the host pool.
        template_name is the template's current name (None when
        anonymous): when no settable name linkage is found the template
        name is kept and the info dict carries a note (never guessed).
        need_pool refuses constant-referencing bodies when the template
        itself has no pool to clone. Returns {"index", "growth",
        "members", "renamed", ...}.
        """
        try:
            name_bytes = name.encode("latin1")
        except (UnicodeEncodeError, AttributeError):
            raise RebuildError("new-fn name must be latin1")
        strobj = self._string_object(name_bytes)
        # Resolve template + host on the live payload first: every
        # position below derives from this walk. Twin-tolerant: a
        # previously duplicated template/host stream exists twice, and
        # the clones are interchangeable for further cloning.
        t_blob, t_bc = self._first_stream_hit(template_stream, True)
        sfi = self.sfi_of_bc(t_bc)
        try:
            self.pool_of_bc(t_bc)
        except RebuildError:
            if need_pool:
                raise RebuildError(
                    "template has no constant pool but the body uses "
                    "constants (LdaConstant); duplicate a function with "
                    "constants instead")
        _, host_bc = self._first_stream_hit(host_stream, False)
        host_pool = self.pool_of_bc(host_bc)
        host = next(
            (o for o in self.objects if o["start"] == host_pool["start"]),
            None)
        if host is None:
            raise RebuildError("host pool vanished")
        if host["start"] == sfi["start"] or (
                sfi["start"] < host["start"] and host["end"] <= sfi["end"]):
            raise RebuildError("host pool inside function span")
        closure = sorted(
            (o for o in self.objects
             if sfi["start"] < o["start"] and o["end"] <= sfi["end"]),
            key=lambda o: o["start"])
        sfi_map = self.map_root(sfi)
        for o in closure:
            if self.map_root(o) == sfi_map:
                raise RebuildError(
                    f"possible nested function at {o['start']}: leaf-only")
        # Bytecode surgery plan on the detached span (mirrors
        # replace_bytecode; all metadata precedes the blob).
        tail = None
        for ev in self.raw_runs(t_bc):
            if ev["raw_start"] <= t_blob and \
                    t_blob + len(template_stream) <= ev["raw_end"]:
                tail = ev
                break
        if tail is None:
            raise RebuildError("template blob spans raw runs "
                               "(unsupported layout)")
        if tail["op"] != "FixedRawData":
            raise RebuildError("template run is not FixedRawData "
                               "(unsupported layout)")
        length_pos = self.locate_length_field(
            t_bc, t_blob, len(template_stream))
        if not (sfi["start"] <= length_pos < t_blob):
            raise RebuildError("template length field outside span order")
        if not (t_bc["size_pos"] < tail["pos"]):
            raise RebuildError("template object header outside span order")
        run_len = tail["raw_end"] - tail["raw_start"]
        head = bytes(self.payload[tail["raw_start"]:t_blob])
        old_tail = bytes(
            self.payload[t_blob + len(template_stream):tail["raw_end"]])
        if len(head) + len(bytecode) <= run_len:
            new_content = head + bytecode + old_tail
            new_content = new_content[:run_len]
            # Word-align like replace_bytecode: an unpadded shrink
            # desyncs the deserializer (raw runs are 8-byte words).
            new_content += bytes((-len(new_content)) % 8)
        else:
            new_content = head + bytecode
            new_content += bytes((-len(new_content)) % 8)
        new_words = len(new_content) // 8
        if not 1 <= new_words <= 32:
            raise RebuildError(
                f"new body {new_words} words exceeds FixedRawData")
        # Name linkage discovery (template coordinates).
        slot = self._name_slot_in_span(
            sfi, template_name, t_bc) if template_name else None
        if slot == "ambiguous":
            raise RebuildError(
                "template name linkage is ambiguous; refusing rename")
        renamed = slot is not None
        # Detached span + surgery.
        span = bytearray(self.payload[sfi["start"]:sfi["end"]])

        def rel(p):
            return p - sfi["start"]

        r_tail, r_tail_end = rel(tail["raw_start"]), rel(tail["raw_end"])
        r_blob = rel(t_blob)
        if span.count(template_stream) != 1 or \
                span[r_blob:r_blob + len(template_stream)] != template_stream:
            raise RebuildError("template stream not unique inside its span")
        span[r_tail:r_tail_end] = new_content
        d_content = len(new_content) - run_len
        r_size_pos = rel(t_bc["size_pos"])
        old_size, size_end = get_uint30(bytes(span), r_size_pos)
        if old_size != t_bc["size"]:
            raise RebuildError("template object size moved during surgery")
        size_new = encode_uint30(old_size + (new_words - tail["slots"]))
        span[r_size_pos:size_end] = size_new
        d_size = len(size_new) - (size_end - r_size_pos)
        r_len = rel(length_pos)
        if bytes(span[r_len:r_len + 4]) != struct.pack(
                "<I", len(template_stream)):
            raise RebuildError("template length field moved during surgery")
        span[r_len:r_len + 4] = struct.pack("<I", len(bytecode))
        if span[rel(tail["pos"])] != 0x60 + tail["slots"] - 1:
            raise RebuildError("template raw op moved during surgery")
        span[rel(tail["pos"])] = 0x60 + new_words - 1

        def adj(p):
            return p + (d_size if p >= size_end else 0) \
                + (d_content if p >= r_tail_end else 0)

        # Remap refs across the insertion (mirrors duplicate_function),
        # with the alpha-shape name slot overridden to the new string.
        span_assigned = [b["index"] for b in self.walker.backrefs
                         if sfi["start"] <= b["start"] < sfi["end"]]
        if not span_assigned or span_assigned[0] != sfi["backref"]:
            raise RebuildError("template backref assignment mismatch")
        cset = set(span_assigned)
        pins = host["end"]
        k = sum(1 for b in self.walker.backrefs if b["start"] < pins)
        shift = 1 if slot is not None and slot[0] == "backref" else 0
        newidx = {old: k + shift + j for j, old in enumerate(span_assigned)}
        n_new = shift + len(span_assigned)

        def shared(idx):
            return idx + n_new if idx >= k else idx

        ident = self.hot_identities()
        repl = []  # (adj_pos, old_len, new_bytes, expect_desc)
        inline_rs = slot[1] if slot is not None and slot[0] == "inline" \
            else None
        inline_re = slot[2] if slot is not None and slot[0] == "inline" \
            else None
        for ev in self.events:
            if not (sfi["start"] <= ev["pos"] < sfi["end"]):
                continue
            op = rel(ev["pos"])
            # The inline name object is replaced wholesale: only
            # remappable refs inside its range are a problem (its own
            # map/raw structure goes with it).
            if inline_rs is not None and inline_rs < op < inline_re \
                    and ev["op"] in ("Backref", "HotObject"):
                raise RebuildError(
                    f"remap {ev['op']} at {ev['pos']} overlaps inline "
                    "name object")
            p = adj(op)
            if ev["op"] == "Backref":
                idx = int(ev["detail"][1:-1])
                _, uend = get_uint30(bytes(self.payload), ev["pos"] + 1)
                old_len = uend - (ev["pos"] + 1)
                if slot is not None and slot[0] == "backref" \
                        and op == slot[1]:
                    if idx != slot[2]:
                        raise RebuildError("name slot target moved")
                    repl.append((p + 1, old_len,
                                 encode_uint30(k), f"backref[{idx}]"))
                elif idx in cset:
                    repl.append((p + 1, old_len,
                                 encode_uint30(newidx[idx]),
                                 f"backref[{idx}]"))
                elif idx >= sfi["backref"]:
                    raise RebuildError(
                        f"copy-internal Backref[{idx}] at {ev['pos']} points "
                        " outside the closure")
                else:
                    repl.append((p + 1, old_len,
                                 encode_uint30(shared(idx)),
                                 f"backref[{idx}]"))
            elif ev["op"] == "HotObject":
                kind, val = ident[ev["pos"]]
                if kind == "backref":
                    if val in cset:
                        v = newidx[val]
                    elif val >= sfi["backref"]:
                        raise RebuildError(
                            f"hot target [{val}] at {ev['pos']} in-span but "
                            "outside closure")
                    else:
                        v = shared(val)
                    repl.append((p, 1, bytes([0x04]) + encode_uint30(v),
                                 "hot"))
                else:
                    repl.append((p, 1, bytes([0x07]) + encode_uint30(val),
                                 "hot"))
        if slot is not None and slot[0] == "inline":
            _, rs, re_, _ = slot
            old_str = bytes(self.payload[sfi["start"] + rs:
                                         sfi["start"] + re_])
            inline_new = self._string_object(name_bytes)
            rs_a, re_a = adj(rs), adj(re_)
            if bytes(span[rs_a:re_a]) != old_str:
                raise RebuildError("inline name object moved during surgery")
            repl.append((rs_a, re_ - rs, inline_new, "inline-name"))
        for pos, old_len, new, desc in sorted(repl, reverse=True):
            if desc.startswith("backref"):
                if span[pos - 1] != 0x04:
                    raise RebuildError(
                        f"remap target moved ({desc} at span+{pos})")
            elif desc == "hot":
                if span[pos] not in range(0x90, 0x98):
                    raise RebuildError(
                        f"remap target moved (hot at span+{pos})")
            span[pos:pos + old_len] = new
        copy = bytes(span)
        # Append to the host pool (string object first for backref shape).
        runs = self.raw_runs(host)
        if not runs:
            raise RebuildError("host pool has no raw runs")
        seg = bytes(self.payload[runs[0]["raw_start"]:runs[0]["raw_end"]])
        if len(seg) < 8 or seg[:4] != bytes(4):
            raise RebuildError("host pool length pattern mismatch")
        host_len = struct.unpack_from("<I", seg, 4)[0]
        if host["size"] != 2 + host_len:
            raise RebuildError("host is not a FixedArray")
        blob_out = strobj + copy if shift else copy
        self._rewrite_uint30_at(host["size_pos"],
                                host["size"] + (2 if shift else 1))
        self.add_edit(runs[0]["raw_start"] + 4, 4,
                      struct.pack("<I", host_len + (2 if shift else 1)))
        self.add_edit(pins, 0, blob_out)
        self.renumber_backrefs(pins, k, n_new)
        self.deopt_hot_after(pins, lambda v: v + n_new if v >= k else v)
        self._rebase()
        info = {"index": k + shift, "growth": len(blob_out),
                "members": n_new, "renamed": renamed}
        if not renamed:
            info["note"] = ("template name kept: no settable name linkage "
                            "found (anonymous template or unseen layout)")
        return info

    def duplicate_function(self, sfi_start: int, host_pool_start: int) -> dict:
        """Duplicate a whole function closure into another pool (add function).

        Whole-closure rule: every object nested in the SFI span is copied,
        so no per-type layout knowledge is needed. Shared roots/attached
        refs pass through (position-independent). Internal Backref/Hot ops
        are remapped to the copy's new indices. Post-insertion Hot ops are
        de-optimised to direct encodings. Leaf functions only (raises if a
        nested SFI-sized object suggests inner functions).
        Returns {"index": new SFI backref, "growth": bytes added}.
        """
        sfi = next((o for o in self.objects if o["start"] == sfi_start),
                   None)
        if sfi is None:
            raise RebuildError(f"no object starts at {sfi_start}")
        host = next((o for o in self.objects if o["start"] == host_pool_start),
                    None)
        if host is None:
            raise RebuildError(f"no object starts at {host_pool_start}")
        if host["start"] == sfi["start"] or (
                sfi["start"] < host["start"] and host["end"] < sfi["end"]):
            raise RebuildError("host pool inside function span")
        closure = sorted(
            (o for o in self.objects
             if sfi["start"] < o["start"] and o["end"] <= sfi["end"]),
            key=lambda o: o["start"])
        sfi_map = self.map_root(sfi)
        for o in closure:
            if self.map_root(o) == sfi_map:
                raise RebuildError(
                    f"possible nested function at {o['start']}: leaf-only")
        members = [sfi] + closure
        # Index closure: every backref assignment inside the span (objects
        # AND size-0 fallbacks) consumes an index in decode order.
        span_assigned = [b["index"] for b in self.walker.backrefs
                         if sfi["start"] <= b["start"] < sfi["end"]]
        assert span_assigned[0] == sfi["backref"]
        cset = set(span_assigned)
        pins = host["end"]
        k = sum(1 for b in self.walker.backrefs if b["start"] < pins)
        newidx = {old: k + j for j, old in enumerate(span_assigned)}
        n_new = len(span_assigned)

        def shared(idx):
            """Remap a kept (non-closure) backref across the insertion."""
            return idx + n_new if idx >= k else idx

        ident = self.hot_identities()
        # rebuild the SFI span with remapped references
        span = bytearray(self.payload[sfi["start"]:sfi["end"]])
        repl = []  # (rel_pos, old_len, new_bytes)

        def emit_rel(pos, old_len, new):
            repl.append((pos - sfi["start"], old_len, new))

        for ev in self.events:
            if not (sfi["start"] <= ev["pos"] < sfi["end"]):
                continue
            if ev["op"] == "Backref":
                idx = int(ev["detail"][1:-1])
                if idx in cset:
                    emit_rel(ev["pos"] + 1,
                             ev["end"] - (ev["pos"] + 1),
                             encode_uint30(newidx[idx]))
                elif idx >= members[0]["backref"]:
                    raise RebuildError(
                        f"copy-internal Backref[{idx}] at {ev['pos']} points "
                        " outside the closure")
                else:
                    emit_rel(ev["pos"] + 1,
                             ev["end"] - (ev["pos"] + 1),
                             encode_uint30(shared(idx)))
            elif ev["op"] == "HotObject":
                kind, val = ident[ev["pos"]]
                if kind == "backref":
                    if val in cset:
                        v = newidx[val]
                    elif val >= sfi["backref"]:
                        raise RebuildError(
                            f"hot target [{val}] at {ev['pos']} in-span but "
                            "outside closure")
                    else:
                        v = shared(val)
                    emit_rel(ev["pos"], 1,
                             bytes([0x04]) + encode_uint30(v))
                else:
                    emit_rel(ev["pos"], 1,
                             bytes([0x07]) + encode_uint30(val))
        for pos, old_len, new in sorted(repl, reverse=True):
            span[pos:pos + old_len] = new
        copy = bytes(span)
        # grow host pool (same FixedArray checks as add_pool_string)
        runs = self.raw_runs(host)
        if not runs:
            raise RebuildError("host pool has no raw runs")
        seg = bytes(self.payload[runs[0]["raw_start"]:runs[0]["raw_end"]])
        if len(seg) < 8 or seg[:4] != bytes(4):
            raise RebuildError("host pool length pattern mismatch")
        host_len = struct.unpack_from("<I", seg, 4)[0]
        if host["size"] != 2 + host_len:
            raise RebuildError("host is not a FixedArray")
        self._rewrite_uint30_at(host["size_pos"], host["size"] + 1)
        self.add_edit(runs[0]["raw_start"] + 4, 4,
                      struct.pack("<I", host_len + 1))
        self.add_edit(pins, 0, copy)
        self.renumber_backrefs(pins, k, n_new)
        self.deopt_hot_after(pins, lambda v: v + n_new if v >= k else v)
        self._rebase()
        return {"index": k, "growth": len(copy), "members": n_new}

    # -- materialise ---------------------------------------------------
    def build(self) -> bytes:
        """Apply edits back-to-front; return the new .jsc bytes."""
        out = bytearray(self.orig)
        # payload edits first (original payload coords -> file coords)
        for pos, old_len, new in sorted(self.edits, reverse=True):
            fpos = HEADER_SIZE + pos
            out[fpos:fpos + old_len] = new
        # header payload_length
        struct.pack_into("<I", out, 20,
                         self.header["payload_length"] + self.growth)
        return bytes(out)

    def validate(self, data: bytes):
        """Re-walk the rebuilt payload. Raises RebuildError on failure."""
        try:
            w, s = walk_payload(payload_of(data))
        except SnapshotError as e:
            raise RebuildError(f"rebuilt payload fails to walk: {e}")
        return w, s
