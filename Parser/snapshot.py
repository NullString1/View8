"""V8 snapshot-bytecode walker for .jsc code-cache payloads.

Ground truth: V8 13.6 source (local checkout):
  src/snapshot/serializer-deserializer.h  (opcode values, size codecs)
  src/snapshot/snapshot-source-sink.h      (uint30 run-length codec)
  src/snapshot/serializer.cc               (SerializePrologue: size>>3, Pad)
  src/snapshot/deserializer.cc             (ReadSingleBytecodeData dispatch,
                                            ReadObject, ReadData slot loop)
  src/snapshot/object-deserializer.cc      (root + deferred + synchronize)
  src/snapshot/code-serializer.h           (32-byte header: 28 + 4 pad)

Build facts (must match producer AND consumer):
  kTaggedSize = 8 (no pointer compression, no sandbox in our builds).
  SnapshotSpace: 0=ReadOnlyHeap, 1=Old, 2=Code, 3=Trusted.

Header: magic@0 ver@4 src@8 flags@12 ro@16 paylen@20 chk@24, pad to 32.
Payload = file[32:32+paylen]; must be consumed exactly by:
  root = ReadObject; deferred = {ReadObject}* kSynchronize; tail = kNop*.

The walker tracks byte spans for every op and object WITHOUT knowing
per-type object layouts: each op reports slots consumed, kNewObject
declares total slots, so boundaries are exact. Unknown/unexpected bytes
are hard errors, never guesses.
"""

import struct

HEADER_SIZE = 32
TAG_SIZE = 8

SPACE_NAMES = ("ReadOnlyHeap", "Old", "Code", "Trusted")


class SnapshotError(Exception):
    pass


def get_uint30(buf: bytes, pos: int) -> tuple:
    """Decode uint30 run-length int at pos. Returns (value, new_pos)."""
    if pos + 4 > len(buf):
        raise SnapshotError(f"uint30 at {pos}: need 4 bytes, have {len(buf)-pos}")
    answer = struct.unpack_from("<I", buf, pos)[0]
    nbytes = (answer & 3) + 1
    if pos + nbytes > len(buf):
        raise SnapshotError(f"uint30 at {pos}: truncated")
    mask = 0xFFFFFFFF >> (32 - 8 * nbytes)
    return ((answer & mask) >> 2, pos + nbytes)


def encode_uint30(value: int) -> bytes:
    """Encode a uint30 value. Inverse of get_uint30."""
    if not 0 <= value < (1 << 30):
        raise SnapshotError(f"uint30 value out of range: {value}")
    raw = value << 2
    if value < (1 << 6):
        return bytes([raw & 0xFF])
    if value < (1 << 14):
        return struct.pack("<H", raw | 0x01)
    if value < (1 << 22):
        return bytes([ (raw | 0x02) & 0xFF,
                       ((raw >> 8) & 0xFF),
                       ((raw >> 16) & 0xFF) ])
    return struct.pack("<I", raw | 0x03)


def parse_header(data: bytes) -> dict:
    """Parse the 32-byte code-cache header. Raises SnapshotError."""
    if len(data) < HEADER_SIZE:
        raise SnapshotError(f"file too small for header: {len(data)}")
    magic, ver, src, flags, ro, pay, chk = struct.unpack_from("<7I", data, 0)
    if pay > len(data) - HEADER_SIZE:
        raise SnapshotError(
            f"payload length {pay} exceeds file {len(data)} (need 32-byte header)")
    return {
        "magic": magic, "version_hash": ver, "source_hash": src,
        "flag_hash": flags, "ro_snapshot_checksum": ro,
        "payload_length": pay, "checksum": chk,
        "header_size": HEADER_SIZE,
        "payload_offset": HEADER_SIZE,
        "total_size": len(data),
    }


def payload_of(data: bytes) -> bytes:
    h = parse_header(data)
    return data[h["header_size"]:h["header_size"] + h["payload_length"]]


class Walker:
    """Op-level recursive-descent walker over a code-cache payload.

    Attributes after walk():
      events: list of dicts {pos, end, op, detail, slots}
      objects: list of dicts {start, end, space, size_words, backref,
                               map_start, map_end, content_start, content_end}
      backrefs: list of object indices in assignment order (with spans)
      root_end / deferred_end / tail_start positions.
    """

    def __init__(self, payload: bytes):
        self.buf = payload
        self.pos = 0
        self.events = []
        self.objects = []
        self.backrefs = []  # (index, obj_start or None for fallback)
        self.depth = 0

    # -- low level -----------------------------------------------------
    def _u8(self) -> int:
        if self.pos >= len(self.buf):
            raise SnapshotError(f"unexpected end at {self.pos}")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def _u30(self) -> int:
        v, self.pos = get_uint30(self.buf, self.pos)
        return v

    def _raw(self, n: int) -> tuple:
        if self.pos + n > len(self.buf):
            raise SnapshotError(f"raw {n} bytes at {self.pos} overruns")
        start = self.pos
        self.pos += n
        return (start, self.pos)

    def _event(self, start: int, op: str, detail: str, slots: int):
        self.events.append(
            {"pos": start, "end": self.pos, "op": op,
             "detail": detail, "slots": slots, "depth": self.depth})

    # -- object level --------------------------------------------------
    def read_object(self) -> int:
        """Read one object reference (1 slot worth). Returns slots (always 1)."""
        start = self.pos
        b = self._u8()
        if b <= 0x03:
            self._read_new_object(start, b)
            return 1
        if b == 0x04:
            idx = self._u30()
            self._event(start, "Backref", f"[{idx}]", 1)
            return 1
        if b == 0x05:
            chunk = self._u30()
            off = self._u30()
            self._event(start, "ReadOnlyHeapRef", f"[{chunk},{off}]", 1)
            return 1
        if b == 0x06:
            idx = self._u30()
            self._event(start, "StartupObjectCache", f"[{idx}]", 1)
            return 1
        if b == 0x07:
            idx = self._u30()
            self._event(start, "RootArray", f"[{idx}]", 1)
            return 1
        if b == 0x08:
            idx = self._u30()
            self._event(start, "AttachedReference", f"[{idx}]", 1)
            return 1
        if b == 0x09:
            idx = self._u30()
            self._event(start, "SharedHeapObjectCache", f"[{idx}]", 1)
            return 1
        if b in (0x1B, 0x1C):
            raise SnapshotError(
                f"meta-map op 0x{b:02x} at {start}: not expected in code cache")
        if b in (0x0F, 0x10):
            raise SnapshotError(
                f"embedder/api-wrapper data op 0x{b:02x} at {start}: unsupported")
        if b in (0x12, 0x13):
            idx = self._u30()
            name = "ApiReference" if b == 0x12 else "ExternalReference"
            self._event(start, name, f"[{idx}]", 1)
            return 1
        if 0x14 <= b <= 0x16 or 0x1D <= b <= 0x21:
            raise SnapshotError(
                f"sandbox-only op 0x{b:02x} at {start}: build has no sandbox")
        if 0x40 <= b <= 0x5F:
            self._event(start, "RootArrayConstants", f"[{b - 0x40}]", 1)
            return 1
        if 0x90 <= b <= 0x97:
            self._event(start, "HotObject", f"[{b - 0x90}]", 1)
            return 1
        raise SnapshotError(f"bad object-start op 0x{b:02x} at {start}")

    def _read_new_object(self, start: int, space_byte: int):
        space = SPACE_NAMES[space_byte]
        size = self._u30()
        size_pos = start + 1
        # V8 assigns the backref index at allocation time (pre-order:
        # parent before children). Match it so indices agree with the
        # deserializer's back_refs_ vector.
        idx = len(self.backrefs)
        if size == 0:
            # User-code fallback: undefined, still takes a backref index.
            self.backrefs.append({"index": idx, "start": start,
                                  "kind": "fallback"})
            self._event(start, f"NewObject[{space}]",
                        "size=0 fallback undefined", 1)
            return
        self.backrefs.append({"index": idx, "start": start, "kind": "object",
                              "space": space, "size": size})
        map_start = self.pos
        self.depth += 1
        self.read_object()  # the map (exactly 1 slot of content)
        map_end = self.pos
        # Remaining content slots.
        content_start = self.pos
        self._read_slots(size - 1)
        content_end = self.pos
        self.depth -= 1
        self.objects.append({
            "start": start, "size_pos": size_pos, "size": size,
            "space": space, "backref": idx,
            "map_start": map_start, "map_end": map_end,
            "content_start": content_start, "content_end": content_end,
            "end": self.pos,
        })
        self._event(start, f"NewObject[{space}]",
                    f"size={size} backref={idx}", 1)

    def _read_slots(self, n: int):
        current = 0
        while current < n:
            start = self.pos
            b = self._u8()
            if 0x00 <= b <= 0x09 or 0x12 <= b <= 0x13 or \
                    0x40 <= b <= 0x5F or 0x90 <= b <= 0x97 or b in (0x1B, 0x1C):
                # Push back and reuse read_object for pointer slots.
                self.pos = start
                self.read_object()
                current += 1
                continue
            if b == 0x0A:
                raise SnapshotError(
                    f"kNop inside object content at {start}: desync")
            if b == 0x0B:
                raise SnapshotError(
                    f"kSynchronize inside object content at {start}: desync")
            if b == 0x0C:
                count = self._u30() + 18
                root = self._u8()
                self._event(start, "VariableRepeatRoot",
                            f"count={count} root={root}", count)
                current += count
                continue
            if b == 0x0D:
                ln = struct.unpack_from("<I", self.buf, self.pos)[0]
                self.pos += 4
                self._raw(ln)
                self._event(start, "OffHeapBackingStore",
                            f"len={ln}", 0)
                continue
            if b == 0x0E:
                ln, mx = struct.unpack_from("<2I", self.buf, self.pos)
                self.pos += 8
                self._raw(ln)
                self._event(start, "OffHeapResizableBackingStore",
                            f"len={ln} max={mx}", 0)
                continue
            if b == 0x11:
                count = self._u30()
                self._raw(count * TAG_SIZE)
                self._event(start, "VariableRawData",
                            f"words={count}", count)
                current += count
                continue
            if b == 0x17:
                self._event(start, "ClearedWeakReference", "", 1)
                current += 1
                continue
            if b in (0x18, 0x1D, 0x21):
                name = {0x18: "WeakPrefix", 0x1D: "IndirectPointerPrefix",
                        0x21: "ProtectedPointerPrefix"}[b]
                self._event(start, name, "", 0)
                continue
            if b == 0x1E:
                raise SnapshotError(
                    f"kInitializeSelfIndirectPointer at {start}: no sandbox")
            if b in (0x0F, 0x10):
                raise SnapshotError(
                    f"embedder data op 0x{b:02x} at {start}: unsupported")
            if b in (0x14, 0x15, 0x16, 0x1F, 0x20):
                raise SnapshotError(
                    f"sandbox/leap op 0x{b:02x} at {start}: unsupported")
            if b == 0x19:
                self._event(start, "RegisterPendingForwardRef", "", 1)
                current += 1
                continue
            if b == 0x1A:
                idx = self._u30()
                self._event(start, "ResolvePendingForwardRef", f"[{idx}]", 0)
                continue
            if 0x60 <= b <= 0x7F:
                count = b - 0x60 + 1
                rstart, _ = self._raw(count * TAG_SIZE)
                self._event(start, "FixedRawData", f"words={count}", count)
                # stash raw span on the event for correlation
                self.events[-1]["raw_start"] = rstart
                self.events[-1]["raw_end"] = self.pos
                current += count
                continue
            if 0x80 <= b <= 0x8F:
                count = (b - 0x80) + 2
                root = self._u8()
                self._event(start, "FixedRepeatRoot",
                            f"count={count} root={root}", count)
                current += count
                continue
            raise SnapshotError(f"bad content op 0x{b:02x} at {start}")

    # -- top level -----------------------------------------------------
    def walk(self) -> dict:
        """Walk root + deferred + padding. Returns summary dict."""
        total = len(self.buf)
        root_start = self.pos
        self.read_object()
        root_end = self.pos
        # Deferred objects until kSynchronize.
        deferred = []
        while True:
            if self.pos >= total:
                raise SnapshotError("missing kSynchronize terminator")
            if self.buf[self.pos] == 0x0B:
                sync_pos = self.pos
                self.pos += 1
                self._event(sync_pos, "Synchronize", "end deferred", 0)
                break
            dstart = self.pos
            b = self.buf[self.pos]
            if not (b <= 0x03):
                raise SnapshotError(
                    f"deferred op 0x{b:02x} at {dstart}: expected NewObject")
            self.read_object()
            deferred.append((dstart, self.pos))
        tail_start = self.pos
        while self.pos < total:
            if self.buf[self.pos] != 0x0A:
                raise SnapshotError(
                    f"tail byte 0x{self.buf[self.pos]:02x} at {self.pos}: "
                    "expected kNop padding")
            self.pos += 1
        return {
            "root": (root_start, root_end),
            "deferred": deferred,
            "tail_start": tail_start,
            "total": total,
            "n_objects": len(self.objects),
            "n_backrefs": len(self.backrefs),
            "n_events": len(self.events),
        }


def walk_payload(payload: bytes) -> tuple:
    """Walk a payload; returns (walker, summary). Raises SnapshotError."""
    w = Walker(payload)
    summary = w.walk()
    return w, summary
