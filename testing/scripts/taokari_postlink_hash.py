from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


MAGIC = bytes.fromhex("b64f412917c35ae8910dfa724c2b806e")
RECORD_SIZE = 32
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    raw_size: int
    raw_ptr: int
    characteristics: int


def fnv64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def pe_sections(data: bytes) -> list[Section]:
    if len(data) < 0x40:
        raise ValueError("file too small")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    sh = pe + 24 + opt_size
    if sh + count * 40 > len(data):
        raise ValueError("truncated PE section table")
    out: list[Section] = []
    for i in range(count):
        base = sh + i * 40
        raw_name = data[base:base + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace")
        virtual_size, rva, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, base + 8)
        characteristics = struct.unpack_from("<I", data, base + 36)[0]
        out.append(Section(name, rva, virtual_size, raw_size, raw_ptr,
                           characteristics))
    return out


def pick_section(sections: list[Section], name: str | None) -> Section:
    if name:
        for sec in sections:
            if sec.name == name:
                return sec
        raise ValueError(f"section not found: {name}")
    for sec in sections:
        if sec.name == ".text":
            return sec
    for sec in sections:
        if (sec.characteristics & IMAGE_SCN_CNT_CODE and
                sec.characteristics & IMAGE_SCN_MEM_EXECUTE):
            return sec
    raise ValueError("no executable section found")


def section_bytes(data: bytes, sec: Section) -> bytes:
    end = sec.raw_ptr + sec.raw_size
    if sec.raw_ptr <= 0 or sec.raw_size <= 0 or end > len(data):
        raise ValueError(f"invalid raw span for section {sec.name}")
    return data[sec.raw_ptr:end]


def record_offsets(data: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        off = data.find(MAGIC, start)
        if off == -1:
            return out
        if off + RECORD_SIZE <= len(data):
            out.append(off)
        start = off + 1


def expected_record(sec: Section, body: bytes) -> bytes:
    return MAGIC + struct.pack("<IIQ", sec.rva, sec.raw_size, fnv64(body))


def patch(path: Path, section: str | None) -> tuple[int, Section, int]:
    data = bytearray(path.read_bytes())
    sec = pick_section(pe_sections(data), section)
    body = section_bytes(data, sec)
    records = record_offsets(data)
    if not records:
        raise ValueError("post-link hash slot not found")
    rec = expected_record(sec, body)
    for off in records:
        data[off:off + RECORD_SIZE] = rec
    path.write_bytes(data)
    return len(records), sec, fnv64(body)


def verify(path: Path, section: str | None) -> tuple[int, Section, int]:
    data = path.read_bytes()
    sec = pick_section(pe_sections(data), section)
    body = section_bytes(data, sec)
    rec = expected_record(sec, body)
    records = record_offsets(data)
    if not records:
        raise ValueError("post-link hash slot not found")
    bad = [off for off in records if data[off:off + RECORD_SIZE] != rec]
    if bad:
        raise ValueError(
            "post-link hash mismatch at " +
            ", ".join(f"0x{off:x}" for off in bad))
    return len(records), sec, fnv64(body)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("patch", "verify"))
    parser.add_argument("binary", type=Path)
    parser.add_argument("--section")
    args = parser.parse_args(argv)
    try:
        if args.mode == "patch":
            count, sec, h = patch(args.binary, args.section)
        else:
            count, sec, h = verify(args.binary, args.section)
    except ValueError as e:
        print(f"{args.mode}: {e}", file=sys.stderr)
        return 1
    print(f"{args.mode}: ok records={count} section={sec.name} "
          f"rva=0x{sec.rva:x} size=0x{sec.raw_size:x} hash=0x{h:016x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
