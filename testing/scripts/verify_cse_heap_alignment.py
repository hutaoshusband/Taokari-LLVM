"""Heap-decrypted strings retain explicit alignment and free the raw allocation.

The old malloc replacement lost a source global's align 64 contract. An
aligned, volatile 16-byte load exercises it using baseline x64 SSE2. Keep the
consumer non-capturing so CSE actually chooses a temporary heap buffer rather
than retaining shared global storage for an address-observing ptrtoint use.
Fresh processes vary allocator placement.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


SOURCE = r'''
@s = private constant [18 x i8] c"heap-align-secret\00", align 64
define i32 @consume(ptr captures(none) align 64 %p) noinline optnone {
  %v = load volatile <16 x i8>, ptr %p, align 64
  %first = extractelement <16 x i8> %v, i32 0
  %data_ok = icmp eq i8 %first, 104
  %address = ptrtoint ptr %p to i64
  %low = and i64 %address, 63
  %aligned = icmp eq i64 %low, 0
  %ok = and i1 %data_ok, %aligned
  %r = select i1 %ok, i32 0, i32 7
  ret i32 %r
}

define i32 @main() {
  %r = call i32 @consume(ptr @s)
  %ok = icmp eq i32 %r, 0
  %rc = select i1 %ok, i32 0, i32 7
  ret i32 %rc
}
'''


def checked(command: list[str], *, vs: bool = False):
    result = tp.run(command, vs=vs)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {' '.join(command)}\n"
                           f"{result.stdout}{result.stderr}")
    return result


def main() -> int:
    opt = tp.tool("opt")
    if not tp.CLANG.exists() or not opt.exists():
        print("missing clang or opt", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="taokari-cse-align-") as tmp:
        work = Path(tmp)
        src = work / "align.ll"
        src.write_text(SOURCE, encoding="utf-8")
        plain = work / tp.exe_name("native")
        checked([str(tp.CLANG), str(src), "-O0", "-o", str(plain)], vs=True)
        checked([str(plain)])
        for level in (1, 3, 4):
            cfg = work / "heap.json"
            cfg.write_text(json.dumps({"cse": {
                "enable": True, "level": level, "heapDecrypt": True,
            }}), encoding="utf-8")
            for variant in range(3):
                ir = work / "protected.ll"
                checked([str(tp.CLANG), str(src), "-O0", "-S", "-emit-llvm",
                         "-mllvm", "-taokari-cse", "-mllvm",
                         f"-taokari-cfg={cfg}", "-o", str(ir)])
                text = ir.read_text(encoding="utf-8")
                assert "EncryptedStringTable" in text and "@malloc(" in text
                assert re.search(r"and i64 [^\n]*, -64", text), "heap view lost align 64"
                checked([str(opt), "-passes=verify", "-disable-output", str(ir)])
                for optimization in ("-O0", "-O2"):
                    exe = work / tp.exe_name("protected")
                    checked([str(tp.CLANG), str(ir), optimization, "-Xclang",
                             "-disable-llvm-passes", "-o", str(exe)], vs=True)
                    assert b"heap-align-secret" not in exe.read_bytes()
                    for _ in range(8):
                        checked([str(exe)])
            print(f"cse heap alignment: level {level}: 3 variants, both backends, "
                  "8 processes each ok", flush=True)
    print("cse heap alignment: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
