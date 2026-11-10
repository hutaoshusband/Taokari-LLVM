"""CSE preserves returned/encoded aliases and scrubs after their last read."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


SOURCE = r'''
@s = private constant [15 x i8] c"alias-lifetime\00", align 16
@number = private constant [13 x i8] c"123-lifetime\00"
declare ptr @strchr(ptr, i32)
declare LONG @strtol(ptr, ptr, i32)
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

define ptr @escape() noinline optnone {
  %a = getelementptr i8, ptr @s, i64 1
  %b = getelementptr i8, ptr %a, i64 1
  ret ptr %b
}

define ptr @escape_via_slot() noinline optnone {
  %slot = alloca ptr
  store ptr @s, ptr %slot
  %p = load ptr, ptr %slot
  ret ptr %p
}

define void @clobber() noinline optnone {
  %buf = alloca [65536 x i8], align 16
  call void @llvm.memset.p0.i64(ptr %buf, i8 0, i64 65536, i1 true)
  ret void
}

define i1 @identity() noinline optnone {
  %a = ptrtoint ptr @s to i64
  %b = ptrtoint ptr @s to i64
  %eq = icmp eq i64 %a, %b
  ret i1 %eq
}

define ptr @parse() noinline optnone {
  ; strtol captures a pointer into its input through endptr.
  %slot = alloca ptr
  %value = call LONG @strtol(ptr @number, ptr %slot, i32 10)
  %end = load ptr, ptr %slot
  ret ptr %end
}

define i1 @read_alias() noinline optnone {
  ; A safe local alias still receives deferred scrubbing at fortress levels.
  %p = call ptr @strchr(ptr @s, i32 108)
  %q = getelementptr i8, ptr %p, i64 1
  %a = load i8, ptr %p
  %b = load i8, ptr %q
  %a_ok = icmp eq i8 %a, 108
  %b_ok = icmp eq i8 %b, 105
  %ok = and i1 %a_ok, %b_ok
  ret i1 %ok
}

define i32 @main() {
  ; A pointer-returning libc call does not finish consuming the string.
  ; A scalar user may encode an alias, rather than read its contents.
  %p = call ptr @strchr(ptr @s, i32 108)
  %address = ptrtoint ptr %p to i64
  %alias = inttoptr i64 %address to ptr
  %v = load i8, ptr %alias
  %ok = icmp eq i8 %v, 108
  %r = call ptr @escape()
  call void @clobber()
  %w = load i8, ptr %r
  %escaped_ok = icmp eq i8 %w, 105
  %both = and i1 %ok, %escaped_ok
  %same_address = call i1 @identity()
  %all = and i1 %both, %same_address
  %end = call ptr @parse()
  call void @clobber()
  %suffix = load i8, ptr %end
  %suffix_ok = icmp eq i8 %suffix, 45
  %result = and i1 %all, %suffix_ok
  %live_ok = call i1 @read_alias()
  %complete = and i1 %result, %live_ok
  %stored = call ptr @escape_via_slot()
  call void @clobber()
  %first = load i8, ptr %stored
  %stored_ok = icmp eq i8 %first, 97
  %final = and i1 %complete, %stored_ok
  %rc = select i1 %final, i32 0, i32 7
  ret i32 %rc
}
'''
SOURCE = SOURCE.replace("LONG", "i32" if tp.IS_WINDOWS else "i64")


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
    with tempfile.TemporaryDirectory(prefix="taokari-cse-lifetime-") as tmp:
        work = Path(tmp)
        src = work / "alias.ll"
        src.write_text(SOURCE, encoding="utf-8")
        native = work / tp.exe_name("native")
        checked([str(tp.CLANG), str(src), "-O0", "-o", str(native)], vs=True)
        checked([str(native)])
        for level, heap in ((1, False), (3, False), (3, True), (4, False)):
            cfg = work / "cse.json"
            cfg.write_text(json.dumps({"cse": {
                "enable": True, "level": level, "heapDecrypt": heap,
                "localStackDecrypt": not heap, "reencryptAfterUse": True,
            }}), encoding="utf-8")
            for variant in range(3):
                ir = work / "protected.ll"
                checked([str(tp.CLANG), str(src), "-O0", "-S", "-emit-llvm",
                         "-mllvm", "-taokari-cse", "-mllvm",
                         f"-taokari-cfg={cfg}", "-o", str(ir)])
                text = ir.read_text(encoding="utf-8")
                assert "EncryptedStringTable" in text, "CSE did not run"
                escaped = text.split("define ptr @escape()", 1)[1].split("\n}", 1)[0]
                assert "alloca" not in escaped, "returned alias uses a local buffer"
                assert "@malloc(" not in escaped, "returned alias uses a freed buffer"
                stored = text.split("define ptr @escape_via_slot()", 1)[1].split("\n}", 1)[0]
                assert "[15 x i8]" not in stored and "@malloc(" not in stored, \
                    "stored literal alias lost its static lifetime"
                if level >= 3:
                    local = text.split("define i1 @read_alias()", 1)[1].split("\n}", 1)[0]
                    assert "strenc.scrublive" in local, "safe local alias lost deferred scrubbing"
                    assert "@goron_scrub_string_i8(" in local
                checked([str(opt), "-passes=verify", "-disable-output", str(ir)])
                for optimization in ("-O0", "-O2"):
                    exe = work / tp.exe_name("protected")
                    checked([str(tp.CLANG), str(ir), optimization, "-Xclang",
                             "-disable-llvm-passes", "-o", str(exe)], vs=True)
                    assert not any(s in exe.read_bytes() for s in
                                   (b"alias-lifetime", b"123-lifetime")), "plaintext leak"
                    for _ in range(2):
                        checked([str(exe)])
            print(f"cse pointer lifetime: level={level} heap={heap}: "
                  "3 variants, both backends ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
