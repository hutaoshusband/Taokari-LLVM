"""String/aggregate PHIs on catchswitch edges remain legal and catch throws."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


SOURCE = r'''
@s = private constant [10 x i8] c"eh-secret\00"
@bundle = internal constant { ptr, i32 } { ptr @s, i32 11 }
declare i32 @__CxxFrameHandler3(...)
declare void @may_throw()

define i32 @test() noinline optnone personality ptr @__CxxFrameHandler3 {
entry:
  invoke void @may_throw() to label %normal unwind label %dispatch
dispatch:
  %cs = catchswitch within none [label %handler] unwind to caller
handler:
  %p = phi ptr [@s, %dispatch]
  %u = phi ptr [@bundle, %dispatch]
  %cp = catchpad within %cs [ptr null, i32 64, ptr null]
  %q = load ptr, ptr %u
  %v = load i8, ptr %p
  %w = load i8, ptr %q
  %same = icmp eq i8 %v, %w
  %value = zext i8 %v to i32
  %r = select i1 %same, i32 %value, i32 0
  catchret from %cp to label %exit
normal:
  ret i32 0
exit:
  ret i32 %r
}
'''

DRIVER = r'''
extern "C" int test();
extern "C" void may_throw() { throw 17; }
int main() { return test() == 'e' ? 0 : 7; }
'''


def checked(command: list[str], *, vs: bool = False):
    result = tp.run(command, vs=vs)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {' '.join(command)}\n"
                           f"{result.stdout}{result.stderr}")
    return result


def main() -> int:
    if not tp.IS_WINDOWS or not tp.CLANG.exists() or not tp.tool("opt").exists():
        print("requires Windows clang and opt", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="taokari-cse-catchswitch-") as tmp:
        work = Path(tmp)
        src = work / "handler.ll"
        src.write_text(SOURCE, encoding="utf-8")
        driver = work / "driver.cpp"
        driver.write_text(DRIVER, encoding="utf-8")
        obj = work / "driver.obj"
        checked([str(tp.CLANG), str(driver), "-c", "-o", str(obj)], vs=True)
        native = work / "native.exe"
        checked([str(tp.CLANG), str(src), str(obj), "-O0", "-o", str(native)], vs=True)
        checked([str(native)])
        for level in (1, 3):
            cfg = work / "cse.json"
            cfg.write_text(json.dumps({"cse": {"enable": True, "level": level}}),
                           encoding="utf-8")
            for variant in range(3):
                ir = work / "protected.ll"
                checked([str(tp.CLANG), str(src), "-O0", "-S", "-emit-llvm",
                         "-mllvm", "-taokari-cse", "-mllvm",
                         f"-taokari-cfg={cfg}", "-o", str(ir)])
                text = ir.read_text(encoding="utf-8")
                assert "catchswitch" in text and "EncryptedStringTable" in text
                checked([str(tp.tool("opt")), "-passes=verify", "-disable-output", str(ir)])
                for optimization in ("-O0", "-O2"):
                    exe = work / "protected.exe"
                    checked([str(tp.CLANG), str(ir), str(obj), optimization,
                             "-Xclang", "-disable-llvm-passes", "-o", str(exe)], vs=True)
                    assert b"eh-secret" not in exe.read_bytes(), "plaintext leak"
                    checked([str(exe)])
            print(f"cse catchswitch PHIs: level {level}: "
                  "3 variants, both backends and native EH ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
