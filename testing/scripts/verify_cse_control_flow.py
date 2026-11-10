"""CSE must initialize each PHI edge and preserve musttail/lifetime rules.

Use handwritten IR so frontend optimization cannot erase the PHI regression.
Check each path in a fresh process, verifier-clean output, and encrypted-at-rest
secrets across three randomized builds per configuration.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


PHI = r'''
@s = private constant [16 x i8] c"phi-edge-secret\00"
@t = private constant [17 x i8] c"phi-other-secret\00"
@bundle = internal constant { ptr, i32 } { ptr @s, i32 17 }
declare i32 @puts(ptr)

define ptr @choose(i32 %n) noinline optnone {
entry:
  %c = icmp eq i32 %n, 1
  br i1 %c, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %p = phi ptr [ @s, %left ], [ @s, %right ]
  ret ptr %p
}

define ptr @aggregate(i32 %n) noinline optnone {
entry:
  %c = icmp eq i32 %n, 1
  br i1 %c, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %p = phi ptr [ @bundle, %left ], [ @bundle, %right ]
  %s = load ptr, ptr %p
  ret ptr %s
}

define ptr @join_use(i32 %n) noinline optnone {
entry:
  %c = icmp eq i32 %n, 1
  br i1 %c, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %p = phi ptr [ @s, %left ], [ @t, %right ]
  %r = call i32 @puts(ptr %p)
  ; A decrypt on just one incoming edge does not initialize @s on the other.
  ret ptr @s
}

define i32 @main(i32 %argc, ptr %argv) {
  %p = call ptr @choose(i32 %argc)
  %a = call i32 @puts(ptr %p)
  %q = call ptr @aggregate(i32 %argc)
  %b = call i32 @puts(ptr %q)
  %j = call ptr @join_use(i32 %argc)
  %c = call i32 @puts(ptr %j)
  ret i32 0
}
'''

MUSTTAIL = r'''
@s = private constant [13 x i8] c"tail-secret!\00"
declare i32 @puts(ptr)

define i32 @sink(ptr captures(none) %p) noinline optnone {
  %r = call i32 @puts(ptr %p)
  ret i32 0
}

define i32 @tail(ptr %unused) noinline optnone {
  ; Also exercise a deferred local string before the tail-call exit.
  %p = getelementptr [13 x i8], ptr @s, i32 0, i32 1
  %r0 = call i32 @puts(ptr %p)
  %r = musttail call i32 @sink(ptr @s)
  ret i32 %r
}

define i32 @main() {
  %r = call i32 @tail(ptr null)
  ret i32 %r
}
'''

LOOP = r'''
@s = private constant [13 x i8] c"loop-secret!\00"
declare i32 @puts(ptr)
define i32 @sink(ptr captures(none) %p) noinline optnone {
  %v = load i8, ptr %p
  %r = zext i8 %v to i32
  ret i32 %r
}
define i32 @main() {
entry:
  br label %loop
loop:
  %i = phi i32 [0, %entry], [%next, %loop]
  %v = call i32 @sink(ptr @s)
  %next = add i32 %i, 1
  %done = icmp eq i32 %next, 300000
  br i1 %done, label %exit, label %loop
exit:
  %r = call i32 @puts(ptr @s)
  ret i32 0
}
'''


def checked(cmd: list[str], *, vs: bool = False):
    result = tp.run(cmd, vs=vs)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {' '.join(cmd)}\n"
                           f"{result.stdout}{result.stderr}")
    return result


def main() -> int:
    opt = tp.tool("opt")
    if not tp.CLANG.exists() or not opt.exists():
        print("missing clang or opt", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="taokari-cse-cfg-") as tmp:
        work = Path(tmp)
        for name, source, secrets in (
            ("phi", PHI, (b"phi-edge-secret", b"phi-other-secret")),
            ("musttail", MUSTTAIL, (b"tail-secret!",)),
            ("loop", LOOP, (b"loop-secret!",)),
        ):
            src = work / f"{name}.ll"
            src.write_text(source, encoding="utf-8")
            native = work / tp.exe_name(f"{name}-plain")
            checked([str(tp.CLANG), str(src), "-O0", "-o", str(native)], vs=True)
            inputs = ([], ["other-edge"]) if name == "phi" else ([],)
            refs = [checked([str(native), *args]).stdout for args in inputs]
            for level, heap in ((1, False), (3, False), (3, True)):
                cfg = work / "cse.json"
                cfg.write_text(json.dumps({"cse": {
                    "enable": True, "level": level,
                    "heapDecrypt": heap, "reencryptAfterUse": True,
                }}), encoding="utf-8")
                for variant in range(3):
                    ir = work / "protected.ll"
                    checked([str(tp.CLANG), str(src), "-O0", "-S", "-emit-llvm",
                             "-fno-discard-value-names", "-mllvm", "-taokari-cse",
                             "-mllvm", f"-taokari-cfg={cfg}", "-o", str(ir)])
                    checked([str(opt), "-passes=verify", "-disable-output", str(ir)])
                    text = ir.read_text(encoding="utf-8")
                    assert "EncryptedStringTable" in text, "CSE did not run"
                    if name == "musttail":
                        assert "musttail call" in text, "musttail was dropped"
                    # Freeze the transformed IR; exercise both backend opt levels.
                    for optimization in ("-O0", "-O2"):
                        exe = work / tp.exe_name("protected")
                        checked([str(tp.CLANG), str(ir), optimization, "-Xclang",
                                 "-disable-llvm-passes", "-o", str(exe)], vs=True)
                        for args, expected in zip(inputs, refs):
                            got = checked([str(exe), *args]).stdout
                            assert got == expected, (name, level, heap, variant,
                                                     optimization, args, got, expected)
                        blob = exe.read_bytes()
                        assert not any(s in blob for s in secrets), "plaintext leak"
                print(f"{name}: level={level} heap={heap}: 3 variants, both backends ok",
                      flush=True)
    print("cse control flow: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
