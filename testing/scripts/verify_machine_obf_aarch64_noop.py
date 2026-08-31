"""AArch64 MIR no-op hook verifier (todo.md A2, MACHINE_IR_AARCH64_PARITY step 4).

Cross-compiles a fixture for aarch64-linux-gnu with -taokari-mir enabled and
checks: compile rc 0, -verify-machineinstrs clean, and object bytes identical
to a non-MIR build (infrastructure parity until AArch64 sub-passes land).

Exit: 0 ok | 1 failure | 2 skip (no clang or no AArch64 backend).
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

SRC = """int fold(int x) {
    int s = 0;
    for (int i = 0; i < 8; ++i) s += x * (i + 1);
    return s;
}
int entry(void) { return fold(3); }
"""
MIR_FLAGS = ("-mllvm", "-taokari-mir=dirtybytes,junk,sub,split,fakeprologue")


def main() -> int:
    clang = tp.CLANG
    if not clang.exists():
        print("machine_obf_aarch64_noop: skip (no clang)", file=sys.stderr)
        return 2
    targets = tp.run([str(clang), "--print-targets"])
    if targets.returncode or "aarch64" not in targets.stdout:
        print("machine_obf_aarch64_noop: skip (no AArch64 backend)", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="taokari-mir-a64-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "f.c"
        src.write_text(SRC, encoding="utf-8")
        common = ["-target", "aarch64-linux-gnu", "-c", str(src), "-O2",
                  "-mllvm", "-verify-machineinstrs"]
        base_obj = tmpdir / "base.o"
        mir_obj = tmpdir / "mir.o"
        for obj, extra in ((base_obj, ()), (mir_obj, MIR_FLAGS)):
            r = tp.run([str(clang), *common, *extra, "-o", str(obj)], vs=tp.IS_WINDOWS)
            if r.returncode:
                tag = "baseline" if obj is base_obj else "MIR"
                print(f"machine_obf_aarch64_noop: FAIL {tag} compile\n{r.stderr}", file=sys.stderr)
                return 1
        if base_obj.read_bytes() != mir_obj.read_bytes():
            print("machine_obf_aarch64_noop: FAIL MIR object differs from non-MIR build",
                  file=sys.stderr)
            return 1
    print("machine_obf_aarch64_noop: ok (rc 0, verify-machineinstrs clean, object identical)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
