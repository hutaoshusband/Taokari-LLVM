"""Build stable VMP samples for devirtualization experiments."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

from verify_vmp_basic_block_bytecode import CLANG, ROOT, run


CASE = ROOT / "testing" / "cases" / "vmp_devirtualization_samples" / "src" / "main.c"
OUT = ROOT / "build" / "vmp-devirt-samples"
TARGETS = {
    "sample_linear",
    "sample_branch",
    "sample_mask",
    "sample_state",
}


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def checked(cmd: list[str], *, use_vs_env: bool = False,
            timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = run(cmd, use_vs_env=use_vs_env, timeout=timeout)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(result.returncode)
    return result


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    if not CASE.exists():
        print(f"missing sample source: {CASE}", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    native = OUT / "vmp_devirt_native.exe"
    protected = OUT / "vmp_devirt_vmp.exe"
    ir = OUT / "vmp_devirt_vmp.ll"
    report = OUT / "vmp_devirt_vmp.tsv"

    common = [str(CASE), "-O2", "-fno-discard-value-names"]
    checked([str(CLANG), *common, "-o", str(native)], use_vs_env=True)
    vmp_flags = [
        str(CLANG), "-DTAOKARI_USE_VMP=1", *common,
        "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        "-mllvm", f"-taokari-vmp-compat-report={report}",
    ]
    checked([*vmp_flags, "-S", "-emit-llvm", "-o", str(ir)], use_vs_env=True)
    checked([*vmp_flags, "-o", str(protected)], use_vs_env=True)

    native_run = checked([str(native)])
    vmp_run = checked([str(protected)])
    if native_run.stdout != vmp_run.stdout:
        raise SystemExit("native/VMP sample output mismatch")

    rows = compat_rows(report)
    missing = sorted(name for name in TARGETS if rows.get(name) != "virtualized")
    if missing:
        raise SystemExit(f"VMP samples did not virtualize: {missing}")

    text = ir.read_text(encoding="utf-8", errors="ignore")
    for name in TARGETS:
        if f"__taokari_vmp_bc_{name}" not in text:
            raise SystemExit(f"missing bytecode global for {name}")
        if f"__taokari_vmp_interp_i64_{name}" not in text:
            raise SystemExit(f"missing interpreter for {name}")

    (OUT / "README.txt").write_text(
        "VMP devirtualization samples.\n"
        "Use vmp_devirt_vmp.exe and vmp_devirt_vmp.ll for analysis.\n",
        encoding="utf-8",
    )
    for stale in OUT.glob("*.tmp"):
        stale.unlink(missing_ok=True)

    print(f"vmp devirtualization samples: ok ({protected})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
