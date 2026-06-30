from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


ROOT = tp.ROOT
CLANG = tp.CLANG
READELF = tp.READELF

CPP_SOURCE = r"""
#include <cstdio>

namespace acme {
class SecretPayload {
public:
    virtual ~SecretPayload() {}
    virtual int value() const { return 0x7e57; }
};

class AnotherSecret {
public:
    virtual ~AnotherSecret() {}
    virtual int fetch() const { return 0xa11ce; }
};
}

int main() {
    acme::SecretPayload a;
    acme::AnotherSecret b;
    printf("rtti:%d:%d\n", a.value(), b.fetch());
    return 0;
}
"""

RTTI_CFG = r"""
{
  "randomSeed": "taokari-itanium-rtti-test-seed"
}
"""


def main() -> int:
    if tp.IS_WINDOWS:
        print("rtti-itanium: skipped on Windows (Itanium ABI is ELF/Linux only)")
        return 2
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-rtti-it-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "rtti.cpp"
        src.write_text(CPP_SOURCE, encoding="utf-8")
        cfg = tmp / "rtti.json"
        cfg.write_text(RTTI_CFG, encoding="utf-8")

        plain = tmp / tp.exe_name("plain")
        res = tp.run([str(CLANG), "-O2", "-std=c++17", "-frtti",
                      str(src), "-o", str(plain)])
        if res.returncode:
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        plain_syms = tp.run([str(READELF), "-s", "-W", str(plain)]).stdout
        if "SecretPayload" not in plain_syms and "Secret" not in plain_syms:
            print("plain build does not expose the class name (baseline check)",
                  file=sys.stderr)

        obf = tmp / tp.exe_name("obf")
        res = tp.run([str(CLANG), "-O2", "-std=c++17", "-frtti",
                      "-mllvm", "-taokari", "-mllvm", "-taokari-rtti",
                      f"-mllvm", f"-taokari-cfg={cfg}",
                      str(src), "-o", str(obf)])
        if res.returncode:
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode

        obf_syms = tp.run([str(READELF), "-s", "-W", str(obf)]).stdout
        obf_dynsyms = tp.run([str(READELF), "--dyn-syms", "-W", str(obf)]).stdout
        obf_rodata = b""
        for sec in (".rodata", ".data.rel.ro", ".data.rel.ro.local"):
            dump = tp.run([str(READELF), "-p", sec, str(obf)])
            if dump.returncode == 0:
                obf_rodata += dump.stdout.encode("utf-8", "ignore")
        haystack = obf_syms + obf_dynsyms + obf_rodata.decode("utf-8", "ignore")
        leaked = []
        for needle in ("SecretPayload", "AnotherSecret"):
            if needle in haystack:
                leaked.append(needle)
        if leaked:
            print(f"RTTI class names leaked after Itanium eraser: {leaked}",
                  file=sys.stderr)
            return 1

        obf_run = tp.run([str(obf)])
        plain_run = tp.run([str(plain)])
        if obf_run.returncode:
            print(f"obf runtime failed: {obf_run.stdout}{obf_run.stderr}",
                  file=sys.stderr)
            return obf_run.returncode
        if obf_run.stdout != plain_run.stdout:
            print(f"output drift:\n  obf: {obf_run.stdout!r}\n  ref: {plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print("rtti-itanium: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
