"""Native-vs-protected memory semantics stress verifier."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

from verify_tier_recipe import TIER_C_FLAGS, parse_compat_report
from verify_vmp_coverage import CLANG, run


SOURCE = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VMP __attribute__((noinline, annotate("+vmp")))
#define NO_VMP __attribute__((annotate("-vmp")))
#define OBF __attribute__((noinline))

typedef uint32_t unaligned_u32 __attribute__((aligned(1)));

struct Cell {
  uint32_t tag;
  uint16_t len;
  uint8_t data[10];
};

static uint8_t g_blob[160];
static uint32_t g_words[40];
static volatile uint32_t g_tap;

OBF uint32_t overlap_case(uint8_t *buf, uint32_t seed) {
  uint8_t tmp[96];
  for (unsigned i = 0; i < 128; ++i)
    buf[i] = (uint8_t)(seed + i * 17u + (seed >> (i & 7)));
  __builtin_memset(tmp, (int)(seed ^ 0x5au), sizeof(tmp));
  __builtin_memcpy(tmp + 8, buf + 13, 72);
  __builtin_memmove(buf + 19, buf + 3, 81);
  __builtin_memmove(buf + 2, buf + 29, 67);
  __builtin_memcpy(buf + 88, tmp + 11, 31);
  uint32_t acc = seed ^ 0x9e3779b9u;
  for (unsigned i = 0; i < 64; ++i) {
    unsigned a = (i * 7u + seed) & 127u;
    unsigned b = (i * 5u + (seed >> 3)) & 95u;
    buf[a] = (uint8_t)(buf[a] ^ (tmp[b] + i));
    acc = (acc << 5) | (acc >> 27);
    acc ^= (uint32_t)buf[a] + ((uint32_t)tmp[b] << (i & 3));
  }
  uint32_t probe = 0;
  __builtin_memcpy(&probe, buf + (seed & 63u), sizeof(probe));
  return acc ^ probe ^ buf[0] ^ ((uint32_t)buf[127] << 8);
}

VMP uint32_t alias_case(uint32_t *words, uint8_t *bytes, uint32_t seed) {
  for (unsigned i = 0; i < 24; ++i)
    words[i] = seed * (i + 3u) + 0x1020304u + (i << (i & 3));
  uint32_t *p = &words[seed & 7u];
  uint32_t *q = &words[(seed >> 3) & 7u];
  *p = *p + 0x11111111u;
  *q = (*q ^ *p) + (uint32_t)(p == q);
  for (unsigned i = 0; i < 32; ++i) {
    unsigned off = (seed + i * 9u) & 95u;
    bytes[off] = (uint8_t)(bytes[off] + (uint8_t)(*p >> (i & 7)));
  }
  uint32_t copy = 0;
  __builtin_memcpy(&copy, bytes + ((seed >> 1) & 60u), sizeof(copy));
  g_tap ^= copy + words[(seed >> 5) & 15u];
  return copy ^ *p ^ *q ^ g_tap;
}

OBF uint32_t struct_case(struct Cell *cells, uint8_t *bytes, uint32_t seed) {
  for (unsigned i = 0; i < 6; ++i) {
    cells[i].tag = seed ^ (0x45d9f3bu * (i + 1u));
    cells[i].len = (uint16_t)((seed >> (i & 7)) + i * 13u);
    for (unsigned j = 0; j < sizeof(cells[i].data); ++j)
      cells[i].data[j] = (uint8_t)(cells[i].tag >> ((j & 3) * 8));
  }
  unsigned idx = (seed >> 4) % 6u;
  cells[idx].data[(seed >> 2) % sizeof(cells[idx].data)] ^= (uint8_t)seed;
  __builtin_memcpy(bytes + 17, cells[idx].data, sizeof(cells[idx].data));
  unaligned_u32 *u = (unaligned_u32 *)(void *)(bytes + 19);
  uint32_t pulled = *u;
  *u = pulled ^ cells[idx].tag ^ cells[idx].len;
  return *u + cells[(idx + 3u) % 6u].tag + bytes[17] + bytes[28];
}

OBF uint32_t pointer_chase_case(uint32_t *words, uint32_t seed) {
  unsigned idx = seed & 15u;
  for (unsigned step = 0; step < 37; ++step) {
    uint32_t next = (words[idx] ^ seed ^ step) & 15u;
    words[idx] = (words[idx] + words[next]) ^ (0xa5a50000u + step);
    idx = next;
  }
  return words[idx] ^ words[(idx + 5u) & 15u] ^ (uint32_t)idx;
}

NO_VMP int main(int argc, char **argv) {
  uint32_t seed = argc > 1 ? (uint32_t)strtoul(argv[1], 0, 0) : 0x1234u;
  struct Cell cells[6];
  __builtin_memset(g_blob, 0, sizeof(g_blob));
  __builtin_memset(g_words, 0, sizeof(g_words));
  __builtin_memset(cells, 0, sizeof(cells));
  uint32_t a = overlap_case(g_blob, seed);
  uint32_t b = alias_case(g_words, g_blob, seed ^ 0x55aa33ccu);
  uint32_t c = struct_case(cells, g_blob, seed + 0x31415927u);
  uint32_t d = pointer_chase_case(g_words, seed ^ c);
  uint32_t final = a ^ (b * 33u) ^ (c * 17u) ^ d ^ g_words[3] ^ g_blob[91];
  printf("memstress:%08x:%08x:%08x:%08x:%08x:%08x\n",
         seed, a, b, c, d, final);
  return 0;
}
"""

VMP_FUNCTIONS = {
    "alias_case",
}

SEEDS = [
    "0",
    "1",
    "7",
    "0x12345678",
    "0x80000000",
    "0xffffffff",
    "0x9e3779b9",
    "0xc001d00d",
]


def compile_exe(
    src: Path,
    out: Path,
    *,
    protected: bool,
    report: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [str(CLANG), str(src), "-O2", "-o", str(out)]
    if protected:
        cfg = out.with_suffix(".json")
        cfg.write_text(
            '{"randomSeed":"taokari-semantic-memory-stress",'
            '"meta":{"enable":true,"level":3,"releaseStrip":true,'
            '"randomizeSections":true}}',
            encoding="utf-8",
        )
        cmd.extend(TIER_C_FLAGS)
        cmd.extend([
            "-mllvm", f"-taokari-cfg={cfg}",
            "-mllvm", "-taokari-vmp-max-bytecode-words=8192",
            "-mllvm", "-taokari-vmp-max-bytecode-expansion=128",
            "-Rpass=taokari-vmp",
            "-Rpass-missed=taokari-vmp",
        ])
        if report is not None:
            cmd.extend(["-mllvm", f"-taokari-vmp-compat-report={report}"])
    return run(cmd, use_vs_env=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-memstress-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "memstress.c"
        native = tmpdir / "native.exe"
        protected = tmpdir / "protected.exe"
        report = tmpdir / "vmp_report.tsv"
        src.write_text(SOURCE, encoding="utf-8")

        native_build = compile_exe(src, native, protected=False)
        if native_build.returncode:
            sys.stderr.write(native_build.stdout + native_build.stderr)
            return 1
        protected_build = compile_exe(src, protected, protected=True, report=report)
        if protected_build.returncode:
            sys.stderr.write(protected_build.stdout + protected_build.stderr)
            return 1

        failures: list[str] = []
        for seed in SEEDS:
            native_run = run([str(native), seed])
            protected_run = run([str(protected), seed])
            if native_run.returncode or protected_run.returncode:
                failures.append(
                    f"{seed}: exit native={native_run.returncode} "
                    f"protected={protected_run.returncode}"
                )
                sys.stderr.write(native_run.stdout + native_run.stderr)
                sys.stderr.write(protected_run.stdout + protected_run.stderr)
                continue
            if native_run.stdout != protected_run.stdout:
                failures.append(
                    f"{seed}: stdout mismatch native={native_run.stdout!r} "
                    f"protected={protected_run.stdout!r}"
                )

        report_text = report.read_text(encoding="utf-8", errors="ignore") if report.exists() else ""
        rows = parse_compat_report(report_text)
        virtualized = {
            name for name, row in rows.items()
            if row.get("status") == "virtualized"
        }
        missing = VMP_FUNCTIONS - virtualized
        if missing:
            failures.append(f"missing virtualized functions: {sorted(missing)}")

        if failures:
            print("semantic memory stress: FAIL", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1

    print(
        f"semantic memory stress: ok "
        f"({len(SEEDS)} seeds, {len(VMP_FUNCTIONS)} VMP functions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
