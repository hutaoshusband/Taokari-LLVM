"""Plugin-style DLL fixture (todo.md F2).

A real-world compatibility case for a plugin ABI: a DLL exports a
plugin_get_info function returning a versioned info struct (abi_version,
name, capabilities), and a plugin_run entry point. The host probes the ABI
version, rejects a mismatched plugin, and only calls run on a compatible
one. Struct-return exports and version-gated dispatch must survive the
obfuscator.

Contract:
  * Build a compatible plugin (abi_version == HOST_ABI) and a mismatched one
    (different version), both under full obfuscation.
  * Build a host that probes each plugin's info and only calls run on the
    compatible one.
  * The compatible plugin's run result must equal the expected native
    result; the mismatched plugin must be rejected.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write((result.stdout or "") + (result.stderr or ""))
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


OBF_FLAGS = mllvm(["-taokari", "-taokari-indbr", "-taokari-icall", "-taokari-indgv",
                   "-taokari-fla", "-taokari-bcf", "-taokari-mba", "-taokari-cse",
                   "-taokari-cie", "-taokari-cfe"])


def plugin_source(abi_version: int, plugin_name: str) -> str:
    return (
        '#include <stdint.h>\n'
        '#include <string.h>\n'
        '\n'
        'struct PluginInfo {\n'
        '  uint32_t abi_version;\n'
        '  char name[16];\n'
        '  uint32_t capabilities;\n'
        '};\n'
        '\n'
        '__declspec(dllexport) void plugin_get_info(struct PluginInfo *out) {\n'
        '  out->abi_version = ' + str(abi_version) + 'u;\n'
        '  memset(out->name, 0, sizeof(out->name));\n'
        '  const char *src = "' + plugin_name + '";\n'
        '  for (int i = 0; src[i] && i < 15; ++i)\n'
        '    out->name[i] = src[i];\n'
        '  out->capabilities = 0x3;\n'
        '}\n'
        '\n'
        '__declspec(dllexport) int32_t plugin_run(int32_t input) {\n'
        '  int32_t acc = input;\n'
        '  for (int32_t i = 0; i < input; ++i)\n'
        '    acc = (acc * 7) ^ (i + 3);\n'
        '  return acc + 0x42;\n'
        '}\n'
    )


HOST_SOURCE = r"""
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HOST_ABI 2u

struct PluginInfo {
  uint32_t abi_version;
  char name[16];
  uint32_t capabilities;
};

typedef void (*get_info_t)(struct PluginInfo *);
typedef int32_t (*run_t)(int32_t);

static int probe_and_run(const char *path, int32_t input, int32_t *out) {
  HMODULE dll = LoadLibraryA(path);
  if (!dll)
    return -1;
  get_info_t info = (get_info_t)GetProcAddress(dll, "plugin_get_info");
  run_t run = (run_t)GetProcAddress(dll, "plugin_run");
  if (!info || !run) {
    FreeLibrary(dll);
    return -2;
  }
  struct PluginInfo pi;
  memset(&pi, 0, sizeof(pi));
  info(&pi);
  if (pi.abi_version != HOST_ABI) {
    FreeLibrary(dll);
    return (int)pi.abi_version;
  }
  *out = run(input);
  FreeLibrary(dll);
  return 0;
}

int main(void) {
  int32_t good_out = 0;
  int good_rc = probe_and_run("plugin_good.dll", 5, &good_out);
  int32_t bad_out = 0;
  int bad_rc = probe_and_run("plugin_bad.dll", 5, &bad_out);
  printf("plugin:%d:%d:%d:%d\n", good_rc, good_out, bad_rc, bad_out);
  return 0;
}
"""


def expected_run(input_val: int) -> int:
    acc = input_val
    for i in range(input_val):
        acc = (acc * 7) ^ (i + 3)
    return (acc + 0x42) & 0xFFFFFFFF


def to_signed(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-plugin-") as tmp_name:
        tmp = Path(tmp_name)
        good_src = tmp / "good.c"
        good_src.write_text(plugin_source(2, "taokari-good"), encoding="utf-8")
        bad_src = tmp / "bad.c"
        bad_src.write_text(plugin_source(99, "taokari-bad"), encoding="utf-8")
        host_src = tmp / "host.c"
        host_src.write_text(HOST_SOURCE, encoding="utf-8")

        good_dll = tmp / "plugin_good.dll"
        bad_dll = tmp / "plugin_bad.dll"
        if not must(run([str(CLANG), str(good_src), "-O2", "-shared",
                         *OBF_FLAGS, "-o", str(good_dll)]),
                    "good plugin build"):
            return 1
        if not must(run([str(CLANG), str(bad_src), "-O2", "-shared",
                         *OBF_FLAGS, "-o", str(bad_dll)]),
                    "bad plugin build"):
            return 1

        host = tmp / "host.exe"
        if not must(run([str(CLANG), str(host_src), "-O2", "-o", str(host)]),
                    "host build"):
            return 1

        result = run([str(host)], cwd=tmp)
        if result.returncode:
            sys.stderr.write(f"host run failed rc={result.returncode}\n")
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        want_run = to_signed(expected_run(5))
        want = f"plugin:0:{want_run}:99:0\n"
        if result.stdout != want:
            print(f"FAIL: plugin result {result.stdout!r} != expected {want!r}",
                  file=sys.stderr)
            return 1

    print(f"plugin-dll: ok (good plugin accepted + run matches native; bad "
          f"plugin rejected by ABI version gate)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
