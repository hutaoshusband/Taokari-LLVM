"""CSE helper-body fortification verification (TK-048).

The pipeline skip-net exempts the cse helpers by name for every FunctionPass,
so their bodies get zero downstream coverage. TK-048 bakes FunctionOutlining's
fortress trio into the helpers at creation time (StringEncryption.cpp):

  token-integrity gate : <helper>.ic.tok global + <helper>.ic.junk
                         unreachable guard block + <helper>.ic.real body block
  fake call edge       : entry call into an opaque internal __taokari_sh_
                         function with the helper's own signature
  layer split          : where an outlinable tail exists (anchor ctor, L3+
                         decryptor), the tail is extracted behind a token
                         dispatcher that also names a __taokari_sh_ decoy

Contract (same source):
  * L3 -O0 IR: all five helpers (goron_decrypt_string_i8/i16,
    goron_scrub_string_i8/i16, __taokari_strenc_anchor_init) carry the gate
    markers and a fake call edge; decryptor and anchor ctor additionally show
    a dispatcher call edge.
  * L1 -O0 IR (+reencrypt): decoration is baked at creation regardless of
    level (gate + fake edge on every helper).
  * Helpers keep their names, one define each (skip-net exemption unchanged).
  * -O2 IR (-fno-discard-value-names): markers survive optimization.
  * Runtime parity byte-exact at -O2 (L3 and L1+reencrypt), and no secret
    survives into the -O2 binary in ASCII/UTF-16LE/UTF-16BE.

Inspection levels: block labels need no name flag at -O0; the -O2 gate emits
IR with -fno-discard-value-names so the same labels are greppable.

pre-fix teeth: gate 1 fails on a pre-TK-048 clang (bare helper bodies).
Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SECRETS = (
    "tk048-narrow-secret",
    "tk048-wide-secret",
    "tk048-anchor-alpha-secret",
    "tk048-anchor-bravo-secret",
)

HELPERS = (
    "goron_decrypt_string_i8",
    "goron_decrypt_string_i16",
    "goron_scrub_string_i8",
    "goron_scrub_string_i16",
    "__taokari_strenc_anchor_init",
)

SOURCE = r'''
#include <cstdio>
#include <cstdint>

extern const char16_t *const kExtW[];
const char16_t *const kExtW[] = {
  u"@@ANC0@@",
  u"@@ANC1@@",
};

static const char narrowbuf[] = "@@NARROW@@";
static const char16_t widebuf[] = u"@@WIDE@@";

static const char *names[] = {
  "@@ANC0@@",
  "@@ANC1@@",
};

__declspec(noinline)
static int hash_narrow(const char *s) {
  int h = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    h = h * 131 + *p;
  return h;
}

__declspec(noinline)
static int hash_wide(const char16_t *s) {
  int h = 7;
  for (; *s; ++s)
    h = h * 17 + (int)*s;
  return h;
}

int main(int argc, char **argv) {
  unsigned i = (unsigned)(argc > 1) & 1u;
  if (argc > 2)
    names[0] = "x";
  std::printf("tk048:%d:%d:%d:%d:%s:%d\n",
              hash_narrow(names[i]), hash_narrow(names[1 - i]),
              hash_wide(kExtW[i]), hash_wide(widebuf),
              narrowbuf, (int)(int16_t)widebuf[0] + narrowbuf[1]);
  return 0;
}
'''.replace("@@NARROW@@", SECRETS[0]).replace("@@WIDE@@", SECRETS[1]) \
   .replace("@@ANC0@@", SECRETS[2]).replace("@@ANC1@@", SECRETS[3])


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
  if not tp.IS_WINDOWS:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
  with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                   encoding="utf-8") as handle:
    batch = Path(handle.name)
    handle.write(
        "@echo off\n"
        f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
        f"{subprocess.list2cmdline(command)}\n"
        "exit /b %ERRORLEVEL%\n"
    )
  try:
    return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
  finally:
    batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
  if result.returncode:
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    raise SystemExit(f"{label} failed: {result.returncode}")


def gate(cond: bool, label: str) -> None:
  if not cond:
    raise SystemExit(f"GATE FAILED: {label}")
  print(f"  [ok] {label}")


def write_cfg(path: Path, **extra) -> None:
  cfg = {"cse": {"enable": True}}
  cfg["cse"].update(extra)
  path.write_text(json.dumps(cfg), encoding="utf-8")


def emit_ir(src: Path, out: Path, cfg: Path, opt: str) -> str:
  cmd = [
      str(CLANG), str(src), "-std=c++17", opt, "-S", "-emit-llvm",
      "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
      "-mllvm", f"-taokari-cfg={cfg}", "-o", str(out),
  ]
  if opt != "-O0":
    cmd.append("-fno-discard-value-names")
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec", "-D_GNU_SOURCE"]
  must(run_vs(cmd, src.parent), f"emit IR {out.name}")
  return out.read_text(encoding="utf-8", errors="ignore")


def compile_exe(src: Path, out: Path, cfg: Path | None, opt: str) -> None:
  cmd = [str(CLANG), str(src), "-std=c++17", opt, "-o", str(out)]
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec", "-D_GNU_SOURCE"]
  if cfg:
    cmd += ["-mllvm", "-taokari", "-mllvm", "-taokari-cse",
            "-mllvm", f"-taokari-cfg={cfg}"]
  must(run_vs(cmd, src.parent), f"compile {out.name}")


def helper_body(ir: str, name: str) -> str:
  m = re.search(rf"define[^@]*@{re.escape(name)}\b[\s\S]*?\n}}", ir)
  return m.group(0) if m else ""


def fake_edges(body: str) -> int:
  return len(re.findall(r"call void @__taokari_sh_[0-9a-f]{12,16}\(", body))


def check_gate_markers(ir: str, label: str, layer_expect: dict[str, int],
                       require_once: bool = True) -> None:
  for name in HELPERS:
    body = helper_body(ir, name)
    gate(bool(body), f"{label}: {name} defined")
    gate(f"{name}.ic.tok" in ir, f"{label}: {name}.ic.tok token global")
    gate(f"{name}.ic.junk" in body, f"{label}: {name}.ic.junk guard block")
    gate(f"{name}.ic.real" in body, f"{label}: {name}.ic.real body block")
    edges = fake_edges(body)
    gate(edges >= 1, f"{label}: {name} fake call edge (found {edges})")
    want = layer_expect.get(name, 1)
    gate(edges >= want, f"{label}: {name} >= {want} decoy/dispatcher edges "
                        f"(found {edges})")
    if require_once:
      gate(len(re.findall(rf"define[^@]*@{re.escape(name)}\b", ir)) == 1,
           f"{label}: {name} defined exactly once")


def encodings(secret: str) -> list[bytes]:
  return [secret.encode("utf-8"),
          secret.encode("utf-16-le"),
          secret.encode("utf-16-be")]


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--clang", default=str(tp.CLANG),
                      help="compiler binary under test (parent for teeth)")
  parser.add_argument("--keep", action="store_true")
  args = parser.parse_args()
  clang = Path(args.clang).resolve()
  if not clang.exists():
    print(f"missing clang: {clang}", file=sys.stderr)
    return 2
  global CLANG
  CLANG = clang

  tmp = Path(tempfile.mkdtemp(prefix="taokari-cse-fort-"))
  try:
    src = tmp / "cse_fort.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain = tmp / "plain.exe"
    compile_exe(src, plain, None, "-O2")
    plain_run = run([str(plain)])
    must(plain_run, "plain run")
    gate(plain_run.stdout.startswith("tk048:") and plain_run.stdout.endswith("\n"),
         f"plain binary deterministic output (got {plain_run.stdout!r})")

    # Gate 1 (teeth against a pre-fix binary): the L3 -O0 IR must carry the
    # baked markers on all five helpers. Layer expectation at L3: the anchor
    # ctor (>=2 anchored entries) and both decryptors (MBA branch arms) get a
    # dispatcher edge in addition to the fake edge.
    print(f"gate 1: L3 -O0 IR markers ({clang.name})")
    l3_cfg = tmp / "l3.json"
    write_cfg(l3_cfg, level=3, minStringLength=5)
    l3_ir = emit_ir(src, tmp / "l3-O0.ll", l3_cfg, "-O0")
    check_gate_markers(l3_ir, "L3 -O0",
                       {"__taokari_strenc_anchor_init": 2,
                        "goron_decrypt_string_i8": 2,
                        "goron_decrypt_string_i16": 2})

    # Gate 2: decoration is baked at creation, level-independent. L1 with
    # explicit reencrypt (scrubs exist at L1 only with the knob).
    print("gate 2: L1+reencrypt -O0 IR markers (baked at creation)")
    l1_cfg = tmp / "l1.json"
    write_cfg(l1_cfg, level=1, minStringLength=5, reencryptAfterUse=True)
    l1_ir = emit_ir(src, tmp / "l1-O0.ll", l1_cfg, "-O0")
    check_gate_markers(l1_ir, "L1 -O0", {})

    # Gate 3: helpers keep their names and skip-net exemption is untouched;
    # the decoration lives inside the helper bodies (nothing else renamed).
    print("gate 3: helper names/counts unchanged in both IRs")
    for ir_text, label in ((l3_ir, "L3"), (l1_ir, "L1")):
      for name in HELPERS:
        gate(len(re.findall(rf"@{re.escape(name)}\b", ir_text)) >= 2,
             f"{label}: {name} still referenced + defined by name")

    # Gate 4: -O2 survival of the markers (IR emitted with
    # -fno-discard-value-names so block labels stay greppable).
    print("gate 4: L3 -O2 IR marker survival")
    l3_o2_ir = emit_ir(src, tmp / "l3-O2.ll", l3_cfg, "-O2")
    for name in HELPERS:
      body = helper_body(l3_o2_ir, name)
      gate(bool(body), f"-O2: {name} defined")
      gate(f"{name}.ic.tok" in l3_o2_ir, f"-O2: {name}.ic.tok survives")
      gate(f"{name}.ic.junk" in body or f"{name}.ic.junk" in l3_o2_ir,
           f"-O2: {name}.ic.junk survives")
      gate(fake_edges(body) >= 1, f"-O2: {name} fake call edge survives")

    # Gate 5: runtime parity byte-exact at -O2 for L3 (fortress tier) and
    # L1+reencrypt (scrub path), plus the leak_bar-style byte scan proving
    # decryptor+scrub still protect end to end.
    print("gate 5: runtime parity + binary leak scan at -O2")
    for cfg, label in ((l3_cfg, "L3"), (l1_cfg, "L1+reencrypt")):
      exe = tmp / f"{label}-obf.exe"
      compile_exe(src, exe, cfg, "-O2")
      exe_run = run([str(exe)])
      must(exe_run, f"{label} obf run")
      gate(exe_run.stdout == plain_run.stdout,
           f"{label}: stdout byte-exact vs plain")
      leaked = [s for s in SECRETS
                if any(form in exe.read_bytes() for form in encodings(s))]
      gate(not leaked, f"{label}: secrets absent from binary (leaked={leaked})")

    print("cse helper fortification verifier: ok")
    return 0
  finally:
    if args.keep:
      print(f"kept temp dir: {tmp}")
    else:
      shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
