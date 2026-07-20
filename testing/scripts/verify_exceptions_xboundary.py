"""Verify exception unwinding across obfuscated/unobfuscated TU boundaries.

The single-TU exception fixtures (exceptions_raii etc.) obfuscate the whole
program at once, so every frame on the unwind path shares the same transform.
This verifier compiles a THROWER TU and a CATCHER TU separately and links them
in mixed configurations, exercising the boundaries that single-TU tests miss:

  1. obfuscated thrower -> plain catcher (throw originates in an obfuscated,
     possibly flattened frame; unwound into a plain frame).
  2. plain thrower -> obfuscated catcher (catch/landingpad lives inside an
     obfuscated frame).
  3. plain thrower -> obfuscated middle (flattened) -> plain catcher: the
     exception passes THROUGH a flattened dispatcher frame that itself has no
     try/catch, proving the flattening pass preserves the unwind tables for
     frames the personality must skip.

Linux/Itanium uses LSDA + personality-function tables (not Windows funclets),
so this is the fragile path for control-flow flattening: if the dispatcher
frame loses or rewrites its landing-pad / unwind edges, unwinding aborts.

Contract: every configuration's stdout + exit code matches the all-plain
baseline. Any mismatch is a real compatibility defect.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG

THROWER = r"""
#include <stdexcept>
#include <cstdint>

extern void log_throw(int code);

__attribute__((noinline)) int deep_throws(int code) {
  log_throw(code);
  if (code < 0) throw std::runtime_error("neg");
  if (code == 0) throw std::logic_error("zero");
  if (code == 7) throw 7;
  return code * 13 + 1;
}

int call_deep_throws(int code) { return deep_throws(code); }
"""

MIDDLE = r"""
#include <cstdint>

extern int call_deep_throws(int code);

__attribute__((noinline)) int passthrough(int n) {
  int acc = 0;
  for (int i = 1; i <= n; ++i) acc += call_deep_throws(i);
  return acc;
}
"""

CATCHER = r"""
#include <cstdio>
#include <exception>
#include <stdexcept>

extern int passthrough(int n);
extern int deep_throws(int code);

static void emit(const char *tag, int v) { std::printf("%s:%d\n", tag, v); }

__attribute__((noinline)) void log_throw(int code) {
  static int seq = 0;
  std::printf("throw-seq:%d:%d\n", seq++, code);
}

int main() {
  int acc = 0;
  const int cases[] = {5, -1, 0, 7, 4};
  for (int c : cases) {
    try {
      int r = deep_throws(c);
      acc += r;
      emit("ret", r);
    } catch (const std::logic_error &) {
      acc += 200;
      emit("caught-logic", c);
    } catch (const std::runtime_error &) {
      acc += 300;
      emit("caught-runtime", c);
    } catch (...) {
      acc += 400;
      emit("caught-any", c);
    }
  }
  try {
    int p = passthrough(3);
    acc += p;
    emit("pass", p);
  } catch (const std::exception &e) {
    acc += 500;
    emit("caught-pass", -1);
  }
  std::printf("xbound-acc:%d\n", acc);
  return 0;
}
"""

OBF = ["-mllvm", "-taokari",
       "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
       "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=2",
       "-mllvm", "-taokari-icall", "-mllvm", "-taokari-level-icall=3"]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return tp.run(cmd)


def build_and_run(tmp: Path, obf_thrower: bool, obf_middle: bool,
                  obf_catcher: bool) -> tuple[int, str, str]:
    thrower_src = tmp / "thrower.cpp"
    middle_src = tmp / "middle.cpp"
    catcher_src = "catcher.cpp"
    (tmp / catcher_src).write_text(CATCHER, encoding="utf-8")
    thrower_src.write_text(THROWER, encoding="utf-8")
    middle_src.write_text(MIDDLE, encoding="utf-8")

    def flags(obf: bool) -> list[str]:
        return (["-O2", "-std=c++17", "-fcxx-exceptions"] +
                (OBF if obf else []))

    objs: list[str] = []
    for name, src, obf in (("th", thrower_src, obf_thrower),
                           ("mid", middle_src, obf_middle),
                           ("ct", tmp / catcher_src, obf_catcher)):
        out = str(tmp / f"{name}.o")
        r = run([str(CLANG), "-c", str(src), *flags(obf), "-o", out])
        if r.returncode:
            raise RuntimeError(f"compile {name} (obf={obf})\n{r.stdout}{r.stderr}")
        objs.append(out)

    exe = str(tmp / ("xbound_th" + str(int(obf_thrower)) +
                     "mid" + str(int(obf_middle)) +
                     "ct" + str(int(obf_catcher))))
    link = tp.CLANG.with_name(tp.CLANG.name.replace("clang", "clang++")) \
        if tp.CLANG.name.replace("clang", "clang++") != tp.CLANG.name else tp.CLANG
    r = run([str(link), *objs, "-o", exe])
    if r.returncode:
        raise RuntimeError(f"link\n{r.stdout}{r.stderr}")
    ran = run([exe])
    return ran.returncode, ran.stdout, ran.stderr


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    configs = [
        ("plain-plain-plain", False, False, False),
        ("obf-thrower", True, False, False),
        ("obf-catcher", False, False, True),
        ("obf-thrower+catcher", True, False, True),
        ("obf-middle-passthrough", False, True, False),
        ("obf-all-three", True, True, True),
    ]
    with tempfile.TemporaryDirectory(prefix="taokari-xbound-") as tmp_name:
        tmp = Path(tmp_name)
        baseline_rc, baseline_out, baseline_err = build_and_run(
            tmp, False, False, False)
        if baseline_rc:
            print(f"baseline failed rc={baseline_rc}\n{baseline_out}{baseline_err}",
                  file=sys.stderr)
            return 1
        failures = 0
        for name, ot, om, oc in configs[1:]:
            try:
                rc, out, err = build_and_run(tmp, ot, om, oc)
            except RuntimeError as exc:
                print(f"FAIL  {name}: {exc}", file=sys.stderr)
                failures += 1
                continue
            if rc != baseline_rc or out != baseline_out:
                print(f"FAIL  {name}: rc={rc} (base {baseline_rc}) "
                      f"stdout={out!r}\n       base={baseline_out!r}",
                      file=sys.stderr)
                failures += 1
            else:
                print(f"ok    {name}: matches baseline")
    if failures:
        print(f"exceptions-xboundary: {failures} config(s) failed", file=sys.stderr)
        return 1
    print("exceptions-xboundary: ok (all mixed-TU unwind paths match baseline)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
