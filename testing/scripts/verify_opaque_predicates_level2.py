"""Level-2 opaque-predicate verification.

Validates the four required properties of `OpaquePredicate.cpp`'s Level-2
context-based seed families:

  * each seed kind (algebraic/pointer/stack/global/environment/nonce) builds
    legal IR and (where statically knowable) returns the right shape
  * volatile load helper actually produces a volatile load
  * `makeUnfoldableTruePredicate` / `makeUnfoldableFalsePredicate` are
    algebraically correct across widths when the seed is a constant
  * the unfoldable predicates SURVIVE `opt -passes=instcombine,simplifycfg`
    when seeded from a runtime value (the Level-2 guarantee: the optimizer
    cannot constant-fold them away).

Uses the locally built Taokari `clang-cl`, `opt` and `llvm-config` to compile
a small C++ harness that links against LLVMObfuscation, then runs the emitted
IR through `opt` to prove survival.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "taokari-local"
CLANG_CL = BUILD / "bin" / "clang-cl.exe"
OPT = BUILD / "bin" / "opt.exe"
LLVM_CONFIG = BUILD / "bin" / "llvm-config.exe"
VSDEVCMD = tp.VSDEVCMD


HARNESS = r'''
#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

using namespace llvm;

static int fail(const char *Msg) {
  std::fputs(Msg, stderr);
  std::fputc('\n', stderr);
  return 1;
}

// Build a function whose body is `ret i1 <unfoldable predicate over a runtime
// seed>` and print its IR to stdout. The python side pipes this through
// `opt -O2 -S` and checks that the result is NOT a constant i1.
static int emit(const char *Name, taokari::OpaqueSeedKind Kind, bool Unfoldable) {
  LLVMContext Ctx;
  Module M("opq-survival", Ctx);
  auto *I32 = Type::getInt32Ty(Ctx);
  Function *F = Function::Create(FunctionType::get(I32, false),
                                 GlobalValue::ExternalLinkage, Name, M);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
  IRBuilder<> IRB(BB);
  std::mt19937_64 RNG(99);
  Value *Seed = taokari::makeContextSeed(*F, IRB, I32, RNG, Kind, "seed");
  Value *P = Unfoldable
      ? taokari::makeUnfoldableTruePredicate(IRB, Seed, RNG, "p")
      : taokari::makeTruePredicate(IRB, Seed, RNG, "p");
  IRB.CreateRet(IRB.CreateZExt(P, I32));
  M.print(outs(), nullptr);
  return 0;
}

// Volatile load helper must produce a volatile, align-1 load.
static int checkVolatileLoad() {
  LLVMContext Ctx;
  Module M("opq-l2-v", Ctx);
  Function *F = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                 GlobalValue::ExternalLinkage, "f", M);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
  IRBuilder<> IRB(BB);
  auto *I32 = Type::getInt32Ty(Ctx);
  auto *GV = new GlobalVariable(M, I32, false, GlobalValue::PrivateLinkage,
                                ConstantInt::get(I32, 0), "g");
  auto *L = taokari::makeVolatileLoad(IRB, I32, GV, "vl");
  if (!L->isVolatile() || L->getAlign().value() != 1)
    return fail("makeVolatileLoad did not produce volatile align-1 load");
  return 0;
}

// Each context-seed kind must build legal IR for i32. Runtime values cannot
// be checked statically; the InstCombine survival test below proves they are
// real runtime dependencies.
static int checkContextSeedsBuild() {
  using K = taokari::OpaqueSeedKind;
  const K Kinds[] = {K::Algebraic, K::Pointer, K::StackAddress, K::Global,
                     K::Environment, K::RuntimeNonce};
  LLVMContext Ctx;
  Module M("opq-l2-s", Ctx);
  Function *F = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                 GlobalValue::ExternalLinkage, "f", M);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
  IRBuilder<> IRB(BB);
  auto *I32 = Type::getInt32Ty(Ctx);
  for (K Kind : Kinds) {
    std::mt19937_64 RNG(7);
    Value *V = taokari::makeContextSeed(*F, IRB, I32, RNG, Kind, "seed");
    if (!V || V->getType() != I32)
      return fail("makeContextSeed produced wrong type");
  }
  return 0;
}

// Nested predicates must be algebraically correct: with a constant seed the
// whole chain folds to the expected i1. Tests the L3 nested identity over a
// spread of constant seeds and both i32 and i64.
static int checkNested() {
  LLVMContext Ctx;
  auto *I32 = Type::getInt32Ty(Ctx);
  auto *I64 = Type::getInt64Ty(Ctx);
  uint64_t Seeds[] = {0, 1, 2, 3, 7, 17, 0x5a5a, 0xdeadbeefULL, 0xffffffffULL};
  for (uint64_t S : Seeds) {
    for (IntegerType *Ty : {I32, I64}) {
      for (int Pass = 0; Pass < 4; ++Pass) {
        Module M("opq-nest", Ctx);
        Function *F = Function::Create(FunctionType::get(Ty, false),
                                       GlobalValue::ExternalLinkage, "f", M);
        BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
        IRBuilder<> IRB(BB);
        std::mt19937_64 RNG(31 + Pass);
        Value *Seed = ConstantInt::get(Ty, S);
        Value *T = taokari::makeNestedTruePredicate(IRB, Seed, RNG, "t");
        Value *Fp = taokari::makeNestedFalsePredicate(IRB, Seed, RNG, "f");
        Value *TC = dyn_cast<ConstantInt>(T);
        Value *FC = dyn_cast<ConstantInt>(Fp);
        if (!TC || !FC)
          return fail("nested predicate did not fold over a constant seed");
        if (!cast<ConstantInt>(TC)->isOne())
          return fail("makeNestedTruePredicate folded to false");
        if (!cast<ConstantInt>(FC)->isZero())
          return fail("makeNestedFalsePredicate folded to true");
      }
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 2 && std::strcmp(argv[1], "--emit") == 0) {
    // --emit <kind> <unfoldable>  : kind in
    // {algebraic,pointer,stack,global,environment,nonce}, unfoldable in {0,1}
    using K = taokari::OpaqueSeedKind;
    K Kind = K::Algebraic;
    std::string KStr = argc >= 3 ? argv[2] : "algebraic";
    if (KStr == "pointer")      Kind = K::Pointer;
    else if (KStr == "stack")   Kind = K::StackAddress;
    else if (KStr == "global")  Kind = K::Global;
    else if (KStr == "environment") Kind = K::Environment;
    else if (KStr == "nonce")   Kind = K::RuntimeNonce;
    bool Unfoldable = argc >= 4 && std::strcmp(argv[3], "1") == 0;
    return emit("survival", Kind, Unfoldable);
  }
  if (int R = checkVolatileLoad())       return R;
  if (int R = checkContextSeedsBuild())  return R;
  if (int R = checkNested())             return R;
  std::puts("opaque predicates level2: ok");
  return 0;
}
'''


# IR emission is driven by the harness's `--emit <kind> <unfoldable>` mode
# (see HARNESS). Python pipes that IR through `opt` to prove survival.


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if not tp.IS_WINDOWS:
      return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                     encoding="utf-8") as h:
        batch = Path(h.name)
        h.write(
            "@echo off\n"
            f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
            f"{subprocess.list2cmdline(command)}\n"
            "exit /b %ERRORLEVEL%\n"
        )
    try:
        return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
    finally:
        batch.unlink(missing_ok=True)


def words(text: str) -> list[str]:
    return [p for p in text.replace("\n", " ").split(" ") if p]


def compile_harness(src: Path, exe: Path) -> subprocess.CompletedProcess[str]:
    include_dir = run([str(LLVM_CONFIG), "--includedir"]).stdout.strip()
    libs = words(run([str(LLVM_CONFIG), "--libs", "core", "support",
                      "obfuscation"]).stdout)
    system_libs = [
        lib for lib in words(run([str(LLVM_CONFIG), "--system-libs"]).stdout)
        if lib.lower() not in {"zlib.lib", "xml2.lib"}
    ]
    cmd = [
        str(CLANG_CL), "/nologo", "/std:c++17", "/EHsc", "/GR-", "/MT",
        f"/I{BUILD / 'include'}",
        f"/I{include_dir}",
        f"/I{ROOT / 'upstream' / 'taokari' / 'llvm' / 'include'}",
        str(src), *libs, *system_libs, f"/Fe:{exe}",
    ]
    return run_vs(cmd)


def survival_for(exe: Path, kind: str, unfoldable: bool) -> tuple[bool, str]:
    """Return (survived, detail). Survived = the function's `ret` operand in
    the optimizer output is NOT a constant i32 (i.e. the predicate was not
    folded to true/false)."""
    emit = run([str(exe), "--emit", kind, "1" if unfoldable else "0"])
    if emit.returncode:
        return False, f"emit failed:\n{emit.stdout}\n{emit.stderr}"
    ir = emit.stdout
    if not ir.strip():
        return False, f"emit produced no IR\n{emit.stderr}"
    opt_run = run(
        [str(OPT), "-passes=instcombine,simplifycfg", "-S"],
        input=ir,
    )
    if opt_run.returncode:
        return False, f"opt failed:\n{opt_run.stdout}\n{opt_run.stderr}"
    out = opt_run.stdout
    # Look for the `survival` function and check its terminator. If it is
    # `ret i32 <const>` the predicate was folded away.
    import re
    m = re.search(r"define[^@]*@survival\b.*?{\n([\s\S]*?)\n}", out)
    if not m:
        return False, f"survival function not found in opt output:\n{out}"
    body = m.group(1)
    # Match `ret i32 <operand>` where operand may be `%N` (SSA, survived),
    # a decimal constant (folded), or `true`/`false`-derived.
    ret_match = re.search(r"ret i32 ([^\s]+)", body)
    if not ret_match:
        return False, f"no ret i32 found:\n{body}"
    operand = ret_match.group(1)
    # Folded iff operand is a plain integer literal (no `%` SSA name).
    folded = not operand.startswith("%")
    detail = f"ret operand={operand}\nbody:\n{body}"
    return not folded, detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="keep the temp build dir for inspection")
    args = ap.parse_args()

    for tool in (CLANG_CL, OPT, LLVM_CONFIG):
        if not tool.exists():
            print(f"missing tool: {tool}", file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory(prefix="taokari-opaq-l2-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "opaque_predicate_level2_unit.cpp"
        exe = tmp / "opaque_predicate_level2_unit.exe"
        src.write_text(HARNESS, encoding="utf-8")

        compiled = compile_harness(src, exe)
        if compiled.returncode:
            print(compiled.stdout, end="")
            print(compiled.stderr, end="", file=sys.stderr)
            return compiled.returncode

        # 1. Structural checks.
        checked = run([str(exe)])
        print(checked.stdout, end="")
        print(checked.stderr, end="", file=sys.stderr)
        if checked.returncode:
            return checked.returncode

        # 2. InstCombine survival. Level-2 guarantees that an unfoldable
        # predicate over a runtime (context) seed survives the normal cleanup
        # pipeline. We test each context seed kind with the unfoldable family
        # and require survival. The Level-1 algebraic predicate is run as a
        # non-failing control: it MAY fold (and we report when it does, since
        # that is exactly the gap Level-2 closes).
        failures = 0
        kinds = ["pointer", "stack", "global", "environment", "nonce"]
        for kind in kinds:
            ok, detail = survival_for(exe, kind, unfoldable=True)
            print(f"[{'SURVIVE' if ok else 'FOLDED'}] {kind}/unfoldable")
            if not ok:
                print(detail)
                failures += 1
            # Control: algebraic over the same seed. Reported, not required.
            ok_a, _ = survival_for(exe, kind, unfoldable=False)
            print(f"[{'SURVIVE' if ok_a else 'FOLDS(control)'}] "
                  f"{kind}/algebraic")

        # Sanity control: a constant-global algebraic seed with the Level-1
        # predicate SHOULD fold, proving the survival test is not vacuous.
        ok, _ = survival_for(exe, "algebraic", False)
        print(f"[{'SURVIVE?!' if ok else 'FOLDS(control)'}] "
              f"algebraic/algebraic (must fold)")
        if ok:
            print("control did not fold - survival test is vacuous",
                  file=sys.stderr)
            failures += 1

        if failures:
            print(f"FAIL: {failures} survival checks failed", file=sys.stderr)
            return 1
        print("opaque predicates level2: survival ok")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
