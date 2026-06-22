from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "taokari-local"
CLANG_CL = BUILD / "bin" / "clang-cl.exe"
LLVM_CONFIG = BUILD / "bin" / "llvm-config.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)


SOURCE = r'''
#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <cstdio>
#include <random>

using namespace llvm;

static int fail(const char *Message) {
  std::fputs(Message, stderr);
  std::fputc('\n', stderr);
  return 1;
}

static int checkWidth(LLVMContext &Ctx, IRBuilder<> &IRB, unsigned Bits) {
  IntegerType *Ty = IntegerType::get(Ctx, Bits);
  const uint64_t Samples[] = {0, 1, 2, 3, 5, 17, 0x55, 0xaa, ~0ull};

  for (uint64_t Sample : Samples) {
    for (uint64_t Seed = 1; Seed != 64; ++Seed) {
      std::mt19937_64 TrueRNG(Seed);
      auto *True = dyn_cast<ConstantInt>(taokari::makeTruePredicate(
          IRB, ConstantInt::get(Ty, Sample), TrueRNG, "true"));
      if (!True || !True->isOne())
        return fail("true predicate folded incorrectly");

      std::mt19937_64 FalseRNG(Seed);
      auto *False = dyn_cast<ConstantInt>(taokari::makeFalsePredicate(
          IRB, ConstantInt::get(Ty, Sample), FalseRNG, "false"));
      if (!False || !False->isZero())
        return fail("false predicate folded incorrectly");
    }
  }
  return 0;
}

int main() {
  LLVMContext Ctx;
  Module M("opaque-predicate-test", Ctx);
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(Ctx), false), GlobalValue::ExternalLinkage,
      "f", M);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
  IRBuilder<> IRB(BB);

  for (unsigned Bits : {1u, 8u, 16u, 32u, 64u})
    if (int Failed = checkWidth(Ctx, IRB, Bits))
      return Failed;

  std::mt19937_64 RNG(7);
  auto *Ty = Type::getInt32Ty(Ctx);
  auto *Seed = dyn_cast<LoadInst>(
      taokari::makeOpaquePredicateSeed(*F, IRB, Ty, RNG, "seed"));
  if (!Seed || Seed->getType() != Ty || !Seed->isVolatile())
    return fail("function seed is not a volatile i32 load");
  auto *GV = dyn_cast<GlobalVariable>(Seed->getPointerOperand());
  if (!GV || !GV->isConstant() || !GV->hasPrivateLinkage())
    return fail("function seed backing global is wrong");

  std::puts("opaque predicates: ok");
  return 0;
}
'''


def words(text: str) -> list[str]:
  return [part for part in text.replace("\n", " ").split(" ") if part]


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def run_vs(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
  with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
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


def main() -> int:
  if not CLANG_CL.exists():
    print(f"missing clang-cl: {CLANG_CL}", file=sys.stderr)
    return 2
  if not LLVM_CONFIG.exists():
    print(f"missing llvm-config: {LLVM_CONFIG}", file=sys.stderr)
    return 2

  opq_source = (
      ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" /
      "Obfuscation" / "OpaquePredicate.cpp"
  ).read_text(encoding="utf-8", errors="ignore")
  if ("makeNeighborProductLowBit" not in opq_source or
      "RNG() % 3" not in opq_source):
    print("missing L1 opaque predicate family variety", file=sys.stderr)
    return 1
  if ("Salt->getLimitedValue() % 3" not in opq_source or
      "even.sub" not in opq_source or
      "even.xor" not in opq_source):
    print("missing makeEvenLowBit shape variety", file=sys.stderr)
    return 1

  include_dir = run([str(LLVM_CONFIG), "--includedir"]).stdout.strip()
  libs = words(run([str(LLVM_CONFIG), "--libs", "core", "support", "obfuscation"]).stdout)
  system_libs = [
      lib for lib in words(run([str(LLVM_CONFIG), "--system-libs"]).stdout)
      if lib.lower() not in {"zlib.lib", "xml2.lib"}
  ]

  with tempfile.TemporaryDirectory(prefix="taokari-opaque-") as tmp_name:
    tmp = Path(tmp_name)
    source = tmp / "opaque_predicate_unit.cpp"
    exe = tmp / "opaque_predicate_unit.exe"
    source.write_text(SOURCE, encoding="utf-8")

    command = [
        str(CLANG_CL),
        "/nologo",
        "/std:c++17",
        "/EHsc",
        "/GR-",
        "/MT",
        f"/I{BUILD / 'include'}",
        f"/I{include_dir}",
        f"/I{ROOT / 'upstream' / 'taokari' / 'llvm' / 'include'}",
        str(source),
        *libs,
        *system_libs,
        f"/Fe:{exe}",
    ]
    compiled = run_vs(command)
    if compiled.returncode:
      print(compiled.stdout, end="")
      print(compiled.stderr, end="", file=sys.stderr)
      return compiled.returncode

    checked = run([str(exe)])
    print(checked.stdout, end="")
    print(checked.stderr, end="", file=sys.stderr)
    return checked.returncode


if __name__ == "__main__":
  raise SystemExit(main())
