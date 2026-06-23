// Section 22 Phase 3 demo target (Tier C "spear" reference).
//
// This file is the canonical annotated source for the Max Protection /
// Tier C recipe. It enumerates the demo's sensitive function (vm_one,
// the proprietary-algorithm stand-in) with +vmp, and explicitly marks
// CRT/main/wrapper functions with -vmp so the Phase 1 cap-fallthrough
// never virtualizes them by accident.
//
// Run with:  build_max_protection.bat testing\cases\max_protection_demo\src\main.c
// Verified by: testing/scripts/verify_tier_recipe.py (Tier C/D)

#include <stdio.h>

// Sensitive function: the proprietary-algorithm core. +vmp + noinline so
// it becomes per-function VM bytecode and is not inlined into a caller.
#define VMP __attribute__((noinline, annotate("+vmp")))
// CRT/main/wrapper: never virtualize (fast path, loader-sensitive).
#define NO_VMP __attribute__((annotate("-vmp")))

// Canonical sensitive function. Phase 3 record (verify_tier_recipe.py C):
//   native IR insts ~= 25, bytecode words = 200, back-edges = 0
// All under the Phase 1 caps (back-edges=64, expansion=32, words=2048).
VMP int vm_one(int x) {
  int acc = (x * 17) ^ 0x5a5a;
  for (int i = 0; i < (x & 7); ++i) {
    acc = (acc + i) ^ (acc >> 3);
    if (acc & 1) acc += 9;
  }
  return acc + 9;
}

// A non-sensitive helper: left unannotated so it gets the blanket (fla,
// bcf, mba, ...) but never VMP. Demonstrates the split between blanket
// and spear.
int compute(int a, int b) {
  int z = ((a + b) ^ (a * b)) + 41;
  return z > 100 ? z - a : z + b;
}

NO_VMP int main(void) {
  printf("max-protection:%d:%d\n", vm_one(13), compute(7, 11));
  return 0;
}
