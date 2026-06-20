// VMP differential correctness harness (L1.5.3).
//
// One case function per IR feature currently supported by the VM. The
// harness is compiled twice by verify_vmp_differential.py:
//   * NATIVE build  -- VMP_ATTR is empty, case fns compile to plain native
//                      code. This is the reference oracle.
//   * VMP build     -- VMP_ATTR expands to __annotate__("+vmp"), so the case
//                      fns are virtualized. Their output must match NATIVE.
//
// main() reads two integer inputs from argv and dispatches to each case,
// printing "<case>:<a>:<b>:<result>\n". The Python driver sweeps a grid of
// (a, b) pairs and diffs the two stdout streams.
//
// Constraints mirrored from CodeVirtualization.cpp::hasUnsupportedIR so the
// case fns actually qualify for virtualization: integer-only args/return
// (<=64 bits), <=8 args, no PHI/calls/allocas/loads/stores. Each case is kept
// small and self-contained.

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// VMP_CASE_ATTRS is injected via -D by the build driver:
//   * NATIVE build  -- "__attribute__((noinline))" so case fns compile to plain
//                      native code. This is the reference oracle.
//   * VMP build     -- "__attribute__((noinline, annotate(\"+vmp\")))" so the
//                      case fns are virtualized by CodeVirtualization.
#ifndef VMP_CASE_ATTRS
#define VMP_CASE_ATTRS __attribute__((noinline))
#endif

#define VMP_CASE(name, body) \
  static int VMP_CASE_ATTRS name(int a, int b) body

// --- Arithmetic: add/sub/xor (the only binary ops in L1). ---
VMP_CASE(add_case, { return a + b; })
VMP_CASE(sub_case, { return a - b; })
VMP_CASE(xor_case, { return (a ^ b) ^ 17; })

// --- L1.5.1 widened integer binary ops. ---
VMP_CASE(mul_case,  { return a * b; })
VMP_CASE(and_case,  { return (a & b) & 0xFF; })
VMP_CASE(or_case,   { return (a | b) | 0x100; })
VMP_CASE(shl_case,  { return (a & 0xF) << (b & 7); })
VMP_CASE(lshr_case, { return (int)((unsigned int)a >> (b & 7)); })
VMP_CASE(ashr_case, { return a >> (b & 7); })
VMP_CASE(sdiv_case, { return b != 0 ? a / b : 0; })
VMP_CASE(udiv_case, { return b != 0 ? (int)((unsigned int)a / (unsigned int)b) : 0; })
VMP_CASE(srem_case, { return b != 0 ? a % b : 0; })
VMP_CASE(urem_case, { return b != 0 ? (int)((unsigned int)a % (unsigned int)b) : 0; })

// --- Comparisons (signed only in L1). Result is 0/1 to keep it integer. ---
VMP_CASE(cmpeq_case,  { return (a == b); })
VMP_CASE(cmpne_case,  { return (a != b); })
VMP_CASE(cmpsgt_case, { return (a > b); })
VMP_CASE(cmpslt_case, { return (a < b); })
VMP_CASE(cmpsge_case, { return (a >= b); })
VMP_CASE(cmpsle_case, { return (a <= b); })

// --- L1.5.1 unsigned compares. ---
VMP_CASE(cmpugt_case, { return ((unsigned int)a > (unsigned int)b); })
VMP_CASE(cmpult_case, { return ((unsigned int)a < (unsigned int)b); })
VMP_CASE(cmpuge_case, { return ((unsigned int)a >= (unsigned int)b); })
VMP_CASE(cmpule_case, { return ((unsigned int)a <= (unsigned int)b); })

// --- select ---
VMP_CASE(select_case, { return (a > b) ? a + 7 : b - 3; })

// --- branch + ret (one conditional, two returns) ---
VMP_CASE(branch_case, {
  int x = (a + b) ^ 5;
  if (x > 40)
    return x - b;
  return x + a;
})

// --- combined: chained arithmetic + compare + select + branch ---
VMP_CASE(mixed_case, {
  int x = (a + b) ^ 17;
  int y = x - a;
  if (y > b) {
    return (y == x) ? x + 1 : y - 1;
  }
  return (a < b) ? a ^ b : b ^ a;
})

// --- L1.5.1 PHI lowering: loops. These are the highest-value coverage win
//     because loops are pervasive in real code and were entirely rejected
//     before PHI support. n is clamped so the loop terminates in bounded time. ---
VMP_CASE(for_sum_case, {
  int n = a & 0xFF;          // 0..255 iterations
  int sum = 0;
  for (int i = 0; i < n; ++i)
    sum = sum + i;
  return sum;
})

VMP_CASE(while_count_case, {
  int n = b & 0x7;           // 0..7 iterations
  int x = a;
  int steps = 0;
  while (x != 0 && steps < n) {
    x = x >> 1;
    ++steps;
  }
  return steps;
})

VMP_CASE(loop_carry_case, {
  // Loop-carried PHI: fib-like sequence. Bounded iterations.
  int n = a & 0xF;           // 0..15
  int prev = 0;
  int cur = 1;
  for (int i = 0; i < n; ++i) {
    int next = prev + cur;
    prev = cur;
    cur = next;
  }
  return prev;
})

VMP_CASE(nested_loop_case, {
  int rows = (a & 0x7) + 1;  // 1..8
  int cols = (b & 0x7) + 1;  // 1..8
  int total = 0;
  for (int i = 0; i < rows; ++i)
    for (int j = 0; j < cols; ++j)
      total += (i ^ j);
  return total;
})

// --- L1.5.1 VM-local memory (middle way). Only VM-local allocas; no
//     external pointer args or globals (deferred to the L2 full-pointer
//     step). volative-marker would force reloads; we use plain locals and
//     rely on -O2 keeping them address-taken so they survive as alloca. ---
VMP_CASE(local_scalar_case, {
  // volatile qualifier forces the locals to live in memory (alloca) rather
  // than registers, exercising the VM load/store path.
  volatile int x = a;
  volatile int y = b;
  x = x + y;
  y = x ^ y;
  x = x - y;
  return x + y;
})

VMP_CASE(local_array_case, {
  volatile int arr[4];
  arr[0] = a;
  arr[1] = b;
  arr[2] = a + b;
  arr[3] = a ^ b;
  // Re-read to force memory traffic (no register promotion).
  volatile int s = arr[0] + arr[1] + arr[2] + arr[3];
  return s;
})

VMP_CASE(swap_case, {
  // Classic swap via locals -- exercises store+load round-trips.
  volatile int p = a;
  volatile int q = b;
  volatile int t = p;
  p = q;
  q = t;
  return p * 1000 + q;
})

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <a> <b>\n", argv[0]);
    return 2;
  }
  int a = (int)strtol(argv[1], 0, 10);
  int b = (int)strtol(argv[2], 0, 10);

  printf("add_case:%d:%d:%d\n",     a, b, add_case(a, b));
  printf("sub_case:%d:%d:%d\n",     a, b, sub_case(a, b));
  printf("xor_case:%d:%d:%d\n",     a, b, xor_case(a, b));
  printf("mul_case:%d:%d:%d\n",     a, b, mul_case(a, b));
  printf("and_case:%d:%d:%d\n",     a, b, and_case(a, b));
  printf("or_case:%d:%d:%d\n",      a, b, or_case(a, b));
  printf("shl_case:%d:%d:%d\n",     a, b, shl_case(a, b));
  printf("lshr_case:%d:%d:%d\n",    a, b, lshr_case(a, b));
  printf("ashr_case:%d:%d:%d\n",    a, b, ashr_case(a, b));
  printf("sdiv_case:%d:%d:%d\n",    a, b, sdiv_case(a, b));
  printf("udiv_case:%d:%d:%d\n",    a, b, udiv_case(a, b));
  printf("srem_case:%d:%d:%d\n",    a, b, srem_case(a, b));
  printf("urem_case:%d:%d:%d\n",    a, b, urem_case(a, b));
  printf("cmpeq_case:%d:%d:%d\n",   a, b, cmpeq_case(a, b));
  printf("cmpne_case:%d:%d:%d\n",   a, b, cmpne_case(a, b));
  printf("cmpsgt_case:%d:%d:%d\n",  a, b, cmpsgt_case(a, b));
  printf("cmpslt_case:%d:%d:%d\n",  a, b, cmpslt_case(a, b));
  printf("cmpsge_case:%d:%d:%d\n",  a, b, cmpsge_case(a, b));
  printf("cmpsle_case:%d:%d:%d\n",  a, b, cmpsle_case(a, b));
  printf("cmpugt_case:%d:%d:%d\n",  a, b, cmpugt_case(a, b));
  printf("cmpult_case:%d:%d:%d\n",  a, b, cmpult_case(a, b));
  printf("cmpuge_case:%d:%d:%d\n",  a, b, cmpuge_case(a, b));
  printf("cmpule_case:%d:%d:%d\n",  a, b, cmpule_case(a, b));
  printf("select_case:%d:%d:%d\n",  a, b, select_case(a, b));
  printf("branch_case:%d:%d:%d\n",  a, b, branch_case(a, b));
  printf("mixed_case:%d:%d:%d\n",   a, b, mixed_case(a, b));
  printf("for_sum_case:%d:%d:%d\n", a, b, for_sum_case(a, b));
  printf("while_count_case:%d:%d:%d\n", a, b, while_count_case(a, b));
  printf("loop_carry_case:%d:%d:%d\n",  a, b, loop_carry_case(a, b));
  printf("nested_loop_case:%d:%d:%d\n", a, b, nested_loop_case(a, b));
  printf("local_scalar_case:%d:%d:%d\n", a, b, local_scalar_case(a, b));
  printf("local_array_case:%d:%d:%d\n", a, b, local_array_case(a, b));
  printf("swap_case:%d:%d:%d\n", a, b, swap_case(a, b));
  return 0;
}
