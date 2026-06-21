// VMP benchmark harness (L1.5.4).
//
// Measures interpreter overhead vs native for each L1.5 IR feature. Compiled
// twice by verify_vmp_benchmark.py: plain NATIVE and +vmp. Each binary runs
// the same workload (tight loop over each case function) and prints
// per-case wall-clock nanoseconds. The driver compares the two streams and
// reports the vmp/native overhead ratio.
//
// The case functions mirror the differential harness but are kept tight and
// looped so timing noise is dominated by the actual work, not call overhead.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef VMP_CASE_ATTRS
#define VMP_CASE_ATTRS __attribute__((noinline))
#endif

#define VMP_CASE(name, body) \
  static int VMP_CASE_ATTRS name(int a, int b) body

VMP_CASE(add_case,    { return a + b; })
VMP_CASE(sub_case,    { return a - b; })
VMP_CASE(xor_case,    { return (a ^ b) ^ 17; })
VMP_CASE(mul_case,    { return a * b; })
VMP_CASE(div_case,    { return b != 0 ? a / b : 0; })
VMP_CASE(branch_case, {
  int x = (a + b) ^ 5;
  if (x > 40) return x - b;
  return x + a;
})
VMP_CASE(loop_sum_case, {
  int n = a & 0xFF;
  int s = 0;
  for (int i = 0; i < n; ++i) s += i;
  return s;
})

// clock() on Windows ticks at 1ms; 50M iterations keeps each case in the
// tens-of-ms range so the 1ms quantization is a small fraction of the total.
#define ITERS 50000000

// volatile sink so the optimizer cannot delete the calls.
static volatile int g_sink;

// Each iteration varies the inputs by the loop index so the optimizer
// cannot hoist the entire body out of the loop (the result genuinely
// depends on i, defeating constant-folding and CSE).
#define BENCH(name, a, b)                                        \
  do {                                                           \
    clock_t t0 = clock();                                        \
    int acc = 0;                                                 \
    for (int i = 0; i < ITERS; ++i)                             \
      acc += name((a) ^ i, (b) + (i & 0x3));                    \
    clock_t t1 = clock();                                        \
    long long ns = (long long)((t1 - t0) *                      \
                   (1000000000LL / CLOCKS_PER_SEC));             \
    g_sink = acc;                                                \
    printf(#name ":%lld:%d\n", ns, ITERS);                       \
  } while (0)

int main(int argc, char **argv) {
  // Read a/b from argv so the optimizer cannot fold the loop bodies away.
  // Default values keep the harness runnable without args.
  int a = argc > 1 ? (int)strtol(argv[1], 0, 10) : 12345;
  int b = argc > 2 ? (int)strtol(argv[2], 0, 10) : 678;
  BENCH(add_case, a, b);
  BENCH(sub_case, a, b);
  BENCH(xor_case, a, b);
  BENCH(mul_case, a, b);
  BENCH(div_case, a, b);
  BENCH(branch_case, a, b);
  BENCH(loop_sum_case, a, b);
  return 0;
}
