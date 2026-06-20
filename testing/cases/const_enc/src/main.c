// Constant encryption stress fixture.
// Exercises ConstantIntEncryption and ConstantFPEncryption across the value
// types and widths that are most exposed to optimizer constant folding:
//   * 8/16/32/64-bit integer constants
//   * float / double constants
//   * constants used as switch cases and phi incoming values
//   * constants used as call arguments (printf format width tag)
// Output is fully deterministic and independent of optimization level.
#include <stdint.h>
#include <stdio.h>

static __declspec(noinline) int64_t int_mix(void) {
  int64_t a = 0x01020304;          // 32-bit width tag
  int64_t b = 0x0000000A;          // small but >= 8 bits
  int64_t c = a * b + 7;           // 0x01020304 * 10 + 7
  int16_t s = 300;                 // 16-bit
  return (c << 1) ^ (int64_t)s;    // mixes widths via casts
}

static __declspec(noinline) double fp_mix(void) {
  double g = 1.41421356237;
  float  f = 2.7182818f;
  return g * (double)f + 0.5;      // 1.41421356237 * 2.7182818 + 0.5
}

static __declspec(noinline) int switch_dispatch(int x) {
  switch (x) {
    case 100: return 1;
    case 200: return 2;
    case 300: return 3;
    case 400: return 4;
    default:  return 0;
  }
}

int main(void) {
  int64_t i = int_mix();
  double  d = fp_mix();
  int     s = switch_dispatch(300);
  // 0x01020304 * 10 + 7 = 16909331, << 1 = 33818662, ^ 300 = 33818930 (300 = 0x12C, low bits)
  printf("const:%lld:%.4f:%d\n", (long long)i, d, s);
  return 0;
}
