// MBA stress fixture.
// Exercises every Level-1 Mixed Boolean Arithmetic identity across integer
// widths and a small control-flow mix so MBA output also feeds flattening,
// bogus-control-flow and indirect-branch passes. Output is fully deterministic
// and independent of optimization level.
#include <stdint.h>
#include <stdio.h>

static __declspec(noinline) int32_t mix32(int32_t x, int32_t y) {
  int32_t a = x + y;
  int32_t b = x - y;
  int32_t c = a ^ b;
  int32_t d = a & b;
  int32_t e = a | b;
  return c + d + e;
}

static __declspec(noinline) int64_t mix64(int64_t x, int64_t y) {
  int64_t a = x + y;
  int64_t b = x - y;
  int64_t c = a ^ b;
  int64_t d = a & b;
  int64_t e = a | b;
  return c + d + e;
}

static __declspec(noinline) int32_t chained(int32_t seed) {
  // Long addition chain so MBA substitutions stack across a basic block.
  int32_t v = seed;
  v = v + 3;
  v = v + 7;
  v = v + 11;
  v = v - 5;
  v = v ^ 0x55;
  v = v & 0xFF;
  v = v | 0x10;
  return v;
}

int main(void) {
  int32_t  m32 = mix32(1234, 567);
  int64_t  m64 = mix64(999983LL, 1000003LL);
  int32_t  ch  = chained(2024);
  printf("mba-basic:%lld:%lld:%d\n", (long long)m32, (long long)m64, ch);
  return 0;
}
