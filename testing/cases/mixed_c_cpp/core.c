#include <stdint.h>

int32_t core_accumulate(const int32_t *data, int32_t n, int32_t scale) {
  int32_t s = 0;
  for (int32_t i = 0; i < n; ++i)
    s += data[i] * (scale + i);
  return s;
}

int32_t core_reduce(int32_t x, int32_t mask) {
  int32_t r = x ^ mask;
  r = (r * 13) - (x & 0x1F);
  return r;
}
