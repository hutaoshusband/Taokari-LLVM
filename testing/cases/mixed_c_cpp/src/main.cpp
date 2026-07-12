#include <cstdint>
#include <cstdio>

extern "C" {
int32_t core_accumulate(const int32_t *data, int32_t n, int32_t scale);
int32_t core_reduce(int32_t x, int32_t mask);
}

struct Aggregator {
  int32_t bias;
  explicit Aggregator(int32_t b) : bias(b) {}
  int32_t sum_with_bias(const int32_t *data, int32_t n, int32_t scale) {
    return core_accumulate(data, n, scale) + bias;
  }
};

template <typename T>
T clamped(T v, T lo, T hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

int main() {
  static const int32_t data[5] = {1, 2, 3, 4, 5};
  Aggregator agg(100);
  int32_t acc = agg.sum_with_bias(data, 5, 3);
  int32_t red = core_reduce(42, 0x55);
  int32_t cl = clamped(red, 0, 1000);
  printf("mixedcc:%d:%d:%d\n", acc, red, cl);
  return 0;
}
