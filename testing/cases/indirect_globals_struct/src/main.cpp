// Indirect global variables — extended fixture.
// Exercises IndirectGlobalVariable on:
//   * a large struct global (multiple fields, mixed types)
//   * an array global (index-bearing access)
//   * a C++ static local (per-function static initialised once)
//   * a const struct global
// Output is deterministic and independent of optimization level. Stresses
// the page-table indirection across a wider range of global shapes than
// the basic c_globals fixture.
#include <cstdint>
#include <cstdio>

struct Point {
  int x;
  int y;
  int64_t tag;
  int weights[4];
};

// Large mutable struct global.
Point g_point = {10, 20, 0xABCDEF1234567890LL, {1, 2, 3, 4}};

// Const struct global (read-only after init).
const Point g_origin = {0, 0, 0, {0, 0, 0, 0}};

// Array global indexed at runtime.
int g_grid[8] = {0, 1, 2, 3, 4, 5, 6, 7};

__declspec(noinline) int sum_grid(int n) {
  int acc = 0;
  for (int i = 0; i < n && i < 8; ++i)
    acc += g_grid[i];
  return acc;
}

__declspec(noinline) int64_t move_point(int dx, int dy) {
  g_point.x += dx;
  g_point.y += dy;
  g_point.tag ^= (static_cast<int64_t>(dx) << 32) | dy;
  return g_point.tag;
}

__declspec(noinline) int next_static_local() {
  // C++ static local: initialised once, persists across calls.
  static int s_counter = 100;
  return ++s_counter;
}

int main() {
  int s = sum_grid(5);              // 0+1+2+3+4 = 10
  int64_t t = move_point(3, 4);     // tag XOR (3<<32)|4
  int a = next_static_local();      // 101
  int b = next_static_local();      // 102
  int c = next_static_local();      // 103
  int origin_x = g_origin.x;        // 0
  std::printf("indgv-struct:%d:%lld:%d:%d:%d:%d\n", s,
              static_cast<long long>(t), a, b, c, origin_x);
  return 0;
}
