#include <cstdio>

template <typename T>
__declspec(noinline) T bump_twice(T x) {
  return x * 2 + 1;
}

static __declspec(noinline) int plus7(int x) {
  return x + 7;
}

static __declspec(noinline) int times3(int x) {
  return x * 3;
}

using Fn = int (*)(int);

static __declspec(noinline) int apply(Fn fn, int x) {
  return fn(x);
}

struct Base {
  virtual int calc(int x) const = 0;
  virtual ~Base() = default;
};

struct Derived : Base {
  int calc(int x) const override { return x + 11; }
};

static __declspec(noinline) int direct_bridge(int x) {
  return plus7(x) + times3(x);
}

int main() {
  Derived d;
  int total = apply(plus7, 5) + apply(times3, 4) + d.calc(10) +
              bump_twice<int>(6) + direct_bridge(2);
  std::printf("indirect-calls:%d\n", total);
  return 0;
}
