#include <cstdint>
#include <cstdio>

// recursion + int math -> ConstantIntEncryption, Flattening, IndirectBranch
static uint64_t fact(int n) {
  if (n <= 1) return 1;
  return static_cast<uint64_t>(n) * fact(n - 1);
}

// FP math -> ConstantFPEncryption
static double newton_sqrt(double x) {
  if (x <= 0.0) return 0.0;
  double g = x * 0.5;
  for (int i = 0; i < 20; ++i) {
    g = 0.5 * (g + x / g);
  }
  return g;
}

// struct holding function pointer -> IndirectGlobalVariable, IndirectCall
struct Op {
  int id;
  int (*apply)(int, int);
};

static int add(int a, int b) { return a + b; }
static int mul(int a, int b) { return a * b; }

int main() {
  Op ops[] = {{1, add}, {2, mul}};
  uint64_t f = fact(10);        // 3628800
  double s = newton_sqrt(2.0);  // ~1.41421356
  int acc = 0;
  for (const Op &op : ops) {
    acc += op.apply(op.id, 100);  // add(1,100) + mul(2,100) = 301
  }
  std::printf("mixed:%llu:%.4f:%d\n", static_cast<unsigned long long>(f), s, acc);
  return 0;
}
