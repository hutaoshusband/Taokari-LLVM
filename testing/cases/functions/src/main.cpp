// Functions & parameter passing fixture.
// Exercises value, reference and pointer parameters; varying return types
// (int, double, struct); inline functions; function pointers; std::function;
// lambdas (with and without capture); and C-style varargs. All call sites
// turn into IndirectCall targets and the return-value paths feed
// ConstantInt/ConstantFP encryption.
//
// Target: IndirectCall on every direct and indirect call site, return-value
// preservation across struct returns, ABI of varargs.
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <functional>

struct Result {
  int code;
  int payload;
};

__declspec(noinline) int by_value(int a, int b) { return a + b; }
__declspec(noinline) int by_reference(int &a, const int &b) { return a += b; }
__declspec(noinline) int by_pointer(int *a, const int *b) { return *a += *b; }
__declspec(noinline) double fp_return(double a, double b) { return a * b + 1.5; }
__declspec(noinline) Result struct_return(int c, int p) { return {c, p * 3 + 1}; }

inline int inline_add(int a, int b) { return a + b + 7; }

using BinFn = int (*)(int, int);

__declspec(noinline) int via_fn_ptr(BinFn fn, int a, int b) { return fn(a, b); }

__declspec(noinline) int via_stdfunction(std::function<int(int)> fn, int x) {
  return fn(x) + fn(x + 1);
}

__declspec(noinline) int varargs_sum(int count, ...) {
  va_list args;
  va_start(args, count);
  int total = 0;
  for (int i = 0; i < count; ++i) total += va_arg(args, int);
  va_end(args);
  return total;
}

int main() {
  int v = 10;
  const int fixed = 9;
  int r1 = by_value(v, 5);             // 15
  int r2 = by_reference(v, 4);         // v = 14, returns 14
  int r3 = by_pointer(&v, &fixed);     // v = 23, returns 23
  double r4 = fp_return(2.0, 3.0);     // 7.5
  Result res = struct_return(7, 5);    // {7, 16}
  int r5 = inline_add(r1, r2);         // 15 + 14 + 7 = 36

  int r6 = via_fn_ptr(by_value, 100, 11);  // 111
  int r7 = via_stdfunction([](int x) { return x * x; }, 3);  // 9 + 16 = 25

  int captured = 100;
  int r8 = [captured](int x) { return captured + x; }(5);    // 105

  int r9 = varargs_sum(5, 1, 2, 3, 4, 5);  // 15

  std::printf("functions:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d\n",
              r1, r2, r3, v, r5, r6, r7, r8, r9, res.code, res.payload);
  (void)r4;
  return 0;
}
