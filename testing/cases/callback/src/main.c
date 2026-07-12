#include <stdio.h>
#include <stdint.h>

typedef int (*binop)(int, int);

static int op_add(int a, int b) { return a + b; }
static int op_sub(int a, int b) { return a - b; }
static int op_mul(int a, int b) { return a * b; }
static int op_xor(int a, int b) { return a ^ b; }

static const binop table[4] = {op_add, op_sub, op_mul, op_xor};

static int apply_via_ptr(binop fn, int a, int b) {
  return fn(a, b);
}

static int dispatch(int selector, int a, int b) {
  binop fn = table[selector & 3];
  return apply_via_ptr(fn, a, b);
}

static int fold_callbacks(int seed, int n) {
  int acc = seed;
  for (int i = 0; i < n; ++i)
    acc = dispatch(i, acc, i + 1);
  return acc;
}

static int higher_order(int (*f)(int), int lo, int hi) {
  int s = 0;
  for (int i = lo; i < hi; ++i)
    s += f(i);
  return s;
}

static int dbl(int x) { return x * 2; }

int main(void) {
  int d0 = dispatch(0, 10, 3);
  int d1 = dispatch(2, 4, 5);
  int fold = fold_callbacks(1, 6);
  int ho = higher_order(dbl, 1, 6);
  printf("callback:%d:%d:%d:%d\n", d0, d1, fold, ho);
  return 0;
}
