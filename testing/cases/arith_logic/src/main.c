// Arithmetic & logic operator fixture.
// Exercises the full set of arithmetic (+ - * / %), unary sign, pre/post
// increment and decrement, every relational operator, the logical operators
// with short-circuit semantics, and the ternary operator on int and float
// operands. Output is deterministic and independent of optimisation.
//
// Target: ConstantIntEncryption, ConstantFPEncryption, MBA on add/sub/xor,
// and opaque predicates around the branches.
#include <stdint.h>
#include <stdio.h>

__declspec(noinline) int int_arith(int a, int b) {
  int q = a / b;        // 29 / 7 = 4
  int r = a % b;        // 29 % 7 = 1
  int s = a * b + 1;    // 203 + 1 = 204
  int d = a - b - 2;    // 22 - 2 = 20
  return q * 1000 + r * 100 + s * 10 + d;
}

__declspec(noinline) int inc_dec_chain(int v) {
  int x = v;
  int t1 = x++;     // x becomes v+1, t1 = v
  int t2 = ++x;     // x becomes v+2, t2 = v+2
  int t3 = x--;     // x becomes v+1, t3 = v+2
  int t4 = --x;     // x becomes v,   t4 = v
  return t1 * 1000 + t2 * 100 + t3 * 10 + t4;
}

__declspec(noinline) int relational_chain(int a, int b) {
  int bits = 0;
  bits |= (a == b) << 0;   // 29 == 7 -> 0
  bits |= (a != b) << 1;   // 1 -> 2
  bits |= (a <  b) << 2;   // 0 -> 0
  bits |= (a >  b) << 3;   // 1 -> 8
  bits |= (a <= b) << 4;   // 0 -> 0
  bits |= (a >= b) << 5;   // 1 -> 32
  return bits;             // 42
}

__declspec(noinline) int short_circuit(int a, int b) {
  // Short-circuit must skip the right side when left is false on &&, and
  // skip when left is true on ||. Side effects land via the counters.
  int touched = 0;
  int f_and = (a == 0) && (touched++ > -1);   // left false -> right skipped
  int t_or  = (a != 0) || (touched++ > -1);   // left true  -> right skipped
  int not_a = !(a < b);                        // !(29<7) = 1
  return f_and * 1000 + t_or * 100 + not_a * 10 + touched;
}

__declspec(noinline) double fp_arith(double a, double b) {
  double q = a / b;
  double p = a * b;
  double s = a + b;
  double d = a - b;
  // ternary on FP picks the larger magnitude.
  double pick = (s > d) ? s : d;
  return q + p + s + d + pick;
}

int main(void) {
  int i1 = int_arith(29, 7);            // 4*1000 + 1*100 + 204*10 + 20 = 4+0.1k.. = 6160
  int i2 = inc_dec_chain(5);            // 5*1000 + 7*100 + 7*10 + 5 = 5775
  int i3 = relational_chain(29, 7);     // 42
  int i4 = short_circuit(29, 7);        // 0*1000 + 1*100 + 1*10 + 0 = 110
  double f = fp_arith(29.0, 7.0);
  // q=4.142857 p=203 s=36 d=22 pick=36 -> 301.142857
  int tern = (i3 > 40) ? (i3 + 100) : 0;  // 142
  printf("arith:%d:%d:%d:%d:%d:%.6f\n", i1, i2, i3, i4, tern, f);
  return 0;
}
