#include <stdio.h>
#include <stdint.h>
#include <math.h>

static double poly_eval(const double *c, int n, double x) {
  double r = 0.0;
  for (int i = n - 1; i >= 0; --i)
    r = r * x + c[i];
  return r;
}

static int isqrt_floor(int n) {
  if (n < 0)
    return -1;
  int x = n;
  int y = (x + 1) / 2;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2;
  }
  return x;
}

static uint64_t mulhi(uint64_t a, uint64_t b) {
  uint64_t a_lo = a & 0xFFFFFFFFull;
  uint64_t a_hi = a >> 32;
  uint64_t b_lo = b & 0xFFFFFFFFull;
  uint64_t b_hi = b >> 32;
  uint64_t lo = a_lo * b_lo;
  uint64_t mid1 = a_hi * b_lo;
  uint64_t mid2 = a_lo * b_hi;
  uint64_t carry = ((mid1 & 0xFFFFFFFFull) + (mid2 & 0xFFFFFFFFull) +
                    (lo >> 32)) >> 32;
  return a_hi * b_hi + (mid1 >> 32) + (mid2 >> 32) + carry;
}

static double trig_sum(int n, double phase) {
  double s = 0.0;
  for (int i = 0; i < n; ++i) {
    double a = (double)i * phase;
    s += sin(a) * cos(a * 0.5);
  }
  return s;
}

static uint64_t pow_mod(uint64_t base, uint64_t exp, uint64_t mod) {
  uint64_t result = 1 % mod;
  base %= mod;
  while (exp) {
    if (exp & 1)
      result = mulhi(result, base) % mod + (result * base) % mod;
    base = mulhi(base, base) % mod + (base * base) % mod;
    exp >>= 1;
  }
  return result % mod;
}

int main(void) {
  double coeffs[5] = {1.5, -2.0, 3.0, -4.0, 5.0};
  double pe = poly_eval(coeffs, 5, 2.0);
  int sq = isqrt_floor(1048576);
  uint64_t hi = mulhi(0x123456789ABCDEF0ull, 0xFEDCBA9876543210ull);
  double ts = trig_sum(8, 0.3);
  uint64_t pm = pow_mod(7, 13, 1000);
  printf("math:%.4f:%d:%llu:%.4f:%llu\n",
         pe, sq, (unsigned long long)hi, ts, (unsigned long long)pm);
  return 0;
}
