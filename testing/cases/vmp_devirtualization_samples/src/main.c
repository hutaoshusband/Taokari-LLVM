#include <stdint.h>
#include <stdio.h>

#ifdef TAOKARI_USE_VMP
#define VMP __attribute__((noinline, annotate("+vmp")))
#else
#define VMP __attribute__((noinline))
#endif

int VMP sample_linear(int a, int b) {
  int x = ((a + 0x1234) ^ (b * 7)) - 0x55;
  return (x ^ (a << 2)) + (b & 31);
}

int VMP sample_branch(int a, int b) {
  int x = (a ^ 0x2d) + (b * 3);
  if ((x & 7) > 3)
    return (x - a) ^ 0x71;
  return (x + b) ^ 0x39;
}

int VMP sample_mask(int a, int b) {
  int mask = -((a ^ b) & 1);
  int x = a + b + 9;
  int left = (x ^ 0x11) + (a & 0x3f);
  int right = ((x * 3) - 7) ^ (b << 1);
  return (left & mask) | (right & ~mask);
}

int VMP sample_state(int a, int b) {
  int acc = a ^ 0x4b;
  acc = ((acc + b) * 3) ^ a;
  acc = ((acc + b + 1) * 3) ^ (a >> 1);
  acc = ((acc + b + 2) * 3) ^ a;
  acc = ((acc + b + 3) * 3) ^ (a >> 1);
  acc = ((acc + b + 4) * 3) ^ a;
  return acc;
}

int main(void) {
  int pairs[][2] = {{7, 3}, {19, 11}, {-13, 5}};
  int total = 0;
  for (unsigned i = 0; i < sizeof(pairs) / sizeof(pairs[0]); ++i) {
    int a = pairs[i][0];
    int b = pairs[i][1];
    total += sample_linear(a, b);
    total ^= sample_branch(a, b);
    total += sample_mask(a, b);
    total ^= sample_state(a, b);
  }
  printf("vmp-devirt:%d\n", total);
  return 0;
}
