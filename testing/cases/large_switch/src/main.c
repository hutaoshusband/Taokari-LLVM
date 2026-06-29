#include <stdio.h>
#include <stdint.h>

static int classify(int code) {
  switch (code) {
    case 0: return 100;
    case 1: return 201;
    case 2: return 302;
    case 3: return 403;
    case 4: return 504;
    case 5: return 605;
    case 6: return 706;
    case 7: return 807;
    case 8: return 908;
    case 9: return 109;
    case 10: return 211;
    case 11: return 312;
    case 12: return 413;
    case 13: return 514;
    case 14: return 615;
    case 15: return 716;
    case 16: return 817;
    case 17: return 918;
    case 18: return 129;
    case 19: return 231;
    case 20: return 332;
    case 21: return 433;
    case 22: return 534;
    case 23: return 635;
    case 24: return 736;
    case 25: return 837;
    case 26: return 938;
    case 27: return 149;
    case 28: return 251;
    case 29: return 352;
    case 30: return 453;
    default: return -1;
  }
}

static int fallthrough_chain(int start) {
  int acc = start;
  switch (start) {
    case 0:
      acc += 1;
      __attribute__((fallthrough));
    case 1:
      acc += 2;
      __attribute__((fallthrough));
    case 2:
      acc += 4;
      __attribute__((fallthrough));
    case 3:
      acc += 8;
      break;
    default:
      acc = -acc;
  }
  return acc;
}

static int sum_classification(int n) {
  int s = 0;
  for (int i = 0; i < n; ++i)
    s += classify(i % 32);
  return s;
}

int main(void) {
  int c7 = classify(7);
  int c25 = classify(25);
  int c99 = classify(99);
  int ft = fallthrough_chain(1);
  int sum = sum_classification(32);
  printf("switch:%d:%d:%d:%d:%d\n", c7, c25, c99, ft, sum);
  return 0;
}
