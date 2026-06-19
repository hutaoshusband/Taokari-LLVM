#include <stdio.h>

static int fold(int n) {
  int total = 0;
  for (int i = 0; i <= n; ++i) {
    total += (i * 3) ^ (i + 7);
  }
  return total;
}

int main(void) {
  printf("c-console:%d\n", fold(7));
  return 0;
}
