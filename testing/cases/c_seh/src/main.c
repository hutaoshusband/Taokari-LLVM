#include <stdio.h>

volatile int g = 3;

__declspec(noinline) int guarded(int x) {
  int local = 0;
  __try {
    local = x + g;
  } __finally {
    g += 1;
  }
  return local + g;
}

int main(void) {
  int first = guarded(5);
  int second = guarded(7);
  printf("seh:%d:%d\n", first, second);
  return 0;
}
