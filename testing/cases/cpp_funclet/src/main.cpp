#include <stdio.h>

struct Guard {
  int *value;
  ~Guard() { *value += 3; }
};

__declspec(noinline) int run_case(int x) {
  int value = 1;
  try {
    Guard guard{&value};
    if (x)
      throw 5;
    value += 10;
  } catch (...) {
    value += 20;
  }
  return value;
}

int main() {
  printf("funclet:%d:%d\n", run_case(0), run_case(1));
  return 0;
}
