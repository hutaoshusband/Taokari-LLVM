#include <stdio.h>

__attribute__((noinline, __annotate__("+vmp")))
static int protected_mix(int a, int b) {
  int x = (a + b) ^ 17;
  if (x > 40)
    return x - b;
  return x + a;
}

int main(int argc, char **argv) {
  (void)argv;
  printf("vmp-basic:%d:%d\n", protected_mix(argc + 22, 19),
         protected_mix(argc + 2, 4));
  return 0;
}
