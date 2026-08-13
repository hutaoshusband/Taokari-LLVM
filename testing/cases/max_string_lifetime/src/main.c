#include <stdio.h>
#include <string.h>

__declspec(noinline) int score(const char *s) {
  int acc = 0;
  for (; s && *s; ++s)
    acc = acc * 131 + (unsigned char)*s;
  return acc;
}

__declspec(noinline) int local_ptr(void) {
  const char *p = "local-lifetime";
  return score(p) + (int)strlen(p);
}

__declspec(noinline) int used_twice(void) {
  const char *p = "used-twice";
  return score(p) ^ score(p + 5);
}

__declspec(noinline) int table_lookup(int i) {
  const char *msgs[] = {"alpha", "bravo", "charlie"};
  return score(msgs[i % 3]);
}

__declspec(noinline) const char *pick(int x) {
  return x ? "yes-branch" : "no-branch";
}

int main(void) {
  printf("maxstr:%d:%d:%d:%d:%s\n", local_ptr(), used_twice(),
         table_lookup(1), score(pick(1)) + score(pick(0)), "fmt-ok");
  return 0;
}
