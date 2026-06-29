#include <cstdio>
#include <cstdint>

static int counter = 0;

int next_id() {
  static int current = ++counter * 100;
  return current++;
}

struct Registrar {
  int id;
  Registrar() : id(next_id()) {}
};

static Registrar r1;
static Registrar r2;

static int lazy_once() {
  static int cached = (counter * 7) + 13;
  return cached;
}

int main() {
  int a = next_id();
  int b = next_id();
  int c = r1.id;
  int d = r2.id;
  int lz = lazy_once();
  int lz2 = lazy_once();
  printf("staticinit:%d:%d:%d:%d:%d:%d\n", a, b, c, d, lz, lz2);
  return 0;
}
