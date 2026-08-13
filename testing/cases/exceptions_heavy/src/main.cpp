// Exception-heavy C++ fixture.
// Surfaces beyond exceptions_raii: destructor-order fingerprint across
// inlined and noinline frames, virtual exception hierarchies, rethrow,
// exception_ptr crossing noinline helpers, throw from a virtual override,
// try/catch in a loop, function-try-block constructors, partial member
// construction unwind, and catching a heap-allocated exception pointer.
// Flattening already refuses personality functions; the remaining stack
// (CIE/ICALL/CSE/MBA) must still preserve unwind tables and catch matching.
#include <cstdint>
#include <cstdio>
#include <exception>
#include <stdexcept>
#include <string>

struct Probe {
  int *log;
  int id;
  Probe(int *log, int id) : log(log), id(id) { *log = *log * 10 + id; }
  ~Probe() { *log = *log * 10 + (id + 5); }
  Probe(const Probe &) = delete;
  Probe &operator=(const Probe &) = delete;
};

struct BaseExc {
  virtual int code() const { return 1; }
  virtual ~BaseExc() = default;
};
struct MidExc : BaseExc {
  int code() const override { return 2; }
};
struct LeafExc : MidExc {
  int code() const override { return 3; }
  int extra() const { return 40; }
};

struct App {
  int n;
  explicit App(int n) : n(n) {}
};

struct Shape {
  virtual int go(int x) const { return x; }
  virtual ~Shape() = default;
};
struct Sharp : Shape {
  int go(int x) const override {
    if (x < 0)
      throw x;
    return x * 2;
  }
};

struct Member {
  int *p;
  Member(int *p, int tag) : p(p) { *p = *p * 10 + tag; }
  ~Member() { *p = *p * 10 + 9; }
};
struct Owner {
  Member a, b;
  Owner(int *p) : a(p, 1), b(p, 2) {
    *p = *p * 10 + 3;
    throw 1;
  }
};

struct Boom {
  int v;
  Boom(int x, int *out)
  try : v(x) {
    if (x < 0)
      throw x;
    *out = v;
  } catch (int t) {
    *out = t - 50;
    throw;
  }
};

static int g_fp;

__declspec(noinline) int dtor_order() {
  int log = 0;
  try {
    Probe a(&log, 1);
    Probe b(&log, 2);
    Probe c(&log, 3);
    throw 1;
  } catch (...) {
  }
  return log;
}

__declspec(noinline) int virt_exc() {
  try {
    throw LeafExc();
  } catch (const MidExc &e) {
    return e.code() * 10;
  } catch (...) {
    return -1;
  }
}

__declspec(noinline) int rethrow_chain() {
  int rec = 0;
  try {
    try {
      throw 7;
    } catch (int x) {
      rec = x + 1;
      throw;
    }
  } catch (int y) {
    return rec * 100 + y;
  }
}

__declspec(noinline) std::exception_ptr capture(int x) {
  try {
    if (x)
      throw App{x};
  } catch (...) {
    return std::current_exception();
  }
  return {};
}

__declspec(noinline) int consume(std::exception_ptr p) {
  if (!p)
    return 0;
  try {
    std::rethrow_exception(p);
  } catch (const App &e) {
    return e.n;
  }
}

__declspec(noinline) int virt_throw(const Shape &s, int x) {
  try {
    return s.go(x);
  } catch (int t) {
    return t - 100;
  }
}

__declspec(noinline) int loop_try() {
  int acc = 0;
  for (int i = 0; i < 5; ++i) {
    try {
      if (i == 3)
        throw i;
      acc += i;
    } catch (int t) {
      acc += t * 10;
    }
  }
  return acc;
}

__declspec(noinline) int fn_try(int x) {
  int out = 0;
  try {
    Boom b(x, &out);
    return out;
  } catch (int) {
    return out;
  }
}

__declspec(noinline) int partial_ctor() {
  int log = 0;
  try {
    Owner o(&log);
  } catch (int) {
    return log;
  }
  return -1;
}

__declspec(noinline) int catch_ptr() {
  try {
    throw new LeafExc();
  } catch (LeafExc *p) {
    int c = p->code() + p->extra();
    delete p;
    return c;
  } catch (...) {
    return -1;
  }
}

__declspec(noinline) int str_exc() {
  try {
    throw std::runtime_error("heavy");
  } catch (const std::exception &e) {
    return static_cast<int>(static_cast<unsigned char>(e.what()[0]));
  }
}

__declspec(noinline) int f4(int x) {
  Probe a(&g_fp, 4);
  if (x)
    throw x;
  return 1;
}
__declspec(noinline) int f3(int x) {
  Probe a(&g_fp, 3);
  return f4(x) + 1;
}
__declspec(noinline) int f2(int x) {
  Probe a(&g_fp, 2);
  return f3(x) + 1;
}
__declspec(noinline) int deep_unwind(int x) {
  g_fp = 0;
  try {
    return f2(x);
  } catch (int t) {
    return g_fp + t;
  }
}

int main() {
  Sharp sh;
  int r0 = dtor_order();
  int r1 = virt_exc();
  int r2 = rethrow_chain();
  int r3 = consume(capture(9));
  int r4 = virt_throw(sh, 4);
  int r5 = virt_throw(sh, -3);
  int r6 = loop_try();
  int r7 = fn_try(6);
  int r8 = fn_try(-4);
  int r9 = partial_ctor();
  int r10 = catch_ptr();
  int r11 = str_exc();
  int r12 = deep_unwind(9);
  std::printf("exc-heavy:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d\n", r0, r1, r2,
              r3, r4, r5, r6, r7, r8, r9, r10, r11, r12);
  return 0;
}
