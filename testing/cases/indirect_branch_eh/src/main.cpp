// Indirect branch + EH compatibility fixture.
// Combines C++ exceptions (throw/catch) with computed-goto dispatch so
// the IndirectBranch pass has to coexist with funclet-oriented EH IR.
// MSVC SEH-style: a throw inside a goto-dispatched block must propagate
// to a catch in the caller, and the goto targets must still resolve
// correctly after the IndirectBranch page-table rewrite.
#include <cstdint>
#include <cstdio>
#include <stdexcept>

__declspec(noinline) int dispatch_with_throw(int op, int v) {
  static const void *const table[] = {&&L_INC, &&L_DEC, &&L_THROW};
  if (op < 0 || op > 2)
    return v;
  goto *table[op];
L_INC:
  return v + 1;
L_DEC:
  return v - 1;
L_THROW:
  throw std::runtime_error("branch-throws");
}

int main() {
  int results[5] = {0, 0, 0, 0, 0};
  results[0] = dispatch_with_throw(0, 41); // 42
  results[1] = dispatch_with_throw(1, 43); // 42
  try {
    results[2] = dispatch_with_throw(2, 0); // throws
  } catch (const std::exception &e) {
    results[2] = -1;
  }
  try {
    results[3] = dispatch_with_throw(5, 99); // out of range -> 99
  } catch (...) {
    results[3] = -2;
  }
  results[4] = dispatch_with_throw(0, 0); // 1
  std::printf("indbr-eh:%d:%d:%d:%d:%d\n", results[0], results[1],
              results[2], results[3], results[4]);
  return 0;
}
