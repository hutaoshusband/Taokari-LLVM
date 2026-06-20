// Indirect global variable fixture.
// Exercises IndirectGlobalVariable on a mutable global, a const global, and a
// global function pointer table. Output is deterministic and independent of
// optimization level.
#include <stdint.h>
#include <stdio.h>

int        g_counter = 7;
const int  g_factor  = 11;
static int (*g_ops[2])(int) = {0};

__declspec(noinline) int bump(int x) { return x + 1; }
__declspec(noinline) int dbl(int x) { return x * 2; }

__declspec(noinline) int consume_globals(int x) {
  g_counter += g_factor;           // mutable + const global reads/writes
  return g_counter + x * g_factor; // 18 + x*11
}

int main(void) {
  g_ops[0] = bump;
  g_ops[1] = dbl;
  int via_table = g_ops[0](g_ops[1](5));  // dbl(5)=10, bump(10)=11
  int via_globals = consume_globals(3);   // 18 + 33 = 51
  // g_counter is now 18 after consume_globals bumped it once (7+11)
  printf("globals:%d:%d:%d\n", via_table, via_globals, g_counter);
  return 0;
}
