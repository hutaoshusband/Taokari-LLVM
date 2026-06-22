// Indirect branch fixture.
// Uses computed goto (which the obfuscator lowers through the indirect
// branch page table) plus a manual jump table built on local labels. This
// stresses the IndirectBranch pass: the dispatch targets are local labels
// and the page-table indirection must preserve the control flow exactly.
//
// Target: IndirectBranch (Level 1+).
#include <cstdint>
#include <cstdio>

__declspec(noinline) int computed_goto_table(int op, int acc) {
  // A 5-way dispatch over a computed goto. The &&label expressions are
  // BlockAddress values; the dispatch lowers to an indirectbr in the
  // final IR, which the IndirectBranch pass routes through its page
  // table.
  static const void *const table[] = {&&L_ADD, &&L_SUB, &&L_MUL,
                                       &&L_XOR, &&L_DONE};
  if (op < 0 || op > 4)
    return acc;
  goto *table[op];
L_ADD:
  acc = acc + 7;
  goto L_DONE;
L_SUB:
  acc = acc - 3;
  goto L_DONE;
L_MUL:
  acc = acc * 5;
  goto L_DONE;
L_XOR:
  acc = acc ^ 0x55;
  goto L_DONE;
L_DONE:
  return acc;
}

__declspec(noinline) int loop_with_goto(int n) {
  // A loop whose body re-enters via goto — a second source of indirect
  // branch edges after the obfuscator rewrites control flow.
  int i = 0;
  int sum = 0;
L_TOP:
  if (i >= n)
    goto L_EXIT;
  sum += i;
  ++i;
  goto L_TOP;
L_EXIT:
  return sum;
}

int main() {
  int a = computed_goto_table(0, 10);   // 10 + 7 = 17
  int b = computed_goto_table(1, 20);   // 20 - 3 = 17
  int c = computed_goto_table(2, 4);    // 4 * 5 = 20
  int d = computed_goto_table(3, 0xAA); // 0xAA ^ 0x55 = 0xFF = 255
  int e = computed_goto_table(5, 99);   // out of range, returns 99
  int s = loop_with_goto(10);           // 0+1+..+9 = 45
  std::printf("indbr:%d:%d:%d:%d:%d:%d\n", a, b, c, d, e, s);
  return 0;
}
