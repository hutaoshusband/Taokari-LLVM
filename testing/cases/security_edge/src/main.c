// Security & sanitizer-compatibility fixture.
// Exercises the edge cases that UBSan/ASan check, in their well-defined form:
// signed integer overflow via promotion to unsigned (the wrap-around that the
// standard guarantees), integer division/modulo rounding, signed/unsigned
// comparison pitfalls, strict-aliasing-safe buffer copies via memcpy, length-
// bounded string ops, and stack-array bounds checks. Nothing here is UB; the
// obfuscator must preserve every defined result, and the binary must run
// cleanly under sanitizers.
//
// Target: ConstantIntEncryption on the boundary constants, MBA on the
// arithmetic (must not introduce UB by reassociating signed overflow), and
// the memcpy/memmove/strnlen lowering must stay side-effect-equivalent.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Wrap-around via unsigned arithmetic: defined for unsigned, UB for signed.
__declspec(noinline) uint32_t unsigned_wrap(uint32_t base) {
  uint32_t a = base - 1;          // wrap if base==0
  uint32_t b = a * 0x10000u;
  uint32_t c = b + 0xFFFFFFFFu;   // wrap back near a
  return (a ^ b) + c;
}

// Division/modulo rounding on both signs.
__declspec(noinline) int divmod_quirks(int a, int b) {
  int q = a / b;
  int r = a % b;
  // signed division truncates toward zero, so (a%b) has the sign of a.
  int sign_check = (r != 0) && ((r < 0) == (a < 0));
  return q * 100 + r + sign_check * 1000;
}

// Signed/unsigned comparison: the signed value is promoted to unsigned.
__declspec(noinline) int signed_unsigned_compare(int s, unsigned u) {
  int s_lt_u = (s < (int)u);          // true compare via cast
  int s_promoted_lt = ((unsigned)s < u);  // -1 promotes to UINT_MAX
  return s_lt_u * 10 + (s_promoted_lt ? 1 : 0);
}

// Strict-aliasing-safe copy via memcpy (no UB from type punning).
__declspec(noinline) uint32_t pun_float_to_uint(float f) {
  uint32_t u;
  memcpy(&u, &f, sizeof(u));
  return u;
}

// Length-bounded string ops: never read past the bound.
__declspec(noinline) int bounded_string_ops(const char *src, size_t cap) {
  char buf[32];
  size_t n = strnlen(src, cap);
  if (n >= sizeof(buf)) n = sizeof(buf) - 1;
  memcpy(buf, src, n);
  buf[n] = '\0';
  // Simple checksum of the copied bytes.
  int cs = 0;
  for (size_t i = 0; i < n; ++i) cs = cs * 31 + (unsigned char)buf[i];
  return cs * 1000 + (int)n;
}

// Stack-array bounds: index computed from a hash, clamped to valid range.
__declspec(noinline) int safe_index(int seed) {
  int table[16];
  for (int i = 0; i < 16; ++i) table[i] = (i + 1) * (i + 1);
  int idx = (seed * 2654435761) & 15;   // fast mod-16 via mask; always 0..15
  if (idx < 0) idx = 0;
  if (idx >= 16) idx = 15;
  return table[idx];
}

// INT_MIN / -1 would overflow (UB on x86). Guard against it explicitly.
__declspec(noinline) int safe_intmin_div(int x) {
  if (x == INT32_MIN) return 0;        // would be UB to negate/divide by -1
  int neg = -x;
  return neg;
}

int main(void) {
  uint32_t w = unsigned_wrap(1u);                // a=0, b=0, c=0xFFFFFFFF -> xor 0 + 0xFFFFFFFF
  int dm1 = divmod_quirks(-7, 2);                 // -7/2=-3, -7%2=-1, sign_match -> -300 + -1 + 1000 = 699
  int dm2 = divmod_quirks(7, -2);                 // 7/-2=-3, 7%-2=1, no sign match -> -300 + 1 + 0 = -299
  int cmp = signed_unsigned_compare(-1, 1u);      // s<1u via cast: true(1); unsigned(-1)<1: false(0) -> 10
  uint32_t pun = pun_float_to_uint(1.0f);          // 0x3F800000 = 1065353216
  const char *s = "taokari-security";
  int bso = bounded_string_ops(s, 100);            // checksum * 1000 + 17
  int si = safe_index(0x12345678);
  int sim = safe_intmin_div(INT32_MIN);            // 0 (guarded)
  printf("sec:%u:%d:%d:%d:%u:%d:%d:%d\n",
         w, dm1, dm2, cmp, pun, bso, si, sim);
  return 0;
}
