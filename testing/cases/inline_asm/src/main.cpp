// Inline assembler & compiler-specifics fixture.
// Exercises GCC/Clang inline asm (`asm volatile(...)`) with input, output and
// clobber operands; the compiler-specific __attribute__((packed)) and
// __attribute__((aligned)) layout attributes; and a struct that mixes packed
// and aligned members. Inline asm must pass through the obfuscator unchanged
// (the obfuscator only rewrites IR it models), and the packed-struct GEP
// offsets must stay byte-exact after ConstantIntEncryption.
//
// Target: inline-asm pass-through, packed/aligned struct GEP correctness,
// and struct-return ABI for the asm-bridged helpers.
#include <stdint.h>
#include <stdio.h>

#if defined(__clang__) || defined(__GNUC__)
#define HAVE_GNU_ASM 1
#else
#define HAVE_GNU_ASM 0
#endif

// Pure-computation inline asm: add two ints via the asm constraint path so
// the result is deterministic and side-effect free.
__declspec(noinline) int asm_add(int a, int b) {
#if HAVE_GNU_ASM
  int result;
  __asm__ volatile("add %2, %0" : "=r"(result) : "0"(a), "r"(b));
  return result;
#else
  return a + b;
#endif
}

__declspec(noinline) int asm_shift_xor(int a, int b) {
#if HAVE_GNU_ASM
  int result = a << (b & 7);
  // Final xor via asm so the constraint/clobber path is exercised without
  // the byte/word register sizing ambiguity of a full shift sequence.
  __asm__ volatile(
      "xorl %1, %0\n\t"
      : "+r"(result)
      : "r"(b)
      : "cc");
  return result;
#else
  return (a << (b & 7)) ^ b;
#endif
}

// Packed struct: no padding between members, GEP offsets are non-trivial.
struct __attribute__((packed)) Packed {
  uint8_t a;
  uint32_t b;
  uint16_t c;
  uint8_t d;
};

__declspec(noinline) uint32_t packed_sum(const struct Packed *p) {
  return p->a + p->b + p->c + p->d;
}

// Aligned struct: forces alignment that the obfuscator must not relax.
struct __attribute__((aligned(32))) Aligned {
  uint64_t values[4];
};

__declspec(noinline) uint64_t aligned_sum(const struct Aligned *a) {
  uint64_t s = 0;
  for (int i = 0; i < 4; ++i) s += a->values[i];
  return s;
}

// Combined: packed + an inline-asm xor loop, to stress both at once.
struct __attribute__((packed)) Mixed {
  uint8_t tag;
  uint64_t payload;
};

__declspec(noinline) uint64_t mixed_xor_sum(const struct Mixed *items, int n) {
  uint64_t acc = 0;
  for (int i = 0; i < n; ++i) {
    acc += asm_shift_xor(static_cast<int>(items[i].payload & 0xFFFFu),
                         static_cast<int>(items[i].tag));
  }
  return acc;
}

int main(void) {
  int r1 = asm_add(1234, 5678);          // 6912
  int r2 = asm_shift_xor(0x10, 4);       // (0x10 << 4) ^ 4 = 0x100 ^ 4 = 260
  int r3 = asm_shift_xor(0x20, 2);       // (0x20 << 2) ^ 2 = 0x80 ^ 2 = 130

  struct Packed pk = {0xABu, 0x12345678u, 0xBEEFu, 0x07u};
  uint32_t ps = packed_sum(&pk);

  struct Aligned al = {{1ull, 10ull, 100ull, 1000ull}};
  uint64_t as = aligned_sum(&al);        // 1111

  struct Mixed items[3] = {
      {1u, 0x100ull},
      {2u, 0x200ull},
      {3u, 0x300ull},
  };
  uint64_t mx = mixed_xor_sum(items, 3);

  printf("asm:%d:%d:%d:%u:%llu:%llu\n",
         r1, r2, r3, ps,
         (unsigned long long)as, (unsigned long long)mx);
  return 0;
}
