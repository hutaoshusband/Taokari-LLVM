// Bitwise & shift operator fixture.
// Exercises bit-wise AND/OR/XOR/complement on int and unsigned, left/right
// shifts (<<, >>), every compound bit-assignment form (|= &= ^= <<= >>=), and
// the set/clear/toggle bit-mask idioms. A byte-order probe exercises storing
// a value to memory and reading it back byte by byte, which is what the
// obfuscator must preserve when ConstantIntEncryption rewrites the literal.
//
// Target: ConstantIntEncryption on every literal, MBA substitution on the
// AND/OR/XOR, and the constant folder under -O2/LTO.
#include <stdint.h>
#include <stdio.h>

__declspec(noinline) uint32_t basic_bits(uint32_t a, uint32_t b) {
  uint32_t and_ = a & b;
  uint32_t or_  = a | b;
  uint32_t xor_ = a ^ b;
  uint32_t not_ = ~a;
  // Combine with rotation-free shifts so the literal survives MBA.
  return (and_ << 24) | ((or_ & 0xFFFFFFu) << 8) | (xor_ & 0xFFu) | (not_ >> 24);
}

__declspec(noinline) uint32_t shifts(uint32_t v) {
  uint32_t l1 = v << 1;
  uint32_t l4 = v << 4;
  uint32_t r1 = v >> 1;
  uint32_t r4 = v >> 4;
  return l1 ^ l4 ^ r1 ^ r4;
}

__declspec(noinline) uint32_t compound(uint32_t v) {
  v |= 0x100u;     // set bit 8
  v &= ~0x4u;      // clear bit 2
  v ^= 0x80u;      // toggle bit 7
  v <<= 2;
  v >>= 1;
  return v;
}

__declspec(noinline) uint32_t bit_ops(uint32_t v) {
  uint32_t r = v;
  int bit3_set   = (r & (1u << 3)) ? 1 : 0;
  int bit5_clear = (r & (1u << 5)) ? 0 : 1;
  int bit7_tgl   = (r & (1u << 7)) ? 1 : 0;
  r |= (1u << 4);     // set bit 4
  r &= ~(1u << 6);    // clear bit 6
  r ^= (1u << 8);     // toggle bit 8
  return (bit3_set << 0) | (bit5_clear << 1) | (bit7_tgl << 2) | ((r >> 4) & 0xFFFFFu);
}

__declspec(noinline) int endian_probe(uint32_t v) {
  // Store then load back byte by byte: exercises memcpy-like access patterns
  // the obfuscator must keep value-stable. Returns LE byte index of the
  // lowest set bit of v, computed via byte inspection rather than builtin.
  unsigned char buf[4];
  buf[0] = (unsigned char)(v & 0xFFu);
  buf[1] = (unsigned char)((v >> 8) & 0xFFu);
  buf[2] = (unsigned char)((v >> 16) & 0xFFu);
  buf[3] = (unsigned char)((v >> 24) & 0xFFu);
  for (int i = 0; i < 4; ++i) {
    if (buf[i] != 0) {
      return i;  // first non-zero LE byte index
    }
  }
  return 4;
}

int main(void) {
  uint32_t a = 0xF0F0F0F0u;
  uint32_t b = 0x0FF00FF0u;
  uint32_t r1 = basic_bits(a, b);
  uint32_t r2 = shifts(0x12345678u);
  uint32_t r3 = compound(0x00000040u);
  uint32_t r4 = bit_ops(0x000000C8u);  // bits 3,6,7 set
  int e = endian_probe(0x00010000u);   // first nonzero LE byte = index 2
  printf("bitops:%u:%u:%u:%u:%d\n", r1, r2, r3, r4, e);
  return 0;
}
