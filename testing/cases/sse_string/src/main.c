// SSE string-op protection fixture.
//
// Reproduces the exact weakness pattern reported against the obfuscator: a
// CRT-style SSE string routine that decompiles cleanly in Hex-Rays because
//   * the dispatch is a perfectly regular `case N: shift by N` switch,
//   * every SSE op (_mm_srli_si128 / _mm_cmpeq_epi8 / _mm_movemask_epi8) is
//     fully modelled by the microcode lifter,
//   * constants 1..15 are plaintext,
//   * no opaque guards, no fake cases, no CFG protection.
//
// This fixture is the regression target for verify_sse_string_protection.py
// and the +mir:sse Fortress body-walking pass. Output is deterministic.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
#include <emmintrin.h>

// Vectorised "find first occurrence of target byte in a 16-byte chunk".
//
// The switch below is deliberately the textbook regular dispatcher:
//   case N: _mm_srli_si128(chunk, N)
// Each case is a distinct compile-time immediate shift (x86 PSRLDQ mandates
// an immediate), so the optimiser cannot collapse the 16 cases into one
// variable shift and must keep the switch. The shifted value is observable
// (it contributes the sign bit of byte[N+3] to the result), so DCE cannot
// drop the SSE ops either.
__declspec(dllexport) __declspec(noinline)
uint32_t taokari_sse_strlen_probe(const __m128i *chunk_ptr, uint8_t target) {
  __m128i pat   = _mm_set1_epi8((char)target);
  __m128i chunk = _mm_loadu_si128(chunk_ptr);
  __m128i eq    = _mm_cmpeq_epi8(chunk, pat);
  int mask      = _mm_movemask_epi8(eq);
  if (mask == 0)
    return 0x80000000u;  // sentinel: target absent

  unsigned pos = (unsigned)__builtin_ctz((unsigned)mask);
  uint32_t r;
  // case N: shift by N -- the pattern a deobfuscator collapses instantly.
  switch (pos) {
    case 0:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 0));  break;
    case 1:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 1));  break;
    case 2:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 2));  break;
    case 3:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 3));  break;
    case 4:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 4));  break;
    case 5:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 5));  break;
    case 6:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 6));  break;
    case 7:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 7));  break;
    case 8:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 8));  break;
    case 9:  r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 9));  break;
    case 10: r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 10)); break;
    case 11: r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 11)); break;
    case 12: r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 12)); break;
    case 13: r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 13)); break;
    case 14: r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 14)); break;
    case 15: r = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(chunk, 15)); break;
    default: r = 0; break;
  }
  // pos is the byte index of the first match; r's top bit is the sign of
  // byte[pos+3]. Combining them keeps both observable without changing the
  // position semantics the test verifies.
  return (pos & 0xFFFFu) | ((r >> 31) << 16);
}

int main(void) {
  // chunk = "taokari-sse-probe" (16 bytes). 'a' appears at indices 1, 4, 11.
  // pcmpeqb|pmovmskb mask = 0b10010 = 0x12; ctz -> pos = 1. The first match
  // byte 'a' is positive, so the sign bit tag is 0.
  // Golden output (verified against the binary): sse-string:1:0:a
  static const char buf[32] = "taokari-sse-probe!!";
  uint32_t pos = taokari_sse_strlen_probe((const __m128i *)buf, 'a');
  // pos encodes the match index in the low 16 bits and a 1-bit tag in bit 16.
  unsigned idx = pos & 0xFFFFu;
  unsigned tag = (pos >> 16) & 1u;
  printf("sse-string:%u:%u:%c\n", idx, tag, buf[idx]);
  return 0;
}
