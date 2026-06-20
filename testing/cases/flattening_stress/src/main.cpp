#include <cstdint>
#include <cstdio>

#if defined(_MSC_VER)
#define TAO_NOINLINE __declspec(noinline)
#else
#define TAO_NOINLINE __attribute__((noinline))
#endif

#if defined(__clang__)
#define TAO_FLA3 __attribute__((annotate("+fla ^fla=3")))
#else
#define TAO_FLA3
#endif

static inline uint32_t rotl32(uint32_t x, unsigned n) {
  n &= 31u;
  return n ? (x << n) | (x >> (32u - n)) : x;
}

TAO_NOINLINE TAO_FLA3 uint32_t fortress_switch(uint32_t x, uint32_t rounds) {
  uint32_t state = x ^ 0x9e3779b9u;
  for (uint32_t i = 0; i < rounds; ++i) {
    switch ((state ^ i) & 7u) {
    case 0:
      state += rotl32(x + i, 3);
      break;
    case 1:
      state ^= 0x45d9f3bu * (i | 1u);
      break;
    case 2:
      state = rotl32(state, (i & 15u) + 1u) ^ x;
      break;
    case 3:
      state -= (state >> 5) + 0x10203040u;
      break;
    case 4:
      state = (state * 33u) ^ (x >> (i & 7u));
      break;
    case 5:
      state += (state | 1u) * 7u;
      break;
    case 6:
      state ^= rotl32(state + x, 11);
      break;
    default:
      state = (state + 0x31415926u) ^ (i * 17u);
      break;
    }
    if ((state & 3u) == 1u) {
      state ^= rotl32(state, 9);
    } else if ((state & 7u) == 2u) {
      state += 0x27100001u ^ i;
    } else {
      state -= (state >> 3) | 1u;
    }
  }
  return state;
}

TAO_NOINLINE TAO_FLA3 uint32_t fortress_nested(uint32_t seed) {
  uint32_t acc = seed * 0x01000193u;
  for (uint32_t outer = 0; outer < 9; ++outer) {
    uint32_t local = acc ^ (outer * 0x811c9dc5u);
    for (uint32_t inner = 0; inner < 5; ++inner) {
      if (((local + inner) & 1u) == 0u) {
        local = rotl32(local ^ acc, inner + 3u);
      } else {
        local = (local * 13u) + (acc >> ((inner + outer) & 7u));
      }
      acc ^= local + 0x5bd1e995u;
    }
    acc += fortress_switch(local, 3u + (outer & 3u));
  }
  return acc;
}

int main() {
  const uint32_t a = fortress_switch(0x12345678u, 17);
  const uint32_t b = fortress_nested(a ^ 0xa5a55a5au);
  std::printf("flattening-stress:%u:%u\n", a, b);
  return (a == 0u || b == 0u) ? 9 : 0;
}
