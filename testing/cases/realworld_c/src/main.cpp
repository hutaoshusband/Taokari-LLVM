// Ported from FireflyProtector/test64/realworld_c/main.cpp.
// Stripped the Firefly SDK dependency (FIREFLY_NOINLINE / FIREFLY_VM_RETURN) and
// the MSVC-only intrinsics, replaced with portable equivalents that preserve the
// exact bit math so the original deterministic output is unchanged.
// Goal: a heavy, realistic obfuscator stress fixture (64-bit mixing, switch
// dispatch, hashing, multi-branch state machine) that proves -mllvm -taokari-*
// passes do not break complex logic.
#include <cstdint>
#include <cstdio>
#include <cstring>

static inline uint64_t rotl64(uint64_t x, int n) {
  n &= 63;
  return n ? (x << n) | (x >> (64 - n)) : x;
}
static inline uint64_t rotr64(uint64_t x, int n) {
  n &= 63;
  return n ? (x >> n) | (x << (64 - n)) : x;
}
static inline uint32_t rotl32(uint32_t x, int n) {
  n &= 31;
  return n ? (x << n) | (x >> (32 - n)) : x;
}
static inline uint32_t rotr32(uint32_t x, int n) {
  n &= 31;
  return n ? (x >> n) | (x << (32 - n)) : x;
}
static inline uint32_t bswap32(uint32_t x) {
  return ((x & 0x000000ffu) << 24) | ((x & 0x0000ff00u) << 8) |
         ((x & 0x00ff0000u) >> 8) | ((x & 0xff000000u) >> 24);
}

__attribute__((noinline)) uint64_t FireflyRealWorldMix(uint64_t x, uint64_t y) {
  for (uint64_t round = 0; round < 8; ++round) {
    x = rotl64(x, static_cast<int>((y ^ round) & 31u));
    x += 0x9E3779B97F4A7C15ull ^ round;
    y ^= x * 0xBF58476D1CE4E5B9ull;
    y = rotr64(y, static_cast<int>((x >> 3) & 31u));
  }
  return x ^ y;
}

__attribute__((noinline)) uint32_t FireflyRealWorldBranch(uint32_t value) {
  uint32_t result = 0;
  switch (value & 7u) {
    case 0: result = value * 17u + 3u; break;
    case 1: result = rotl32(value, 5) ^ 0xA5A55A5Au; break;
    case 2: result = value - 0x10203040u; break;
    case 3: result = (value | 0x13579BDFu) * 9u; break;
    case 4: result = (value & 0x00FF00FFu) + (value >> 8); break;
    case 5: result = bswap32(value) ^ 0xC001C0DEu; break;
    case 6: result = value * (value | 1u); break;
    default: result = value ^ 0xDEADBEEFu; break;
  }
  return result;
}

__attribute__((noinline)) uint32_t FireflyRealWorldSlice(const uint8_t *data, size_t length, uint32_t seed) {
  if (data == nullptr) {
    return seed ^ 0xBAD0BAD0u;
  }
  uint32_t acc = seed ^ 0x811C9DC5u;
  for (size_t i = 0; i < length; ++i) {
    acc ^= static_cast<uint32_t>(data[i]) + rotl32(static_cast<uint32_t>(i), static_cast<int>(i & 15u));
    acc *= 0x01000193u;
    acc ^= acc >> 13;
  }
  return acc;
}

__attribute__((noinline)) uint32_t FireflyRealWorldStateMachine(uint32_t state, uint32_t steps) {
  state = (state * 0x45D9F3Bu) + 0x27100001u;
  state ^= rotl32(state, 7);
  uint32_t cursor = 0;
  while (cursor < steps) {
    const uint32_t opcode = (state ^ (cursor * 0x45D9F3Bu)) & 0xFu;
    if (opcode <= 1u) {
      state = rotl32(state, static_cast<int>((cursor & 31u) + 1u));
    } else if (opcode <= 3u) {
      state += 0x12345678u ^ cursor;
    } else if (opcode <= 5u) {
      state = state * 3u - cursor;
    } else if (opcode <= 7u) {
      state ^= (state >> 7) ^ 0x31415926u;
    } else if (opcode <= 9u) {
      state += rotr32(state, 11);
    } else {
      state = bswap32(state) + opcode;
    }
    ++cursor;
  }
  return state;
}

__attribute__((noinline)) uint32_t FireflyRealWorldLeafCanary(uint32_t value) {
  return (value * 9u) + 7u;
}

// Replaces the SDK-marker VM function: plain noinline leaf, same return shape.
__attribute__((noinline)) uint32_t FireflyRealWorldSdkMarker(uint32_t value) {
  return value + 130u;
}

int main(int argc, char **argv) {
  const char *input = argc > 1 ? argv[1] : "FireflyRealWorldFixture";
  const size_t length = std::strlen(input);
  const auto *bytes = reinterpret_cast<const uint8_t *>(input);
  const uint64_t a = FireflyRealWorldMix(0x123456789ABCDEF0ull, static_cast<uint64_t>(length));
  const uint32_t b = FireflyRealWorldBranch(static_cast<uint32_t>(a) ^ 0x51505150u);
  const uint32_t c = FireflyRealWorldSlice(bytes, length, b);
  const uint32_t d = FireflyRealWorldStateMachine(c, 19);
  const uint32_t leaf = FireflyRealWorldLeafCanary(d);
  volatile uint32_t sdkInput = 42u;
  const uint32_t sdk = FireflyRealWorldSdkMarker(sdkInput);

  std::printf("FireflyRealWorldFixture:%016llx:%08x\n", static_cast<unsigned long long>(a), d);
  if (d == 0 || sdk != 172u || leaf == 0) {
    return 7;
  }
  return 0;
}
