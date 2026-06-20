#include <stdint.h>
#include <stdio.h>

__declspec(noinline) __declspec(dllexport)
uint32_t taokari_ida_switch_probe(uint32_t x) {
  uint32_t acc = 0x13579bdfu;
  for (uint32_t i = 0; i < 16; ++i) {
    switch ((x ^ i) & 7u) {
    case 0: acc += x * 3u + i; break;
    case 1: acc ^= (x << 5) | (x >> 27); break;
    case 2: acc -= x ^ 0xa5a55a5au; break;
    case 3: acc += (x | 1u) * 9u; break;
    case 4: acc ^= (x & 0x00ff00ffu) + i; break;
    case 5: acc += (x >> 3) ^ 0xc001c0deu; break;
    case 6: acc = (acc << 7) | (acc >> 25); break;
    default: acc ^= x + 0x10203040u; break;
    }
    x = x * 1664525u + 1013904223u + acc;
  }
  return acc ^ x;
}

int main(void) {
  printf("ida-switch:%u\n", taokari_ida_switch_probe(0x12345678u));
  return 0;
}
