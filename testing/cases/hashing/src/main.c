#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

static uint64_t fnv1a64(const char *s) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
    h ^= *p;
    h *= 0x100000001b3ull;
  }
  return h;
}

static uint32_t djb2(const char *s) {
  uint32_t h = 5381;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    h = h * 33 + *p;
  return h;
}

static const uint32_t CRC_TABLE[16] = {
    0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
    0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
    0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
    0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C,
};

static uint32_t crc32(const unsigned char *data, size_t n) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; ++i) {
    crc ^= data[i];
    crc = (crc >> 4) ^ CRC_TABLE[crc & 0x0F];
    crc = (crc >> 4) ^ CRC_TABLE[crc & 0x0F];
  }
  return ~crc;
}

static const uint8_t PEARSON_KEY[16] = {
    1,  87, 49, 12, 176, 178, 102, 166,
    121, 193, 6,  84, 249, 230, 44, 15,
};

static uint8_t pearson8(const char *s) {
  uint8_t h = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    h = PEARSON_KEY[(h ^ *p) & 0x0F];
  return h;
}

int main(void) {
  const char *msg = "taokari-hash-fixture";
  const unsigned char *bytes = (const unsigned char *)msg;
  size_t n = 0;
  while (msg[n])
    ++n;

  uint64_t fnv = fnv1a64(msg);
  uint32_t dj = djb2(msg);
  uint32_t crc = crc32(bytes, n);
  uint8_t pe = pearson8(msg);

  printf("hash:%llu:%u:%u:%u\n",
         (unsigned long long)fnv, dj, crc, pe);
  return 0;
}
