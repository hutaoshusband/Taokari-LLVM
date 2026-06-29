#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_OUT 256

static int rle_compress(const unsigned char *in, int n,
                        unsigned char *out, int cap) {
  int w = 0;
  int i = 0;
  while (i < n) {
    unsigned char b = in[i];
    int run = 1;
    while (i + run < n && in[i + run] == b && run < 255)
      ++run;
    if (w + 2 > cap)
      return -1;
    out[w++] = (unsigned char)run;
    out[w++] = b;
    i += run;
  }
  return w;
}

static int rle_decompress(const unsigned char *in, int n,
                          unsigned char *out, int cap) {
  int w = 0;
  for (int i = 0; i + 1 < n; i += 2) {
    int run = in[i];
    unsigned char b = in[i + 1];
    if (w + run > cap)
      return -1;
    for (int k = 0; k < run; ++k)
      out[w++] = b;
  }
  return w;
}

#define WIN 16
#define MIN_MATCH 3

static int lz_compress(const unsigned char *in, int n,
                       unsigned char *out, int cap) {
  int w = 0;
  int pos = 0;
  while (pos < n) {
    int best_len = 0;
    int best_off = 0;
    int start = pos - WIN;
    if (start < 0)
      start = 0;
    for (int off = start; off < pos; ++off) {
      int len = 0;
      while (pos + len < n && len < 18 && in[off + len] == in[pos + len])
        ++len;
      if (len > best_len) {
        best_len = len;
        best_off = pos - off;
      }
    }
    if (best_len >= MIN_MATCH) {
      if (w + 3 > cap)
        return -1;
      out[w++] = 0x80 | (unsigned char)(best_len - MIN_MATCH);
      out[w++] = (unsigned char)best_off;
      out[w++] = in[pos];
      pos += best_len;
    } else {
      if (w + 1 > cap)
        return -1;
      out[w++] = in[pos];
      ++pos;
    }
  }
  return w;
}

static int lz_decompress(const unsigned char *in, int n,
                         unsigned char *out, int cap) {
  int w = 0;
  int i = 0;
  while (i < n) {
    if (in[i] & 0x80) {
      if (i + 2 >= n || w + (in[i] & 0x7f) + MIN_MATCH > cap)
        return -1;
      int len = (in[i] & 0x7f) + MIN_MATCH;
      int off = in[i + 1];
      int src = w - off;
      for (int k = 0; k < len; ++k)
        out[w++] = out[src + k];
      i += 3;
    } else {
      if (w + 1 > cap)
        return -1;
      out[w++] = in[i];
      ++i;
    }
  }
  return w;
}

static const unsigned char INPUT[] = {
    'a','a','a','a','b','b','c','d','d','d','d','d','e',
    'x','y','z','x','y','z','x','y','z','q','q','q','r','r','r','r','r','s'
};

int main(void) {
  unsigned char rle_out[MAX_OUT];
  unsigned char rle_back[MAX_OUT];
  int rle_c = rle_compress(INPUT, (int)sizeof(INPUT), rle_out, MAX_OUT);
  int rle_d = rle_decompress(rle_out, rle_c, rle_back, MAX_OUT);
  int rle_ok = (rle_d == (int)sizeof(INPUT) &&
                memcmp(rle_back, INPUT, sizeof(INPUT)) == 0);

  unsigned char lz_out[MAX_OUT];
  unsigned char lz_back[MAX_OUT];
  int lz_c = lz_compress(INPUT, (int)sizeof(INPUT), lz_out, MAX_OUT);
  int lz_d = lz_decompress(lz_out, lz_c, lz_back, MAX_OUT);
  int lz_ok = (lz_d == (int)sizeof(INPUT) &&
               memcmp(lz_back, INPUT, sizeof(INPUT)) == 0);

  printf("compress:%d:%d:%d:%d:%d:%d\n",
         rle_c, rle_ok, lz_c, lz_ok,
         (int)sizeof(INPUT), rle_c + lz_c);
  return 0;
}
