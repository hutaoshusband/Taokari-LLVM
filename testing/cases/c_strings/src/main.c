// String encryption fixture.
// Exercises ConstantStringEncryption on char literals, a multi-byte literal, a
// format string, and runtime-built strings. Output is deterministic.
#include <stdio.h>
#include <string.h>

static const char *secret = "taokari-secret";
static const char *tag    = "FX";

__declspec(noinline) int score(const char *s) {
  int acc = 0;
  for (const char *p = s; *p; ++p) {
    acc = acc * 31 + (unsigned char)*p;
  }
  return acc;
}

int main(void) {
  char buf[32];
  // Build "taokari-secret|FX" at runtime to mix runtime and literal paths.
  strncpy(buf, secret, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  size_t len = strlen(buf);
  buf[len] = '|';
  buf[len + 1] = '\0';
  strncat(buf, tag, sizeof(buf) - strlen(buf) - 1);

  int combined = score(buf);          // hash of "taokari-secret|FX"
  int plain    = score("plaintext");  // hash of literal passed directly
  printf("strings:%s:%d:%d\n", tag, combined, plain);
  return 0;
}
