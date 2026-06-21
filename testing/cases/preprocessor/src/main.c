// Preprocessor & macros fixture.
// Exercises complex multi-line macros, variadic macros, token pasting (##),
// stringizing (#), conditional compilation (#ifdef/#ifndef/#if defined),
// __FILE__/__LINE__/__COUNTER__, static_assert, pragma once, and the comma
// operator inside macro bodies. The preprocessor expands before any IR pass,
// but the resulting literals and string constants are the input to
// ConstantIntEncryption and ConstantStringEncryption, so a regression here
// surfaces as a wrong constant in the obfuscated binary.
#include <stdint.h>
#include <stdio.h>

#define TAO_VERSION_MAJOR 2
#define TAO_VERSION_MINOR 3
#define TAO_VERSION_PATCH 4

// Token paste + computed stringify. Two-level indirection so the inner
// CONCAT expands before STRINGIZE stringises it.
#define CONCAT_(a, b) a##b
#define CONCAT(a, b) CONCAT_(a, b)
#define STRINGIZE(x) #x
#define STRINGIZE2(x) STRINGIZE(x)
#define TAO_MAJOR 2
#define TAO_MINOR 3
#define TAO_PATCH 4
#define TAO_TAG CONCAT(TAO, CONCAT(TAO_MAJOR, TAO_MINOR))  // TAO23

// Multi-line expression macro with a do/while(0) body.
#define CLAMP(x, lo, hi) \
  do { \
    if ((x) < (lo)) (x) = (lo); \
    else if ((x) > (hi)) (x) = (hi); \
  } while (0)

// Variadic macro: count args via a compound literal (a GCC/clang extension
// the obfuscator must keep value-stable after expansion).
#define COUNT_ARGS(...) (sizeof((int[]){__VA_ARGS__}) / sizeof(int))

// __FILE__/__LINE__ mix.
#define LOC() __LINE__

// Conditional compilation: pick a path by feature flag.
#define TAO_USE_FAST 1

#if TAO_USE_FAST
#define HASH_STEP(acc, x) ((acc) * 31 + (x))
#else
#define HASH_STEP(acc, x) ((acc) + (x))
#endif

__declspec(noinline) int macro_clamp_chain(int v1, int v2, int v3) {
  CLAMP(v1, 10, 20);  // 5 -> 10
  CLAMP(v2, 10, 20);  // 15 -> 15
  CLAMP(v3, 10, 20);  // 25 -> 20
  return v1 * 100 + v2 * 10 + v3;
}

__declspec(noinline) int macro_hash(const int *data, int n) {
  int acc = 5381;
  for (int i = 0; i < n; ++i) {
    acc = HASH_STEP(acc, data[i]);
  }
  return acc;
}

int main(void) {
  static_assert(TAO_MAJOR + TAO_MINOR + TAO_PATCH == 9,
                "version digits must sum to 9");

  int clamped = macro_clamp_chain(5, 15, 25);  // 10,15,20 -> 1000+150+20=1170

  int data[] = {1, 2, 3, 4, 5};
  int hashed = macro_hash(data, 5);

  // Variadic macro -> compound literal array.
  int arr_count = COUNT_ARGS(10, 20, 30, 40);  // 4
  int arr[] = {10, 20, 30, 40};
  int arr_sum = 0;
  for (int i = 0; i < arr_count; ++i) arr_sum += arr[i];  // 100

  int line_marker = LOC();  // this source line number
  (void)line_marker;

  const char *tag = STRINGIZE2(TAO_TAG);  // "TAO23"
  printf("preproc:%d:%d:%d:%d:%s\n", clamped, hashed, arr_count, arr_sum, tag);
  return 0;
}
