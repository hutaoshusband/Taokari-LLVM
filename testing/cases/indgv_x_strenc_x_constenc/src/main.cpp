// Cross-pass fixture: IndirectGlobalVariable + StringEncryption +
// ConstantIntegerEncryption. The same function uses an encrypted
// string, an encrypted integer constant, and an indirected mutable
// global, exercising all three passes at once. Output is
// deterministic and identical across optimisation modes.
#include <cstdint>
#include <cstdio>

static const char *kSecret = "taokari-xpass-secret";
int g_state = 100;
static const int64_t kMagic = 0xABCDEF1234567890LL;

__declspec(noinline) int64_t use_all(int n) {
  g_state += n;
  int64_t v = kMagic ^ static_cast<int64_t>(n);
  std::printf("xpass:%s:%lld:%d\n", kSecret,
              static_cast<long long>(v), g_state);
  return v;
}

int main() {
  int64_t a = use_all(7);
  int64_t b = use_all(11);
  std::printf("xpass-done:%lld:%lld\n", static_cast<long long>(a),
              static_cast<long long>(b));
  return 0;
}
