#include <cstdio>
#include <cstdint>
#include <thread>
#include <vector>

static thread_local int tl_counter = 0;
static thread_local int tl_buffer[8];
static thread_local const char *tl_label = "seed";

static int bump_local(int n) {
  for (int i = 0; i < n; ++i)
    tl_counter += i + 1;
  return tl_counter;
}

static int fill_buffer(int seed) {
  for (int i = 0; i < 8; ++i)
    tl_buffer[i] = (seed + i) ^ (i * 3);
  int s = 0;
  for (int i = 0; i < 8; ++i)
    s += tl_buffer[i];
  return s;
}

static int label_hash() {
  int h = 7;
  for (const char *p = tl_label; *p; ++p)
    h = h * 31 + *p;
  return h;
}

static void worker(int id, int rounds, int *out) {
  bump_local(rounds);
  int fb = fill_buffer(id);
  out[id] = tl_counter + fb + label_hash();
}

int main() {
  int base = bump_local(4);
  int fb = fill_buffer(2);
  int lh = label_hash();

  const int N = 3;
  std::vector<int> results(N, 0);
  std::vector<std::thread> threads;
  for (int i = 0; i < N; ++i)
    threads.emplace_back(worker, i, 5 + i, results.data());
  for (auto &t : threads)
    t.join();

  int sum = 0;
  for (int i = 0; i < N; ++i)
    sum += results[i];

  printf("tls:%d:%d:%d:%d\n", base, fb, lh, sum);
  return 0;
}
