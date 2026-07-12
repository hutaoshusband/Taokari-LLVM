#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>

static _Atomic int counter = 0;
static _Atomic uint64_t seq = 0;

static int bump(void) {
  return atomic_fetch_add(&counter, 1) + 1;
}

static uint64_t ticket(void) {
  return atomic_fetch_add(&seq, 7);
}

static int cas_loop(int want) {
  int old = atomic_load(&counter);
  while (!atomic_compare_exchange_weak(&counter, &old, want)) {
  }
  return old;
}

static int fence_probe(void) {
  int a = atomic_load(&counter);
  atomic_thread_fence(memory_order_acquire);
  int b = atomic_load(&counter);
  atomic_thread_fence(memory_order_release);
  return a * 2 + b;
}

int main(void) {
  int v0 = bump();
  int v1 = bump();
  uint64_t t0 = ticket();
  uint64_t t1 = ticket();
  int prev = cas_loop(40);
  int fp = fence_probe();
  printf("atomics:%d:%d:%llu:%llu:%d:%d\n",
         v0, v1, (unsigned long long)t0, (unsigned long long)t1, prev, fp);
  return 0;
}
