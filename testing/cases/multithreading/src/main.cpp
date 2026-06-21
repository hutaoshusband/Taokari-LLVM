// Multithreading & synchronisation fixture.
// Exercises std::thread join, std::mutex + std::lock_guard, a producer/consumer
// pair on std::condition_variable, std::async + std::future return values, and
// std::atomic counters. Thread entry-point functions are called indirectly
// through the runtime (CreateThread), and TLS / per-thread stack init are a
// common place for an obfuscator to corrupt ABI. The shared atomic/mutex
// state must stay race-free after obfuscation.
//
// Target: IndirectCall on the thread entry point, mutex lock/unlock ABI,
// condition_variable wait/notify correctness, and atomic ordering on the
// shared counters.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <future>
#include <mutex>
#include <numeric>
#include <thread>
#include <vector>

__declspec(noinline) int worker(int base, int rounds) {
  int acc = base;
  for (int i = 0; i < rounds; ++i) acc = (acc ^ (i + 7)) + (i * 3);
  return acc;
}

__declspec(noinline) int parallel_sum(int n_threads, int rounds) {
  std::vector<std::thread> pool;
  std::vector<int> results(n_threads, 0);
  for (int t = 0; t < n_threads; ++t) {
    pool.emplace_back([&results, t, rounds]() {
      results[t] = worker(t + 1, rounds);
    });
  }
  for (auto &th : pool) th.join();
  return std::accumulate(results.begin(), results.end(), 0);
}

struct Counter {
  std::mutex m;
  int value = 0;
};

__declspec(noinline) int mutex_contention(int n_threads, int per_thread) {
  Counter c;
  std::vector<std::thread> pool;
  for (int t = 0; t < n_threads; ++t) {
    pool.emplace_back([&c, per_thread]() {
      for (int i = 0; i < per_thread; ++i) {
        std::lock_guard<std::mutex> lk(c.m);
        c.value += 1;
      }
    });
  }
  for (auto &th : pool) th.join();
  return c.value;
}

struct Queue {
  std::mutex m;
  std::condition_variable cv;
  std::deque<int> data;
  bool done = false;
};

__declspec(noinline) int producer_consumer(int items) {
  Queue q;
  std::thread producer([&q, items]() {
    for (int i = 0; i < items; ++i) {
      {
        std::lock_guard<std::mutex> lk(q.m);
        q.data.push_back(i * 2 + 1);
      }
      q.cv.notify_one();
    }
    {
      std::lock_guard<std::mutex> lk(q.m);
      q.done = true;
    }
    q.cv.notify_one();
  });
  int sum = 0;
  std::thread consumer([&q, &sum]() {
    for (;;) {
      std::unique_lock<std::mutex> lk(q.m);
      q.cv.wait(lk, [&q]() { return !q.data.empty() || q.done; });
      while (!q.data.empty()) {
        sum += q.data.front();
        q.data.pop_front();
      }
      if (q.done) break;
    }
  });
  producer.join();
  consumer.join();
  return sum;  // sum of (2i+1) for i in 0..items-1
}

__declspec(noinline) int async_future_path(int base) {
  std::vector<std::future<int>> futures;
  for (int i = 0; i < 4; ++i) {
    futures.push_back(std::async(std::launch::async, worker, base + i, 100));
  }
  int total = 0;
  for (auto &f : futures) total += f.get();
  return total;
}

__declspec(noinline) int atomic_path(int n_threads, int per_thread) {
  std::atomic<int> atom{0};
  std::vector<std::thread> pool;
  for (int t = 0; t < n_threads; ++t) {
    pool.emplace_back([&atom, per_thread]() {
      for (int i = 0; i < per_thread; ++i) {
        atom.fetch_add(3, std::memory_order_relaxed);
      }
    });
  }
  for (auto &th : pool) th.join();
  return atom.load();
}

int main() {
  int r1 = parallel_sum(4, 500);
  int r2 = mutex_contention(4, 1000);             // 4000
  int r3 = producer_consumer(100);               // sum(2i+1, i=0..99) = 10000
  int r4 = async_future_path(10);
  int r5 = atomic_path(4, 1000);                  // 4*1000*3 = 12000
  std::printf("thread:%d:%d:%d:%d:%d\n", r1, r2, r3, r4, r5);
  return 0;
}
