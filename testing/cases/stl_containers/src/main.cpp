// STL containers & algorithms fixture.
// Exercises std::vector, std::list, std::deque, std::map, std::unordered_map,
// std::set; forward/reverse iterators; std::sort, std::accumulate,
// std::transform, std::copy, std::find, std::count_if; lambdas with capture;
// range-for; and auto. Containers exercise allocator-backed heap growth
// (IndirectGlobalVariable on the allocator state) and the inlined comparison
// functors are a big ConstantInt/MBA surface that must fold identically.
//
// Target: allocator-backed container growth, iterator invalidation safety,
// and std::* algorithm inlining under -O2/LTO/clang-cl.
#include <algorithm>
#include <deque>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <list>
#include <map>
#include <numeric>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

__declspec(noinline) int vector_ops() {
  std::vector<int> v{5, 3, 8, 1, 9, 2, 7, 4, 6, 0};
  std::sort(v.begin(), v.end());
  int sum = std::accumulate(v.begin(), v.end(), 0);          // 45
  std::transform(v.begin(), v.end(), v.begin(),
                 [](int x) { return x * x; });
  int sq_sum = std::accumulate(v.begin(), v.end(), 0);       // sum of squares 0..9 = 285
  int found_idx = -1;
  auto it = std::find(v.begin(), v.end(), 49);               // 7*7 = 49 present
  if (it != v.end()) found_idx = static_cast<int>(it - v.begin());
  int count_big = static_cast<int>(std::count_if(v.begin(), v.end(),
                                                  [](int x) { return x > 25; }));
  return sum * 1000 + sq_sum + found_idx * 10 + count_big;   // 45000 + 285 + 70 + 4
}

__declspec(noinline) int list_ops() {
  std::list<int> l{1, 2, 3, 4, 5};
  l.push_front(0);
  l.push_back(6);
  l.reverse();
  int forward = 0, reverse = 0, idx = 0;
  for (auto it = l.begin(); it != l.end(); ++it, ++idx) {
    if (idx < 3) forward = forward * 10 + *it;   // first 3 forward
  }
  for (auto rit = l.rbegin(); rit != l.rend(); ++rit) {
    reverse = reverse * 10 + *rit;              // all reversed
  }
  l.remove_if([](int x) { return x % 2 == 0; });
  int odd_sum = std::accumulate(l.begin(), l.end(), 0);
  return forward * 10000 + reverse + odd_sum;
}

__declspec(noinline) int map_ops() {
  std::map<std::string, int> m;
  m["alpha"] = 1;
  m["beta"] = 2;
  m["gamma"] = 3;
  m["delta"] = 4;
  int ordered_sum = 0;
  for (const auto &kv : m) ordered_sum += kv.second;   // ordered: 1+2+3+4=10
  // Replace keys to force rebalance.
  m["alpha"] = 10;
  m.erase("beta");
  int after = m["alpha"] + m["gamma"] + m["delta"];     // 10+3+4 = 17
  return ordered_sum * 1000 + after;
}

__declspec(noinline) int unordered_ops() {
  std::unordered_map<int, int> um;
  for (int i = 1; i <= 20; ++i) um[i] = i * i;
  int sum_vals = 0;
  for (const auto &kv : um) sum_vals += kv.second;     // sum of squares 1..20 = 2870
  int hit = um.count(15) ? um[15] : 0;                 // 225
  int miss = um.count(99) ? 1 : 0;
  return sum_vals + hit * 10 + miss;
}

__declspec(noinline) int set_deque_ops() {
  std::set<int> s{7, 2, 9, 1, 5, 3};
  s.insert(4);
  s.insert(2);  // dup, ignored
  int set_sum = std::accumulate(s.begin(), s.end(), 0);   // 1+2+3+4+5+7+9 = 31
  int set_count = static_cast<int>(s.size());             // 7

  std::deque<int> dq;
  for (int i = 0; i < 6; ++i) {
    if (i & 1) dq.push_back(i * 10);
    else dq.push_front(i * 10);
  }
  int dq_front = dq.front();
  int dq_back = dq.back();
  return set_sum * 10000 + set_count * 1000 + dq_front * 10 + dq_back;
}

int main() {
  int r1 = vector_ops();
  int r2 = list_ops();
  int r3 = map_ops();
  int r4 = unordered_ops();
  int r5 = set_deque_ops();
  std::printf("stl:%d:%d:%d:%d:%d\n", r1, r2, r3, r4, r5);
  return 0;
}
