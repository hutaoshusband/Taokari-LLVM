#include <array>
#include <cstddef>
#include <iostream>

template <typename T, std::size_t N>
T weighted_sum(const std::array<T, N> &values) {
  T total = 0;
  for (std::size_t i = 0; i < N; ++i) {
    total += values[i] * (i + 1);
  }
  return total;
}

int main() {
  std::array<int, 5> ints{1, 2, 3, 4, 5};
  std::array<int, 4> fib{1, 1, 2, 5};
  std::cout << "templates:" << weighted_sum(ints) << ":" << weighted_sum(fib) << "\n";
  return 0;
}
