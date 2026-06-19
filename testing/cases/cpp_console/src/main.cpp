#include <iostream>
#include <numeric>
#include <vector>

int main() {
  std::vector<int> values{3, 5, 8, 13, 21};
  int sum = std::accumulate(values.begin(), values.end(), 0);
  std::cout << "cpp-console:" << (sum * 3 - 6) << "\n";
  return 0;
}
