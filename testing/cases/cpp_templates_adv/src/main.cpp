// Advanced templates fixture.
// Builds on cpp_templates with the harder surfaces: full + partial
// specialisations, a non-type parameter, a variadic template, a CRTP base,
// and a generic Matrix<T> with operator overloads. Each instantiation
// produces its own IR function that the obfuscator must keep value-stable.
//
// Target: every instantiation produces a distinct IR function exercised by
// ConstantIntEncryption / MBA / IndirectCall; variadic expansion and CRTP
// devirtualisation must survive -O2/LTO folding.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

// Primary template + full specialisation + partial specialisation.
template <typename T>
struct Traits { static constexpr int kind = 0; };
template <>
struct Traits<int> { static constexpr int kind = 1; };
template <typename T>
struct Traits<T *> { static constexpr int kind = 2; };

// Non-type parameter.
template <auto Tag>
struct Tagged { static constexpr int value = static_cast<int>(Tag); };

// Variadic sum.
template <typename T>
T vsum(T first) { return first; }
template <typename T, typename... Rest>
T vsum(T first, Rest... rest) { return first + vsum(rest...); }

// CRTP base: the derived type is a template parameter so the compiler can
// devirtualise, which is a path the obfuscator can break by inserting an
// indirect call where a direct one was expected.
template <typename Derived>
struct Counter {
  int bump() { return ++static_cast<Derived *>(this)->count_; }
};

struct Widget : Counter<Widget> { int count_ = 0; };

// Generic Matrix<T> with operator+ and operator[].
template <typename T, std::size_t N>
struct Matrix {
  std::array<T, N> data{};
  T &operator[](std::size_t i) { return data[i]; }
  const T &operator[](std::size_t i) const { return data[i]; }
  Matrix operator+(const Matrix &other) const {
    Matrix out;
    for (std::size_t i = 0; i < N; ++i) out.data[i] = data[i] + other.data[i];
    return out;
  }
  T trace() const {
    T t = 0;
    for (std::size_t i = 0; i < N; ++i) t += data[i] * static_cast<T>(i + 1);
    return t;
  }
};

template <typename T>
__declspec(noinline) void bubble_sort(T *arr, std::size_t n) {
  for (std::size_t i = 0; i + 1 < n; ++i) {
    for (std::size_t j = 0; j + 1 < n - i; ++j) {
      if (arr[j] > arr[j + 1]) {
        T tmp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = tmp;
      }
    }
  }
}

int main() {
  int kinds = Traits<int>::kind + Traits<int *>::kind + Traits<double>::kind;  // 1+2+0
  int tag = Tagged<42>::value;        // 42
  int vs = vsum(1, 2, 3, 4, 5);       // 15

  Widget w;
  int bumps = w.bump() + w.bump() + w.bump();  // 1+2+3 = 6

  Matrix<int, 4> m{};
  for (int i = 0; i < 4; ++i) m[i] = i * 2 + 1;  // 1 3 5 7
  Matrix<int, 4> n{};
  for (int i = 0; i < 4; ++i) n[i] = i;           // 0 1 2 3
  Matrix<int, 4> sum = m + n;                     // 1 4 7 10
  int trace = sum.trace();                         // 1*1 + 4*2 + 7*3 + 10*4 = 68

  int arr[] = {5, 2, 8, 1, 9, 3, 7, 4, 6, 0};
  bubble_sort<int>(arr, 10);
  int sorted_hash = 0;
  for (int i = 0; i < 10; ++i) sorted_hash = sorted_hash * 31 + arr[i];

  std::printf("templates-adv:%d:%d:%d:%d:%d:%d\n",
              kinds, tag, vs, bumps, trace, sorted_hash);
  return 0;
}
