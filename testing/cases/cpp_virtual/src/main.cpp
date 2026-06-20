// Virtual dispatch fixture.
// Exercises IndirectCall (vtable load -> virtual call) and ConstantIntEncryption
// on the vtable offsets / return constants. Output is deterministic.
#include <cstdio>

struct Shape {
  explicit Shape(int id) : id_(id) {}
  virtual int area(int scale) const = 0;
  virtual ~Shape() = default;
  int id_;
};

struct Square : Shape {
  explicit Square(int side) : Shape(1), side_(side) {}
  int area(int scale) const override { return side_ * side_ * scale; }
  int side_;
};

struct Rect : Shape {
  Rect(int w, int h) : Shape(2), w_(w), h_(h) {}
  int area(int scale) const override { return w_ * h_ * scale; }
  int w_;
  int h_;
};

__declspec(noinline) int total_area(const Shape *a, const Shape *b, int scale) {
  return a->area(scale) + b->area(scale) + a->id_ + b->id_;
}

int main() {
  Square sq(3);     // area = 9 * scale
  Rect   rc(4, 5);  // area = 20 * scale
  int t = total_area(&sq, &rc, 2);  // 18 + 40 + 1 + 2 = 61
  std::printf("virtual:%d\n", t);
  return 0;
}
