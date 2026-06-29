#include <cstdio>
#include <cstdint>

struct Shape {
  virtual int area(int scale) const = 0;
  virtual ~Shape() {}
};

struct Square : Shape {
  int side;
  explicit Square(int s) : side(s) {}
  int area(int scale) const override { return side * side * scale; }
};

struct Triangle : Shape {
  int base, height;
  Triangle(int b, int h) : base(b), height(h) {}
  int area(int scale) const override { return (base * height * scale) / 2; }
};

struct Circle : Shape {
  int radius;
  explicit Circle(int r) : radius(r) {}
  int area(int scale) const override { return (3 * radius * radius * scale) / 7; }
};

static int total_area(const Shape *shapes[], int n, int scale) {
  int acc = 0;
  for (int i = 0; i < n; ++i)
    acc += shapes[i]->area(scale);
  return acc;
}

int main() {
  Square sq(4);
  Triangle tri(6, 5);
  Circle cir(3);
  const Shape *shapes[] = {&sq, &tri, &cir};
  int a1 = sq.area(2);
  int a2 = tri.area(3);
  int a3 = cir.area(4);
  int sum = total_area(shapes, 3, 5);
  printf("vdispatch:%d:%d:%d:%d\n", a1, a2, a3, sum);
  return 0;
}
