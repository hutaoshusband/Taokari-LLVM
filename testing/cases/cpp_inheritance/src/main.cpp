// Inheritance & polymorphism fixture.
// Builds on cpp_virtual with the harder surfaces: multiple inheritance, an
// abstract base class with pure virtuals, virtual destructors, final
// overrides, a diamond with virtual inheritance, and a polymorphic container
// dispatched in a loop. The vtable loads, the virtual this-adjustment
// thunks, and the RTTI/type descriptors are exactly what IndirectCall and
// MicrosoftRTTIEraser rewrite.
//
// Target: IndirectCall on every virtual call, vtable offset encryption, the
// this-adjustment thunk ABI under multiple + virtual inheritance, and RTTI
// erasure without breaking throw/catch by base pointer.
#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

struct Animal {
  explicit Animal(int id) : id_(id) {}
  virtual int sound(int scale) const = 0;
  virtual int legs() const { return 0; }
  virtual ~Animal() = default;
  int id_;
};

struct Mammal : virtual Animal {
  Mammal(int id, int w) : Animal(id), weight_(w) {}
  int legs() const override { return 4; }
  int weight_;
};

struct Bird : virtual Animal {
  Bird(int id, int ws) : Animal(id), wingspan_(ws) {}
  int legs() const override { return 2; }
  int wingspan_;
};

// Multiple inheritance from two virtual bases: the classic diamond.
struct Platypus : Mammal, Bird {
  Platypus(int id, int w, int ws)
      : Animal(id), Mammal(id, w), Bird(id, ws) {}
  int sound(int scale) const override { return (weight_ + wingspan_) * scale; }
  // Diamond makes legs() ambiguous: resolve explicitly.
  int legs() const override { return Mammal::legs(); }
};

struct Bat : Mammal {
  Bat(int id, int w) : Animal(id), Mammal(id, w) {}
  int sound(int scale) const override { return weight_ * 7 * scale; }
};

__declspec(noinline) int total_sound(const std::vector<const Animal *> &zoo, int scale) {
  int total = 0;
  for (const Animal *a : zoo) {
    total += a->sound(scale) + a->legs() + a->id_;
  }
  return total;
}

int main() {
  Platypus p(11, 30, 12);   // sound = (30+12)*scale = 42*scale, legs=4
  Bat b(22, 5);              // sound = 5*7*scale = 35*scale, legs=4

  std::vector<const Animal *> zoo;
  zoo.push_back(&p);
  zoo.push_back(&b);
  int t = total_sound(zoo, 3);  // (42*3+4+11) + (35*3+4+22) = 141 + 131 = 272

  // Polymorphic delete through base via unique_ptr exercises the virtual dtor
  // path and the thunk cleanup, which is a common place to break ABI.
  std::unique_ptr<Animal> owned = std::make_unique<Bat>(99, 10);
  int owned_sound = owned->sound(2);  // 10*7*2 = 140

  // catch-by-base requires intact RTTI even after the eraser runs.
  int caught = 0;
  try {
    throw Platypus(7, 1, 1);
  } catch (const Animal &a) {
    caught = a.id_;  // 7
  }

  std::printf("inherit:%d:%d:%d\n", t, owned_sound, caught);
  return 0;
}
