#include <iostream>
#include <string>

class Mixer {
public:
  explicit Mixer(int seed) : seed_(seed) {}

  int mix(int value) const {
    int x = value ^ seed_;
    return (x * 5) - (seed_ / 2);
  }

private:
  int seed_;
};

int main() {
  Mixer mixer(42);
  std::string name = "tao";
  name += "kari";
  std::cout << "classes:" << mixer.mix(55) << ":" << name << "\n";
  return 0;
}
