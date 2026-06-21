// Dynamic memory management fixture.
// Exercises scalar new/delete, array new[]/delete[], malloc/free, placement
// new, std::unique_ptr with a custom deleter, std::shared_ptr reference
// counting across copies, and std::weak_ptr expiry. Smart-pointer control
// blocks live on the heap and are addressed indirectly, which interacts with
// IndirectGlobalVariable; the refcount inc/dec is a hot MBA/ConstantInt
// surface that must stay atomic-correct.
//
// Target: new/delete lowering, IndirectGlobalVariable on the control block,
// ConstantIntEncryption/MA on the refcount arithmetic, and absence of double
// free / leak under -O2/LTO folding.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>

static int g_dtors = 0;

struct Tracker {
  int value;
  Tracker() : value(0) {}
  explicit Tracker(int v) : value(v) {}
  ~Tracker() { ++g_dtors; }
};

__declspec(noinline) int scalar_new_delete() {
  Tracker *t = new Tracker(11);
  int v = t->value;
  delete t;
  return v;
}

__declspec(noinline) int array_new_delete() {
  Tracker *arr = new Tracker[5];
  for (int i = 0; i < 5; ++i) arr[i] = Tracker(i + 1);
  int sum = 0;
  for (int i = 0; i < 5; ++i) sum += arr[i].value;
  delete[] arr;
  return sum;
}

__declspec(noinline) int malloc_free_path() {
  int *p = static_cast<int *>(malloc(sizeof(int) * 4));
  if (!p) return -1;
  for (int i = 0; i < 4; ++i) p[i] = (i + 1) * (i + 1);  // 1 4 9 16
  int sum = p[0] + p[1] + p[2] + p[3];
  free(p);
  return sum;
}

__declspec(noinline) int placement_new_path() {
  alignas(Tracker) unsigned char buf[sizeof(Tracker)];
  Tracker *t = new (buf) Tracker(42);
  int v = t->value;
  t->~Tracker();
  return v;
}

struct FileCloser {
  void operator()(int *h) const {
    if (h) *h = -1;  // mimic close()
  }
};

__declspec(noinline) int unique_custom_deleter() {
  std::unique_ptr<int, FileCloser> handle(new int(77));
  int v = *handle;
  return v;  // dtor runs FileCloser, sets the int to -1 (leak by design here)
}

__declspec(noinline) int shared_refcount() {
  auto sp1 = std::make_shared<Tracker>(99);
  std::shared_ptr<Tracker> sp2 = sp1;  // refcount 2
  std::shared_ptr<Tracker> sp3 = sp1;  // refcount 3
  int use = sp1.use_count();           // 3
  sp3.reset();                          // refcount 2
  int use2 = sp2.use_count();          // 2
  int value = sp1->value;              // 99
  return use * 1000 + use2 * 10 + value;  // 3020 + 99 = 3119? use=3 -> 3000+20+99=3119
}

__declspec(noinline) int weak_ptr_expiry() {
  auto sp = std::make_shared<Tracker>(5);
  std::weak_ptr<Tracker> wp = sp;
  int before = wp.use_count();  // 1
  int locked_ok = !wp.expired();
  sp.reset();
  int after = wp.use_count();   // 0
  int expired = wp.expired();   // 1
  return before * 1000 + locked_ok * 100 + after * 10 + expired;  // 1100 + 0 + 1 = 1101
}

int main() {
  int before_dtors = g_dtors;
  int r1 = scalar_new_delete();      // 11, +1 dtor
  int r2 = array_new_delete();       // 15, +5 dtors
  int r3 = malloc_free_path();       // 30
  int r4 = placement_new_path();     // 42, +1 dtor
  int r5 = unique_custom_deleter();  // 77
  int r6 = shared_refcount();        // 3119, +1 dtor
  int r7 = weak_ptr_expiry();        // 1101, +1 dtor
  int dtors = g_dtors - before_dtors;  // 1+5+1+1+1 = 9
  std::printf("dynmem:%d:%d:%d:%d:%d:%d:%d:%d\n",
              r1, r2, r3, r4, r5, r6, r7, dtors);
  return 0;
}
