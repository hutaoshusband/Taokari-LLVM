// Exceptions & RAII fixture.
// Builds on cpp_funclet with the harder surfaces: standard + custom
// exceptions, multiple catch clauses (catch order matters), nested
// exceptions via std::throw_with_nested, RAII destructors that must run
// during stack unwinding, noexcept functions that terminate on throw, and
// exception_ptr capture/rethrow. The C++ exception runtime lowers to
// funclets on Windows/x64, which is a fragile path for control-flow
// obfuscation (funclets share state with the parent frame via the
// frame-info packet).
//
// Target: Flattening + BCF must not break the funclet unwind tables, RAII
// destructor order during unwind, and the std::exception_ptr ABI.
#include <cstdint>
#include <cstdio>
#include <exception>
#include <stdexcept>
#include <string>

class Resource {
 public:
  explicit Resource(int *counter) : counter_(counter) {}
  ~Resource() { if (counter_) *counter_ += 100; }
  Resource(const Resource &) = delete;
  Resource &operator=(const Resource &) = delete;
 private:
  int *counter_;
};

class AppError : public std::runtime_error {
 public:
  explicit AppError(const std::string &msg, int code)
      : std::runtime_error(msg), code_(code) {}
  int code() const noexcept { return code_; }
 private:
  int code_;
};

__declspec(noinline) int multi_catch(int sel) {
  int released = 0;
  try {
    Resource r(&released);  // dtor adds 100 on any unwind
    switch (sel) {
    case 0: throw std::logic_error("logic");        // caught by logic_error
    case 1: throw std::runtime_error("runtime");    // caught by runtime_error
    case 2: throw AppError("app", 42);              // caught by AppError
    case 3: throw 7;                                // caught by catch(...)
    default: break;                                  // no throw
    }
  } catch (const AppError &e) {
    return released + 1000 + e.code();
  } catch (const std::logic_error &) {
    return released + 2000;
  } catch (const std::runtime_error &) {
    return released + 3000;
  } catch (...) {
    return released + 4000;
  }
  return released;
}

__declspec(noinline) int nested_throw(int sel) {
  try {
    if (sel == 0) {
      try {
        throw std::runtime_error("inner");
      } catch (...) {
        std::throw_with_nested(AppError("outer", 5));
      }
    } else {
      throw std::runtime_error("plain");
    }
  } catch (const AppError &e) {
    // The nested inner exception lives on the caught AppError.
    try {
      std::rethrow_if_nested(e);
    } catch (const std::runtime_error &) {
      return 100 + e.code();  // 105
    }
  } catch (const std::runtime_error &) {
    return 200;
  }
  return 0;
}

// noexcept that calls a throwing function: must call std::terminate unless
// we nothrow(...) wrap it. We test the nothrow path only.
__declspec(noinline) int noexcept_safe(int x) noexcept {
  return x * 2 + 1;
}

__declspec(noinline) int via_exception_ptr(int x) {
  std::exception_ptr ep;
  try {
    if (x < 0) throw AppError("neg", x);
  } catch (...) {
    ep = std::current_exception();
  }
  if (ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const AppError &e) {
      return e.code();  // x itself
    }
  }
  return x * 10;
}

int main() {
  int r0 = multi_catch(0);  // 100 + 2000 = 2100
  int r1 = multi_catch(1);  // 100 + 3000 = 3100
  int r2 = multi_catch(2);  // 100 + 1000 + 42 = 1142
  int r3 = multi_catch(3);  // 100 + 4000 = 4100
  int r4 = multi_catch(9);  // 100 (no throw, dtor still ran)
  int n0 = nested_throw(0); // 105
  int n1 = nested_throw(1); // 200
  int s  = noexcept_safe(7); // 15
  int ep = via_exception_ptr(-3); // -3
  int epp = via_exception_ptr(5); // 50
  std::printf("exc:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d\n",
              r0, r1, r2, r3, r4, n0, n1, s, ep, epp);
  return 0;
}
