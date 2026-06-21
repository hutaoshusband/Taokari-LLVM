// File & stream I/O fixture.
// Exercises std::ofstream, std::ifstream, std::fstream in text and binary
// modes; ios::out / ios::app / ios::binary; seekg / seekp; hex/oct formatting;
// and the file lifecycle (open/write/close/reopen). File paths are passed via
// argv so the test writes to a temp dir and the output is deterministic
// regardless of where the binary runs.
//
// Target: stream object lifetimes, the vtable-backed iostream path
// (IndirectCall), and the std::hex / std::oct format manipulator constants
// which feed ConstantIntEncryption.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace {

std::string tmp_path(const char *suffix) {
  const char *dir = std::getenv("TAOKARI_TMP");
  std::string base = dir ? dir : std::string(std::getenv("TEMP") ? std::getenv("TEMP") : ".");
  return base + std::string("\\taokari_io_") + suffix + ".dat";
}

__declspec(noinline) int write_text(const std::string &path) {
  std::ofstream out(path, std::ios::out | std::ios::trunc);
  if (!out) return -1;
  for (int i = 1; i <= 5; ++i) out << i << ' ' << (i * i) << '\n';
  out.close();
  return 0;
}

__declspec(noinline) int append_text(const std::string &path) {
  std::ofstream out(path, std::ios::out | std::ios::app);
  if (!out) return -1;
  out << 6 << ' ' << 36 << '\n';
  out << 7 << ' ' << 49 << '\n';
  return 0;
}

__declspec(noinline) int read_text_sum(const std::string &path) {
  std::ifstream in(path);
  if (!in) return -1;
  int sum = 0, a, b;
  while (in >> a >> b) sum += a + b;
  return sum;
}

__declspec(noinline) int binary_round_trip(const std::string &path) {
  {
    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out) return -1;
    int32_t vals[] = {10, 20, 30, 40, 50};
    out.write(reinterpret_cast<const char *>(vals), sizeof(vals));
  }
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) return -1;
  int32_t got[5] = {0};
  in.read(reinterpret_cast<char *>(got), sizeof(got));
  int sum = 0;
  for (int v : got) sum += v;
  return sum;  // 150
}

__declspec(noinline) int seek_test(const std::string &path) {
  std::fstream io(path,
                  std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc);
  if (!io) return -1;
  for (int i = 0; i < 8; ++i) {
    int32_t v = (i + 1) * 100;
    io.write(reinterpret_cast<const char *>(&v), sizeof(v));
  }
  // Read the 4th int32 via seekg.
  io.seekg(3 * sizeof(int32_t), std::ios::beg);
  int32_t fourth = 0;
  io.read(reinterpret_cast<char *>(&fourth), sizeof(fourth));
  // Overwrite the 2nd via seekp.
  io.seekp(1 * sizeof(int32_t), std::ios::beg);
  int32_t replacement = 999;
  io.write(reinterpret_cast<const char *>(&replacement), sizeof(replacement));
  io.flush();
  // Re-read everything and sum.
  io.seekg(0, std::ios::beg);
  int sum = 0;
  for (int i = 0; i < 8; ++i) {
    int32_t v = 0;
    io.read(reinterpret_cast<char *>(&v), sizeof(v));
    sum += v;
  }
  return sum * 1000 + fourth;  // 4th was 400 -> ... * 1000 + 400
}

__declspec(noinline) std::string format_test() {
  std::ostringstream os;
  os << std::hex << std::showbase << 255 << ' '            // 0xff
     << std::oct << 64 << ' '                              // 100
     << std::dec << std::setw(5) << std::setfill('0') << 42;  // 00042
  return os.str();
}

}  // namespace

int main() {
  std::string tp = tmp_path("text");
  std::string bp = tmp_path("bin");
  write_text(tp);
  append_text(tp);
  int text_sum = read_text_sum(tp);  // (1+1)+(2+4)+...+(7+49) = 175
  int bin_sum = binary_round_trip(bp);
  int seek = seek_test(bp);
  std::string fmt = format_test();

  // Clean up.
  std::remove(tp.c_str());
  std::remove(bp.c_str());

  std::printf("io:%d:%d:%d:%s\n", text_sum, bin_sum, seek, fmt.c_str());
  return 0;
}
