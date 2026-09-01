"""Native-vs-protected UI animation semantics stress verifier."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _taokari_portable as tp


CLANGXX = tp.tool("clang++")

SOURCE = r"""
#include <atomic>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstdio>

#define OBF __attribute__((noinline))

using Byte = std::uint8_t;

struct Animation {
  Byte current;
  Byte from;
  Byte target;
  std::uint64_t start_ms;
  double duration;
};

struct DrawPacket {
  double position[4];
  float color[4];
  std::uint32_t id;
  Byte tag[12];
};

static Animation g_alpha{};
static std::atomic<std::uint64_t> g_now_ms{};
static std::atomic<std::uint32_t> g_updates{};
static std::uint32_t g_trace = 2166136261u;
static std::uint32_t g_frame_trace = 2166136261u;
static std::uint32_t g_packet_trace = 2166136261u;
static std::uint32_t g_exception_trace = 2166136261u;

OBF void record_alpha(Byte value) {
  g_trace = (g_trace ^ value) * 16777619u;
  g_updates.fetch_add(1, std::memory_order_relaxed);
}

static void (*g_sink)(Byte) = record_alpha;

OBF void animate_alpha_to(Byte target, double duration) {
  g_alpha.from = g_alpha.current;
  g_alpha.target = target;
  g_alpha.duration = duration;
  g_alpha.start_ms = g_now_ms.load(std::memory_order_acquire);
}

OBF Byte tick_alpha() {
  const double elapsed =
      (g_now_ms.load(std::memory_order_acquire) - g_alpha.start_ms) / 1000.0;
  double t = g_alpha.duration <= 0.0 ? 1.0 : elapsed / g_alpha.duration;
  if (t < 0.0)
    t = 0.0;
  if (t > 1.0)
    t = 1.0;
  const Byte current = static_cast<Byte>(
      g_alpha.from + (g_alpha.target - g_alpha.from) * t);
  if (current != g_alpha.current) {
    g_sink(current);
    g_alpha.current = current;
  }
  return current;
}

OBF float smooth01(float t) {
  if (t < 0.0f)
    t = 0.0f;
  if (t > 1.0f)
    t = 1.0f;
  return t * t * (3.0f - 2.0f * t);
}

static OBF DrawPacket build_packet(std::uint32_t state, float blend,
                                   float pulse, Byte alpha) {
  DrawPacket packet{};
  for (unsigned i = 0; i < 4; ++i) {
    packet.position[i] =
        static_cast<double>(state ^ (0x9e3779b9u * (i + 1u))) / 65537.0;
    packet.color[i] =
        (i & 1u) ? blend * static_cast<float>(i + 1u)
                 : pulse / static_cast<float>(i + 1u);
  }
  packet.id = state ^ (static_cast<std::uint32_t>(alpha) << 16);
  for (unsigned i = 0; i < 12; ++i)
    packet.tag[i] = static_cast<Byte>((state >> ((i & 3u) * 8u)) + i + alpha);
  return packet;
}

static OBF std::uint32_t consume_packet(DrawPacket packet) {
  std::uint32_t hash = packet.id;
  for (unsigned i = 0; i < 4; ++i) {
    hash = (hash ^ static_cast<std::uint32_t>(packet.position[i])) * 16777619u;
    hash = (hash ^ std::bit_cast<std::uint32_t>(packet.color[i])) * 16777619u;
  }
  for (Byte value : packet.tag)
    hash = (hash ^ value) * 16777619u;
  return hash;
}

static OBF int throw_leaf(int value) {
  if ((value & 31) == 9)
    throw value;
  return value * 17 + 3;
}

static OBF int bridge_throw(int value) {
  return throw_leaf(value) ^ 0x5a5a;
}

OBF std::uint32_t run_frames(std::uint32_t seed) {
  g_alpha = {};
  g_now_ms.store(0, std::memory_order_release);
  g_updates.store(0, std::memory_order_release);
  g_trace = 2166136261u ^ seed;
  g_frame_trace = 2166136261u ^ (seed + 1u);
  g_packet_trace = 2166136261u ^ (seed + 2u);
  g_exception_trace = 2166136261u ^ (seed + 3u);
  std::uint32_t state = seed | 1u;

  animate_alpha_to(255, 0.6);
  for (std::uint32_t frame = 0; frame < 1400; ++frame) {
    state = state * 1664525u + 1013904223u;
    g_now_ms.fetch_add(1u + (state % 33u), std::memory_order_acq_rel);

    if (frame % 53u == 0u) {
      const Byte target = static_cast<Byte>(state >> 24);
      const double durations[] = {0.0, 0.018, 0.18, 0.35, 0.6, 1.25};
      animate_alpha_to(target, durations[(state >> 16) % 6u]);
    }
    if (frame % 211u == 17u)
      animate_alpha_to(static_cast<Byte>(255u - g_alpha.current), 0.18);

    const Byte alpha = tick_alpha();
    const double seconds =
        g_now_ms.load(std::memory_order_relaxed) / 1000.0;
    const float blend = smooth01(static_cast<float>(
        (seconds - static_cast<double>(frame % 7u) * 0.01) / 0.35));
    const float pulse =
        0.5f + 0.5f * static_cast<float>(std::sin(seconds * 5.0));
    const std::uint32_t blend_bits = std::bit_cast<std::uint32_t>(blend);
    const std::uint32_t pulse_bits = std::bit_cast<std::uint32_t>(pulse);
    const DrawPacket packet = build_packet(state, blend, pulse, alpha);
    g_frame_trace = (g_frame_trace ^ alpha ^ blend_bits) * 16777619u;
    g_frame_trace = (g_frame_trace ^ pulse_bits ^ frame) * 16777619u;
    g_packet_trace =
        (g_packet_trace ^ consume_packet(packet)) * 16777619u;
    try {
      g_exception_trace =
          (g_exception_trace ^
           static_cast<std::uint32_t>(
               bridge_throw(static_cast<int>(state & 255u)))) *
          16777619u;
    } catch (int value) {
      g_exception_trace =
          (g_exception_trace ^ static_cast<std::uint32_t>(value) ^
           0xa55aa55au) *
          16777619u;
    }
  }

  return g_trace ^ g_frame_trace ^ g_packet_trace ^ g_exception_trace ^
         g_updates.load(std::memory_order_acquire) ^
         (static_cast<std::uint32_t>(g_alpha.current) << 24);
}

int main(int argc, char **argv) {
  const std::uint32_t seed =
      argc > 1 ? static_cast<std::uint32_t>(std::strtoul(argv[1], nullptr, 0))
               : 1u;
  const auto result = run_frames(seed);
  std::printf(
      "ui-animation:%08x:%08x:%08x:%08x:%08x:%08x:%u:%u\n", seed, result,
      g_trace, g_frame_trace, g_packet_trace, g_exception_trace,
              static_cast<unsigned>(g_alpha.current),
              g_updates.load(std::memory_order_relaxed));
  return 0;
}
"""

PROTECTED_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla",
    "-mllvm", "-taokari-level-fla=4",
    "-mllvm", "-taokari-fla-indirectbr-dispatch",
    "-mllvm", "-taokari-bcf",
    "-mllvm", "-taokari-level-bcf=4",
    "-mllvm", "-taokari-bcf-prob=100",
    "-mllvm", "-taokari-bcf-loops=3",
    "-mllvm", "-taokari-bcf-before-fla",
    "-mllvm", "-taokari-bcf-after-fla",
    "-mllvm", "-taokari-opaq-unfoldable",
    "-mllvm", "-taokari-mba",
    "-mllvm", "-taokari-level-mba=4",
    "-mllvm", "-taokari-mba-prob=100",
    "-mllvm", "-taokari-cse",
    "-mllvm", "-taokari-cie",
    "-mllvm", "-taokari-level-cie=4",
    "-mllvm", "-taokari-cfe",
    "-mllvm", "-taokari-level-cfe=4",
    "-mllvm", "-taokari-icall",
    "-mllvm", "-taokari-level-icall=4",
    "-mllvm", "-taokari-icall-prob=100",
    "-mllvm", "-taokari-icall-func-prob=100",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-level-indbr=4",
    "-mllvm", "-taokari-indgv",
    "-mllvm", "-taokari-level-indgv=4",
    "-mllvm", "-taokari-mir=dirtybytes,junk,sub,split,fakeprologue",
    "-mllvm", "-taokari-mir-dirtybytes-prob=100",
    "-mllvm", "-taokari-mir-junk-prob=100",
    "-mllvm", "-taokari-mir-sub-prob=100",
]

SEEDS = [
    "0",
    "1",
    "7",
    "0x12345678",
    "0x80000000",
    "0xffffffff",
    "0x9e3779b9",
    "0xc001d00d",
]


def compile_exe(
    source: Path,
    output: Path,
    *,
    protected: bool,
) -> subprocess.CompletedProcess[str]:
    command = [str(CLANGXX), str(source), "-std=c++20", "-O3", "-o", str(output)]
    if protected:
        command.extend(PROTECTED_FLAGS)
    return tp.run(command, vs=True)


def main() -> int:
    if not CLANGXX.exists():
        print(f"missing clang++: {CLANGXX}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-ui-animation-") as tmp:
        tmpdir = Path(tmp)
        source = tmpdir / "ui_animation.cpp"
        native = tmpdir / "native.exe"
        protected = tmpdir / "protected.exe"
        source.write_text(SOURCE, encoding="utf-8")

        for output, enabled in ((native, False), (protected, True)):
            result = compile_exe(source, output, protected=enabled)
            if result.returncode:
                sys.stderr.write(result.stdout + result.stderr)
                return 1

        failures = []
        for seed in SEEDS:
            native_run = tp.run([str(native), seed])
            protected_run = tp.run([str(protected), seed])
            if native_run.returncode or protected_run.returncode:
                failures.append(
                    f"{seed}: exit native={native_run.returncode} "
                    f"protected={protected_run.returncode}"
                )
            elif native_run.stdout != protected_run.stdout:
                failures.append(
                    f"{seed}: native={native_run.stdout!r} "
                    f"protected={protected_run.stdout!r}"
                )

        if failures:
            print("ui animation semantics: FAIL", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1

    print(f"ui animation semantics: ok ({len(SEEDS)} seeds)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
