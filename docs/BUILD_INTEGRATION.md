# Taokari Build Integration

How to wire Taokari into real projects: CMake, Ninja, Visual Studio, the
blanket `.bat` recipes, and `+vmp` / `-vmp` annotation examples.

Taokari is driven entirely through clang `-mllvm -taokari*` flags and a JSON
config (`-mllvm -taokari-cfg=<path>`). There is no separate plugin to load:
the obfuscator is built into the Taokari clang at
`build/taokari-local/bin/clang.exe` (Windows) or `build/taokari-linux/bin/clang`
(Linux). Use that clang as your project's C/C++ compiler and add the
`-mllvm` flags.

## CMake

Point your project at the Taokari clang and pass the obfuscation flags
through `CMAKE_C_FLAGS` / `CMAKE_CXX_FLAGS`. For a blanket recipe, drive it
from a JSON config:

```cmake
# example: enable the "balanced" profile across the whole project
set(TAOKARI_CLANG "C:/path/to/Taokari-LLVM/build/taokari-local/bin/clang.exe")
set(TAOKARI_CFG   "C:/path/to/Taokari-LLVM/testing/configs/profile-balanced.json")
set(CMAKE_C_COMPILER   ${TAOKARI_CLANG})
set(CMAKE_CXX_COMPILER ${TAOKARI_CLANG})
add_compile_options(
  -O2
  -mllvm -taokari
  -mllvm -taokari-cfg=${TAOKARI_CFG}
)
```

For per-target control, scope the flags:

```cmake
target_compile_options(my_sensitive_lib PRIVATE
  -mllvm -taokari -mllvm -taokari-fla -mllvm -taokari-bcf -mllvm -taokari-mba
)
```

## Ninja

The Taokari build itself uses Ninja. To consume Taokari in a Ninja project,
set the compiler to the Taokari clang and add the flags to your `build.ninja`
rule (or `CMAKE_NINJA_FORCE_RESPONSE_FILE`):

```ninja
rule obf_cc
  command = C:/path/to/clang.exe $FLAGS -c $in -o $out
build out.obj: obf_cc src.c
  FLAGS = -O2 -mllvm -taokari -mllvm -taokari-fla -mllvm -taokari-bcf
```

## Visual Studio

In a VS project, set **Configuration Properties → General → Platform
Toolset** to use the Taokari clang (`LLVM (clang-cl)` toolset pointing at the
Taokari build), then add the `-mllvm -taokari*` flags under **C/C++ →
Command Line → Additional Options**. `clang-cl` accepts the same `-mllvm`
flags as the GNU-driver clang.

## Blanket recipes (Windows)

Two reference `.bat` recipes ship in the repo root:

| Script | Tier | What it does |
| --- | --- | --- |
| `build_strong.bat` | B | Strong blanket: every cheap IR pass globally (fla L4, bcf L2 around the flattening, mba, cie/cfe, cse, icall, indbr, indgv, meta L3, MIR fortress) + NativeIntegrity. No global VMP. Recommended "noisy in IDA without VM cost" default. |
| `build_max_protection.bat` | C | Strong blanket + VMP "spear" on annotated functions (one `+vmp` demo). Grow toward Tier D by annotating more functions and raising `-taokari-vmp-max-bytecode-words`. |

`build_fortress.bat` is **not** a separate script: "Fortress" is the Tier D
shape — `build_max_protection.bat` with more `+vmp` annotations and higher
per-function VMP budgets. Use `profile-fortress.json` (via `-taokari-cfg`)
for the all-on config. Each script enforces compile-time + size budget caps
and refuses runaway functions, so they cannot freeze the engine.

## `+vmp` / `-vmp` annotation examples

VMP virtualization is opt-in **per function** via `__attribute__((annotate(...)))`:

```c
// Virtualize this function only (the "vmp-spear" pattern):
__attribute__((noinline, annotate("+vmp")))
int verify_license(const char *key) {
  /* sensitive code -> bytecode VM */
  return check(key);
}

// Force a function to NOT be virtualized even under a global -taokari-vmp:
__attribute__((noinline, annotate("-vmp")))
int fast_path(int x) { return x + 1; }

// Set a per-function VMP bytecode-word budget override:
__attribute__((noinline, annotate("+vmp ^vmp=8192")))
int big_secret(int x) { /* ... */ }
```

Combine with `-mllvm -taokari -mllvm -taokari-vmp` (or
`profile-vmp-spear.json`) so the VM is armed but only `+vmp`-annotated
functions are virtualized.

See `docs/CONFIGURATION.md` for the full flag reference and the
`testing/configs/profile-*.json` files for ready-made profiles.
