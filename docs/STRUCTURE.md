# Repository Structure

```text
Taokari-LLVM/
  README.md
  NOTICE.md
  docs/
  scripts/
  upstream/
    taokari/
      llvm/
      clang/
      lld/
      lldb/
      compiler-rt/
      openmp/
      ...
  build/
    taokari-ninja/
```

`upstream/taokari` intentionally preserves LLVM's monorepo layout. Moving `llvm`,
`clang`, `lld`, or `compiler-rt` into custom folders would break CMake assumptions
and make future merges painful.

`build/taokari-ninja` intentionally preserves Arkari's generated Ninja cache and
object files. It still contains generated references to `C:\Arkari`; use it as a
fast cache, not as clean source truth.

The copied cache is ignored by git because it is several GB and machine-specific.
