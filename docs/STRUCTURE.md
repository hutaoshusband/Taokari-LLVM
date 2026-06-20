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
    taokari-local/
```

`upstream/taokari` intentionally preserves LLVM's monorepo layout. Moving `llvm`,
`clang`, `lld`, or `compiler-rt` into custom folders would break CMake assumptions
and make future merges painful.

`build/taokari-local` is generated from `upstream/taokari/llvm`, so source edits
in this repository are the build truth.

The copied cache is ignored by git because it is several GB and machine-specific.
