# Taokari Obfuscation Tests

Run:

```powershell
python testing\run_obfuscation_tests.py --keep-going
```

Each case owns:

- `src/` - checked-in test source
- `obj/` - generated object files, git-ignored
- `build/` - generated executable, git-ignored

The ImGui test uses the vendored source in `testing/vendor/imgui`.
