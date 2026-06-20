# PDB Hygiene

`-taokari-meta -taokari-level-meta=3` strips IR debug metadata, source-path
metadata, `llvm.ident`, `llvm.commandline`, and internal helper names before
object emission. It does not edit a PDB after the linker writes one.

For release builds that must not leak paths or type names:

- do not pass `-g`, `/Zi`, `/ZI`, or `/DEBUG`;
- do not ship generated `.pdb` files;
- use `/DEBUG:NONE` when a build system adds debug link flags by default;
- keep `-taokari-rtti` plus a `randomSeed` enabled when MSVC RTTI type names
  matter.

If PDBs are required for private crash triage, store them outside the shipped
artifact set and treat them as sensitive build output.
