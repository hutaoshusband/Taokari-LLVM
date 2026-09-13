"""String-leak gnarliness bar (todo.md D2).

A release-blocking measurement gate: distinct secret string literals that the
program prints at runtime must NOT survive, in any common byte encoding, into
the shipped obfuscated binary. This turns the string-encryption pass's
effectiveness into a hard, falsifiable bar instead of a feeling.

Contract:
  * Build a program whose output is derived from several secret literals
    (narrow and wide) with the shipping string-encryption profile.
  * The obfuscated binary runs and matches native output exactly.
  * A whole-binary byte scan finds none of the secrets in ASCII, UTF-16LE or
    UTF-16BE form. The plain (unprotected) binary MUST leak at least one
    secret, proving the scan would detect a regression.
  * Anchored-plaintext shapes (TK-024): literals reachable only through
    another global's initializer (writable pointer table, extern-linkage
    table, struct global) must be equally absent.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SECRETS = (
    "taokari-string-leak-bar-secret-alpha",
    "taokari-string-leak-bar-secret-bravo",
)

# Anchored-plaintext shapes (TK-024): string literals reachable only through
# another global's initializer. Constant internal anchors are rewritten by the
# pass's constant-string-user path, so the gates below use the forms the
# optimizer cannot launder into direct string uses: tables the program writes
# (stays mutable, initializer keeps raw pointers) and extern-linkage tables
# (can never be deleted).
SHAPE_SECRETS = {
    "chain": ("taokari-string-leak-bar-secret-charlie-a",
              "taokari-string-leak-bar-secret-charlie-b"),
    "extern": ("taokari-string-leak-bar-secret-delta-a",
               "taokari-string-leak-bar-secret-delta-b"),
    "struct": ("taokari-string-leak-bar-secret-echo-a",
               "taokari-string-leak-bar-secret-echo-b"),
}

HASH_HELPER = r"""
static int hash_narrow(const char *s) {
  int h = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    h = h * 131 + *p;
  return h;
}
"""

SHAPE_SOURCES = {
    "chain": r"""
#include <stdio.h>
#include <string.h>
@@HASH@@
static const char *names[] = {
  "@@LIT0@@",
  "@@LIT1@@",
};

int main(int argc, char **argv) {
  unsigned i = (unsigned)(argc > 1) & 1u;
  if (argc > 2)
    names[0] = "x";
  printf("leakbar-chain:%s:%d\n", names[i], hash_narrow(names[1 - i]));
  return 0;
}
""",
    "extern": r"""
#include <stdio.h>
#include <string.h>
@@HASH@@
extern const char *const kExt[];
const char *const kExt[] = {
  "@@LIT0@@",
  "@@LIT1@@",
};

int main(int argc, char **argv) {
  unsigned i = (unsigned)(argc > 1) & 1u;
  printf("leakbar-extern:%s:%d\n", kExt[i], hash_narrow(kExt[1 - i]));
  return 0;
}
""",
    "struct": r"""
#include <stdio.h>
#include <string.h>
@@HASH@@
struct rec { const char *name; int id; };
static struct rec recs[] = {
  { "@@LIT0@@", 7 },
  { "@@LIT1@@", 9 },
};

int main(int argc, char **argv) {
  unsigned i = (unsigned)(argc > 1) & 1u;
  if (argc > 2)
    recs[0].id = 3;
  printf("leakbar-struct:%s:%d:%d\n", recs[i].name, recs[1 - i].id,
         hash_narrow(recs[i].name));
  return 0;
}
""",
}


def shape_source(shape: str) -> str:
    secrets = SHAPE_SECRETS[shape]
    return (SHAPE_SOURCES[shape].replace("@@HASH@@", HASH_HELPER)
            .replace("@@LIT0@@", secrets[0]).replace("@@LIT1@@", secrets[1]))


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


def encodings(secret: str) -> list[bytes]:
    return [secret.encode("utf-8"),
            secret.encode("utf-16-le"),
            secret.encode("utf-16-be")]


SOURCE = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

static const char *alpha = "@@ALPHA@@";
static const wchar_t *bravo = L"@@BRAVO@@";

static int hash_narrow(const char *s) {
  int h = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    h = h * 131 + *p;
  return h;
}

static int hash_wide(const wchar_t *s) {
  int h = 7;
  for (; *s; ++s)
    h = h * 17 + (int)*s;
  return h;
}

int main(int argc, char **argv) {
  const char *n = (argc > 1) ? argv[1] : alpha;
  printf("leakbar:%d:%d:%s\n", hash_narrow(n), hash_wide(bravo), alpha);
  return 0;
}
""".replace("@@ALPHA@@", SECRETS[0]).replace("@@BRAVO@@", SECRETS[1])


def scan_for(blob: bytes, secrets) -> list[str]:
    leaked = []
    for secret in secrets:
        if any(form in blob for form in encodings(secret)):
            leaked.append(secret)
    return leaked


def scan(blob: bytes) -> list[str]:
    return scan_for(blob, SECRETS)


def check_shape(shape: str, cfg: Path, tmp: Path) -> bool:
    secrets = SHAPE_SECRETS[shape]
    src = tmp / f"leakbar-{shape}.c"
    src.write_text(shape_source(shape), encoding="utf-8")

    plain = tmp / f"{shape}-plain.exe"
    if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain)]),
                f"{shape} plain build"):
        return False
    plain_run = run([str(plain)])
    if plain_run.returncode:
        sys.stderr.write(f"{shape} plain run failed\n")
        return False
    if not scan_for(plain.read_bytes(), secrets):
        print(f"FAIL: {shape} plain binary leaks no secret; scan cannot "
              "detect a regression", file=sys.stderr)
        return False

    obf = tmp / f"{shape}-obf.exe"
    if not must(run([str(CLANG), str(src), "-O2",
                     *mllvm(["-taokari", "-taokari-cse",
                             f"-taokari-cfg={cfg}"]),
                     "-o", str(obf)]), f"{shape} obfuscated build"):
        return False
    obf_run = run([str(obf)])
    if obf_run.returncode or obf_run.stdout != plain_run.stdout:
        print(f"FAIL: {shape} obfuscated runtime mismatch rc={obf_run.returncode} "
              f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
              file=sys.stderr)
        return False

    leaked = scan_for(obf.read_bytes(), secrets)
    if leaked:
        print(f"GATE FAILED: {shape}: secrets survived into obfuscated "
              f"binary: {leaked}", file=sys.stderr)
        return False
    return True


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-strleak-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "leakbar.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1
        if not scan(plain.read_bytes()):
            print("FAIL: plain binary leaks no secret; scan cannot detect "
                  "a regression", file=sys.stderr)
            return 1

        obf = tmp / "obf.exe"
        cfg = tmp / "cse3.json"
        cfg.write_text(json.dumps({"cse": {"enable": True, "level": 3}}),
                       encoding="utf-8")
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-cse",
                                 f"-taokari-cfg={cfg}"]),
                         "-o", str(obf)]), "obfuscated build"):
            return 1
        obf_run = run([str(obf)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: obfuscated runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

        leaked = scan(obf.read_bytes())
        if leaked:
            print(f"FAIL: secrets survived into obfuscated binary: {leaked}",
                  file=sys.stderr)
            return 1

        for shape in ("chain", "extern", "struct"):
            if not check_shape(shape, cfg, tmp):
                return 1

    print(f"string-leak-bar: ok (0/{len(SECRETS)} secrets leaked across "
          f"ASCII/UTF-16LE/UTF-16BE, runtime matches native, "
          f"{len(SHAPE_SECRETS)} anchor shapes clean)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
