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

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SECRETS = (
    "taokari-string-leak-bar-secret-alpha",
    "taokari-string-leak-bar-secret-bravo",
)


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


def scan(blob: bytes) -> list[str]:
    leaked = []
    for secret in SECRETS:
        if any(form in blob for form in encodings(secret)):
            leaked.append(secret)
    return leaked


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

    print(f"string-leak-bar: ok (0/{len(SECRETS)} secrets leaked across "
          f"ASCII/UTF-16LE/UTF-16BE, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
