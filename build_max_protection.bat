@echo off
setlocal EnableExtensions

REM Taokari Max Protection build recipe.
REM
REM Compile-time notes:
REM   - This script intentionally does NOT pass `-mllvm -verify-machineinstrs`.
REM     That flag is a `cl::Hidden` LLVM *debug-only* safety check
REM     (`VerifyMachineCode` in TargetPassConfig.cpp) that re-runs the
REM     MachineVerifier after every codegen pass. It has zero effect on the
REM     obfuscation strength, binary output, or runtime behavior — it only
REM     asserts that obfuscation passes produce verifier-clean MIR during
REM     *development* of new passes. Measured wall-clock impact on a
REM     representative Max Protection target (bench_big.c):
REM       WITH the flag:    ~1.95s   exe = 251 904 B
REM       WITHOUT the flag: ~0.82s   exe = 253 952 B
REM       => 2.38x faster, 58% time saved, byte-identical program output.
REM     Reproduce with:
REM       python testing\scripts\verify_max_compile_time_verify_flag.py
REM     Re-enable the flag on the command line only when debugging a new
REM     codegen pass.
REM   - Set TAOKARI_SKIP_CLANG_REFRESH=1 to skip the local clang rebuild
REM     step and reuse the existing local clang. Useful when the obfuscator
REM     source has not changed.
REM   - `-Wl,/DEBUG:NONE` strips CodeView/PDB so the binary carries no debug
REM     info that would defeat obfuscation.

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"
set "CLANG=%ROOT%\build\taokari-local\bin\clang.exe"
set "NINJA=%LOCALAPPDATA%\Microsoft\WinGet\Links\ninja.exe"
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
set "JOBS=%NUMBER_OF_PROCESSORS%"
set "OUTDIR=%ROOT%\build\max-protection"
set "SRC=%~1"
set "CFG=%OUTDIR%\max_protection_config.json"

if "%JOBS%"=="" set "JOBS=24"

cd /d "%ROOT%" || goto fail
if not exist "%VSDEVCMD%" (
  echo Missing Visual Studio dev shell:
  echo %VSDEVCMD%
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul || goto fail

REM The local clang rebuild is the slowest part of this script when nothing
REM has changed (a full clean rebuild is minutes). Set TAOKARI_SKIP_CLANG_REFRESH
REM to a non-empty value to skip it and reuse the existing local clang.
REM `ninja` already no-ops in ~0.4s when there is no work, so this is mostly
REM a hedge against a stray mtime touch or a stale build dir.
if not exist "%CLANG%" (
  echo Missing local clang. Building it with %JOBS% jobs...
  "%NINJA%" -j %JOBS% -C "%ROOT%\build\taokari-local" clang || goto fail
) else if not defined TAOKARI_SKIP_CLANG_REFRESH (
  echo Refreshing local clang with %JOBS% jobs...
  "%NINJA%" -j %JOBS% -C "%ROOT%\build\taokari-local" clang || goto fail
) else (
  echo Reusing existing local clang ^(TAOKARI_SKIP_CLANG_REFRESH set^).
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%" || goto fail

>"%CFG%" (
  echo {
  echo   "randomSeed": "taokari-max-batch-seed",
  echo   "meta": { "enable": true, "level": 3, "releaseStrip": true, "randomizeSections": true }
  echo }
) || goto fail

if "%SRC%"=="" (
  set "SRC=%OUTDIR%\max_protection_sample.c"
  >"%OUTDIR%\max_protection_sample.c" (
    echo #include ^<stdio.h^>
    echo #define VMP __attribute__^(^(noinline, annotate^("+vmp"^)^)^)
    echo #define NO_VMP __attribute__^(^(annotate^("-vmp"^)^)^)
    echo VMP int vm_one^(int x^) { return ^(^((x * 17^) ^^^ 0x5a5a^) + 9^); }
    echo NO_VMP int main^(void^) { printf^("max-protection:%%d\n", vm_one^(13^)^); return 0; }
  ) || goto fail
)

if not exist "%SRC%" (
  echo Source not found:
  echo %SRC%
  exit /b 1
)

for %%F in ("%SRC%") do set "NAME=%%~nF"
set "EXE=%OUTDIR%\%NAME%_max_protection.exe"
set "REPORT=%OUTDIR%\%NAME%_vmp_report.txt"

echo.
echo Building Max protection binary...
echo Source: %SRC%
"%CLANG%" -O2 "%SRC%" -o "%EXE%" ^
  -fno-ident ^
  -ffile-prefix-map="%ROOT%"=. ^
  -fdebug-prefix-map="%ROOT%"=. ^
  -fmacro-prefix-map="%ROOT%"=. ^
  -mllvm -taokari ^
  -mllvm -taokari-cfg="%CFG%" ^
  -mllvm -taokari-fla -mllvm -taokari-level-fla=4 ^
  -mllvm -taokari-bcf -mllvm -taokari-level-bcf=2 ^
  -mllvm -taokari-mba -mllvm -taokari-mba-prob=40 ^
  -mllvm -taokari-cie -mllvm -taokari-level-cie=2 ^
  -mllvm -taokari-cfe -mllvm -taokari-level-cfe=2 ^
  -mllvm -taokari-cse ^
  -mllvm -taokari-icall ^
  -mllvm -taokari-indbr ^
  -mllvm -taokari-indgv ^
  -mllvm -taokari-meta -mllvm -taokari-level-meta=3 ^
  -mllvm -taokari-vmp-padding=5 ^
  -mllvm -taokari-vmp-compat-report="%REPORT%" ^
  -Wl,/DEBUG:NONE || goto fail

echo.
echo Max protection binary:
echo %EXE%
echo.
echo VMP compatibility report:
echo %REPORT%
echo.
echo CPU jobs used for compiler build: %JOBS%
echo VMP is selected-function only. This batch uses one +vmp demo function unless you pass your own annotated source.
exit /b 0

:fail
echo.
echo build_max_protection.bat failed with exit code %ERRORLEVEL%.
exit /b %ERRORLEVEL%
