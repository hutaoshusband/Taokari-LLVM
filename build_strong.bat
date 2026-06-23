@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM Taokari Strong blanket build recipe (Tier B).
REM
REM The strong blanket applies every cheap, IDA-visible pass globally:
REM fla L4, bcf L2 wrapping the flattened dispatcher on both sides,
REM mba prob 40, cie/cfe L2, cse, icall, indbr, indgv, meta L3,
REM MIR fortress (dirtybytes/junk/sub/split/fakeprologue) and the
REM NativeIntegrity auto-trigger. No -taokari-max shortcut, no global
REM -taokari-vmp. This is the recommended default for "make the binary
REM look noisy in IDA without paying for VM virtualisation".
REM
REM Add VMP later by annotating 1-N sensitive functions in source with
REM __attribute__((noinline, annotate("+vmp"))) and re-running this
REM script (the Phase 1 budget caps refuse runaway functions for you).
REM
REM Set TAOKARI_SKIP_CLANG_REFRESH=1 to reuse the existing local clang.

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"
set "CLANG=%ROOT%\build\taokari-local\bin\clang.exe"
set "NINJA=%LOCALAPPDATA%\Microsoft\WinGet\Links\ninja.exe"
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
set "JOBS=%NUMBER_OF_PROCESSORS%"
set "OUTDIR=%ROOT%\build\strong"
set "SRC=%~1"
set "CFG=%OUTDIR%\strong_config.json"

if "%JOBS%"=="" set "JOBS=24"

cd /d "%ROOT%" || goto fail
if not exist "%VSDEVCMD%" (
  echo Missing Visual Studio dev shell:
  echo %VSDEVCMD%
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul || goto fail

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
  echo   "randomSeed": "taokari-strong-seed",
  echo   "meta": { "enable": true, "level": 3, "releaseStrip": true, "randomizeSections": true }
  echo }
) || goto fail

if "%SRC%"=="" (
  set "SRC=%OUTDIR%\strong_sample.c"
  >"%OUTDIR%\strong_sample.c" (
    echo #include ^<stdio.h^>
    echo int compute^(int x^) { return ^(^((x * 17^) ^^^ 0x5a5a^) + 9^); }
    echo int main^(void^) { printf^("strong:%%d\n", compute^(13^)^); return 0; }
  ) || goto fail
)

if not exist "%SRC%" (
  echo Source not found:
  echo %SRC%
  exit /b 1
)

for %%F in ("%SRC%") do set "NAME=%%~nF"
set "EXE=%OUTDIR%\%NAME%_strong.exe"
set "REPORT=%OUTDIR%\%NAME%_strong_vmp_report.txt"
set "TMROUT=%OUTDIR%\compile_time.txt"

REM Phase 4 compile-time budget. Wall-clock the clang invocation via
REM %TIME% deltas and fail the build over the ceiling. Default ceiling is
REM the demo-target bar from Section 22 Phase 4 (override via
REM TAOKARI_COMPILE_BUDGET_SEC; whole seconds only).
set "BUDGET=%TAOKARI_COMPILE_BUDGET_SEC%"
if "%BUDGET%"=="" set "BUDGET=30"

set "T0=%TIME%"
echo.
echo Building Strong blanket binary (Tier B)...
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
  -mllvm -taokari-bcf-before-fla ^
  -mllvm -taokari-bcf-after-fla ^
  -mllvm -taokari-mba -mllvm -taokari-mba-prob=40 ^
  -mllvm -taokari-cie -mllvm -taokari-level-cie=2 ^
  -mllvm -taokari-cfe -mllvm -taokari-level-cfe=2 ^
  -mllvm -taokari-cse ^
  -mllvm -taokari-icall ^
  -mllvm -taokari-indbr ^
  -mllvm -taokari-indgv ^
  -mllvm -taokari-meta -mllvm -taokari-level-meta=3 ^
  -mllvm -taokari-mir=dirtybytes,junk,sub,split,fakeprologue ^
  -mllvm -taokari-mir-dirtybytes-prob=100 ^
  -mllvm -taokari-mir-junk-prob=100 ^
  -mllvm -taokari-mir-sub-prob=100 ^
  -mllvm -taokari-vmp-padding=5 ^
  -mllvm -taokari-vmp-compat-report="%REPORT%" ^
  -Wl,/DEBUG:NONE || goto fail
set "T1=%TIME%"

call :elapsed "%T0%" "%T1%" ELAPSED
>"%TMROUT%" echo %ELAPSED%
echo Compile time: %ELAPSED% seconds (budget %BUDGET%s)

if %ELAPSED% GTR %BUDGET% (
  echo build_strong.bat: COMPILE BUDGET EXCEEDED. %ELAPSED%s ^> %BUDGET%s budget.
  echo To isolate which pass tripped, rebuild with -mllvm -time-passes.
  exit /b 1
)

echo.
echo Strong blanket binary:
echo %EXE%
echo.
echo VMP compatibility report (no +vmp functions in the default sample):
echo %REPORT%
echo.
echo Tier B recipe: blanket only. Add +vmp annotations in source to grow to Tier C.
exit /b 0

REM Compute whole-second delta between two %TIME% stamps (HH:MM:SS,cc).
REM Handles midnight wraparound. Sets %3 to the integer seconds.
:elapsed
setlocal
set "START=%~1"
set "END=%~2"
set "S_H=%START:~0,2%"
set "S_M=%START:~3,2%"
set "S_S=%START:~6,2%"
set "E_H=%END:~0,2%"
set "E_M=%END:~3,2%"
set "E_S=%END:~6,2%"
set /a "S_H=1%S_H%-100, S_M=1%S_M%-100, S_S=1%S_S%-100"
set /a "E_H=1%E_H%-100, E_M=1%E_M%-100, E_S=1%E_S%-100"
set /a "S=S_H*3600+S_M*60+S_S, E=E_H*3600+E_M*60+E_S"
set /a "D=E-S"
if !D! LSS 0 set /a "D+=86400"
endlocal & set "%~3=%D%"
goto :eof

:fail
echo.
echo build_strong.bat failed with exit code %ERRORLEVEL%.
exit /b %ERRORLEVEL%
