@echo off
setlocal EnableExtensions

set "ROOT=%~dp0.."
set "JOBS=%~1"
set "NINJA=%LOCALAPPDATA%\Microsoft\WinGet\Links\ninja.exe"
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"

cd /d "%ROOT%" || goto fail
call "%VSDEVCMD%" -arch=x64 -host_arch=x64 || goto fail
if "%JOBS%"=="" (
  "%NINJA%" -C build\taokari-local clang
) else (
  "%NINJA%" -j %JOBS% -C build\taokari-local clang
)
if errorlevel 1 goto fail

echo.
echo Taokari build finished.
pause
exit /b 0

:fail
echo.
echo Taokari build failed with exit code %ERRORLEVEL%.
pause
exit /b %ERRORLEVEL%
