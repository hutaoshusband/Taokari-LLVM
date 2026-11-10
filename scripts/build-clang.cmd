@echo off
setlocal EnableExtensions
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b %ERRORLEVEL%
ninja -C "%~dp0..\build\taokari-local" clang opt llvm-config lld llvm-ar llvm-nm llvm-objdump llvm-readobj
exit /b %ERRORLEVEL%
