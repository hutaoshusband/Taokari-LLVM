@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
cd /d C:\Users\hutao\Documents\GitHub\Taokari-LLVM\build\taokari-local
ninja clang opt llvm-config
exit /b %ERRORLEVEL%
