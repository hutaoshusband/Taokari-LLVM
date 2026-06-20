@echo off
setlocal EnableExtensions
set "ROOT=%~dp0.."
pushd "%ROOT%"
for /f "delims=" %%F in ('dir /b /od build-logs\taokari-build-*.log 2^>nul') do set "LOG=build-logs\%%F"
if not defined LOG (
  echo No build log found.
  popd
  exit /b 1
)
echo Log: %CD%\%LOG%
type "%LOG%"
popd
