Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root "build\\taokari-local"
$Clang = Join-Path $Build "bin\clang.exe"

if (-not (Test-Path $Build)) {
  throw "Missing build cache: $Build"
}

ninja -C $Build
if ($LASTEXITCODE -ne 0) {
  throw "Cached build failed. Run from a VS Native Tools shell, or use scripts\configure-release.ps1."
}

if (Test-Path $Clang) {
  & $Clang --version
}
