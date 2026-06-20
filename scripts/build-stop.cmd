@echo off
taskkill /f /fi "imagename eq ninja.exe" >nul 2>nul
taskkill /f /fi "imagename eq cl.exe" >nul 2>nul
taskkill /f /fi "imagename eq cmake.exe" >nul 2>nul
echo Stopped Taokari build processes if any were running.
