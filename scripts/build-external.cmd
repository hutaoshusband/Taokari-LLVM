@echo off
set "JOBS=%~1"
if "%JOBS%"=="" set "JOBS=%NUMBER_OF_PROCESSORS%"
start "Taokari Build" cmd /k ""%~dp0build-worker.cmd" %JOBS%"
echo Started Taokari build in a separate console with %JOBS% jobs.
