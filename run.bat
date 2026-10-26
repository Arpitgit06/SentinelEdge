@echo off
rem ============================================================================
rem  run.bat -- start Sentinel Edge (firewall engine + hotkeys + honeypot
rem             decoys + local dashboard)
rem
rem  Real packet blocking needs Administrator (WinDivert loads a kernel filter
rem  driver). Without it the service still boots in observe-only / fail-open
rem  mode and the dashboard runs -- the machine is never locked out.
rem
rem  Usage:
rem     run.bat                 interactive (asks for elevation, 12s default no)
rem     run.bat admin           go straight to the UAC elevation prompt
rem     run.bat observe         start without elevation (observe-only)
rem     run.bat observe silent  same, never pauses (for automation)
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion
title Sentinel Edge
cd /d "%~dp0"
chcp 65001 >nul

set "SILENT="
if /i "%~2"=="silent" set "SILENT=1"

if not exist ".venv\Scripts\python.exe" goto :nosetup

fltmc >nul 2>&1
if not errorlevel 1 goto :run
rem -- without administrator: notification + optional elevation -----------------
echo.
echo  [i] not running as Administrator: observe-only, fail-open mode.
echo      Detectors run and events stream to the dashboard, nothing is blocked.
if /i "%~1"=="observe" goto :run
if defined SILENT goto :run
choice /C YN /T 12 /D N /N /M "Relaunch elevated to enable blocking mode (UAC prompt)? [Y/N] "
if errorlevel 2 goto :run
:do_elevate
echo  [i] waiting for the UAC prompt (answering no falls back to observe-only) ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList 'observe' -Verb RunAs } catch { exit 1 }"
if not errorlevel 1 exit /b 0
echo  [warn] elevation was refused or failed -- continuing unprivileged.
goto :run

:run
echo.
echo  starting Sentinel Edge (Ctrl+C to stop)
echo  dashboard: http://127.0.0.1:8636
echo.
set "STEP=start sentinel.main serve"
".venv\Scripts\python.exe" -m sentinel.main serve
set "RC=%errorlevel%"
if not "%RC%"=="0" if not defined SILENT (
    echo.
    echo  [i] engine exited with code %RC%. A Ctrl+C stop can report 1; a real
    echo      failure prints a traceback above. Try run.bat admin for blocking.
    echo.
    pause
)
exit /b %RC%

:nosetup
echo  [FAIL] .venv not found. Run setup.bat first: it creates the virtual
echo         environment and everything else run.bat needs.
echo.
if defined SILENT exit /b 1
pause
exit /b 1
