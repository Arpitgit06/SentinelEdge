@echo off
rem ============================================================================
rem  clean.bat -- remove everything setup.bat installed/downloaded (Windows)
rem
rem  Removes:  .venv\  and the whole generated data tree
rem            (blocklists, models, logs/events.db, harness pcaps + reports,
rem             flows CSV, evidence zips, exports, feedback db)
rem  Sweeps:   __pycache__ / .pytest_cache inside the project
rem  Keeps:    all source code (sentinel, tools, harness, tests), README, docs,
rem            the .bat files and requirements.txt
rem
rem  The global pip cache (%%LOCALAPPDATA%%\pip) is intentionally untouched --
rem  it belongs to the machine, not to this project.
rem  Close any running instance first (run.bat console, dashboard browser tab).
rem
rem  Usage:  clean.bat          asks for confirmation
rem          clean.bat --yes    no confirmation (automation)
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion
title Sentinel Edge clean
cd /d "%~dp0"
chcp 65001 >nul

set "ASSUME_YES="
if /i "%~1"=="--yes" set "ASSUME_YES=1"

echo.
echo  ============================================================
echo   Sentinel Edge clean uninstall
echo  ============================================================
echo   removes : .venv\   and the data\ tree
echo             (blocklists, models, logs, harness, flows, evidence,
echo              exports, feedback)
echo   sweeps  : __pycache__ .pytest_cache
echo   keeps   : source code, README, docs, .bat files, requirements.txt
echo.
if not exist "sentinel\main.py" (
    echo [FAIL] sentinel\main.py not found here -- refusing to clean a wrong folder.
    if defined ASSUME_YES exit /b 1
    pause
    exit /b 1
)
if not defined ASSUME_YES (
    choice /C YN /T 20 /D N /N /M "      Continue and delete everything listed above? [Y/N] "
    if errorlevel 2 (
        echo  nothing deleted.
        exit /b 0
    )
)

if exist ".venv" (
    echo [1/4] removing .venv ...
    rd /s /q ".venv" 2>nul
) else (
    echo [1/4] no .venv present -- skipping
)
if exist "data" (
    echo [2/4] removing the data tree ...
    rd /s /q "data" 2>nul
) else (
    echo [2/4] no data tree present -- skipping
)
md "data" >nul 2>&1

echo [3/4] sweeping __pycache__ / .pytest_cache ...
for /d /r . %%D in (__pycache__) do rd /s /q "%%D" 2>nul
if exist ".pytest_cache" rd /s /q ".pytest_cache" 2>nul

if not exist "sentinel\main.py" (
    echo [FAIL] unexpected: sentinel\main.py vanished -- cleanup went wrong!
    if defined ASSUME_YES exit /b 1
    pause
    exit /b 1
)
echo [4/4] project source verified intact.
echo.
echo  clean finished. Run setup.bat to reinstall from scratch.
echo.
if defined ASSUME_YES exit /b 0
pause
exit /b 0
