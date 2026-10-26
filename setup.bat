@echo off
rem ============================================================================
rem  setup.bat -- Sentinel Edge full install (Windows)
rem
rem  Everything lands INSIDE this project folder:
rem    * .venv\          the Python virtual environment (all packages live here)
rem    * data\blocklists downloaded reputation feeds (bloom store)
rem    * data\harness    labelled scenario pcaps
rem    * data\flows      training CSV (runtime feature contract)
rem    * data\models     trained LightGBM flow model + anomaly autoencoder
rem
rem  Nothing is installed globally. After the venv exists, every step runs
rem  ".venv\Scripts\python.exe" directly, so pip can never touch the system
rem  Python or place packages outside of the project folder.
rem
rem  Usage:  setup.bat          (interactive prompts)
rem          setup.bat --yes    (assume yes on all prompts; for automation)
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion
title Sentinel Edge setup
cd /d "%~dp0"
chcp 65001 >nul

set "ASSUME_YES="
if /i "%~1"=="--yes" set "ASSUME_YES=1"

:banner_ok
echo.
echo  ============================================================
echo   Sentinel Edge setup  --  Local Adaptive Firewall
echo  ============================================================
echo   project dir : %CD%
echo   packages    : %CD%\.venv   (installed here only, never global)
echo.

rem -- sanity: right folder? ----------------------------------------------------

if not exist "sentinel\main.py" goto :wrongdir
if not exist "requirements.txt" goto :noreq
echo [1/9] project layout ok (sentinel\main.py + requirements.txt found)

rem -- pick a Python 3.11+ (py launcher first, then PATH python) -----------------

set "PYEXE="
py -3 --version >nul 2>&1
if not errorlevel 1 set "PYEXE=py -3"
if not defined PYEXE python --version >nul 2>&1
if not defined PYEXE if errorlevel 1 goto :nopython
if not defined PYEXE set "PYEXE=python"

set "PYVER="
for /f "tokens=2" %%v in ('%PYEXE% --version 2^>nul') do set "PYVER=%%v"
if not defined PYVER goto :nopython
echo [2/9] using %PYEXE%  --  Python %PYVER%

if "%PYVER:~0,3%"=="3.1" goto :ver_ok
goto :oldversion
:ver_ok
if "%PYVER%"=="3.10" echo       [warn] tested pin set targets Python 3.11+ -- continuing

rem -- virtual environment -------------------------------------------------------

set "RECREATE="
if defined ASSUME_YES set "RECREATE=1"
if not defined RECREATE if exist "%CD%\.venv\Scripts\python.exe" (
    choice /C YN /T 20 /D Y /N /M "      .venv already exists. Delete and recreate it? [Y/N] "
    if errorlevel 2 (
        echo       keeping the existing .venv -- run clean.bat first for a full reset
    ) else (
        set "RECREATE=1"
    )
)
if defined RECREATE (
    echo       removing the old .venv ...
    rd /s /q ".venv" 2>nul
)
echo [3/9] creating .venv (isolated environment inside the project folder) ...
set "STEP=creating the virtual environment (%PYEXE% -m venv .venv)"
%PYEXE% -m venv .venv
if errorlevel 1 goto :die
if not exist ".venv\Scripts\python.exe" goto :die

rem -- pip into the venv ---------------------------------------------------------

echo [4/9] upgrading pip inside .venv ...
".venv\Scripts\python.exe" -m pip install --upgrade --disable-pip-version-check pip setuptools wheel >nul 2>&1
if errorlevel 1 echo       [warn] pip upgrade skipped -- continuing with the bundled pip

echo [5/9] installing pinned requirements into .venv (downloads ~200 MB once) ...
set "STEP=pip install -r requirements.txt"
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :die

echo       import sanity check inside .venv ...
".venv\Scripts\python.exe" -c "import fastapi, uvicorn, websockets, numpy, pandas, sklearn, lightgbm, scapy, pydivert, ahocorasick, yaml, psutil, httpx; import sentinel.main, harness.runner, tools.update_blocklists"
if errorlevel 1 goto :die

rem -- blocklists (network step; tolerated offline with a warning) -----------------

set "DO_BL=1"
if not defined ASSUME_YES if exist "data\blocklists\reputation.bin" (
    choice /C YN /T 15 /D N /N /M "      a blocklist store already exists. Refresh it from the internet? [Y/N] "
    if errorlevel 2 set "DO_BL=0"
)
if "%DO_BL%"=="0" (
    echo [6/9] keeping the existing data\blocklists -- skipping the download
    goto :bl_done
)
echo [6/9] downloading public blocklists and rebuilding the bloom store ...
".venv\Scripts\python.exe" tools\update_blocklists.py
if exist "data\blocklists\reputation.bin" goto :bl_done
echo       [warn] blocklist download failed -- offline?
echo       The engine still runs; the reputation stage just warns and passes traffic.
echo       Retry later:  .venv\Scripts\python.exe tools\update_blocklists.py
:bl_done

rem -- training data + models -----------------------------------------------------

echo [7/9] building labelled scenario pcaps (scapy, all local -- no external tools)
set "STEP=harness build mode (scapy scenario pcaps)"
".venv\Scripts\python.exe" -m harness.runner --mode build
if errorlevel 1 goto :die

echo [8/9] extracting training flows and training both models ...
set "STEP=tools\pcap_to_flows.py (runtime feature extraction)"
".venv\Scripts\python.exe" tools\pcap_to_flows.py data\harness\pcaps\benign_browsing.pcap data\harness\pcaps\brute_force.pcap data\harness\pcaps\malformed_packets.pcap data\harness\pcaps\port_scan.pcap data\harness\pcaps\slow_scan.pcap data\harness\pcaps\syn_flood.pcap data\harness\pcaps\web_injection.pcap --label auto --out data\flows\flows.csv
if errorlevel 1 goto :die
if not exist "data\flows\flows.csv" goto :die

set "STEP=train the flow classifier (LightGBM)"
".venv\Scripts\python.exe" -m sentinel.main train --csv data\flows\flows.csv
if errorlevel 1 goto :die
if not exist "data\models\flow_lgbm.joblib" goto :die

set "STEP=train the anomaly autoencoder (benign baseline)"
".venv\Scripts\python.exe" -m sentinel.ml.train_anomaly --csv data\flows\flows.csv
if errorlevel 1 goto :die
if not exist "data\models\flow_ae.npz" goto :die

rem -- validation -------------------------------------------------------------------

echo [9/9] validating the whole chain (replay through the live engine) ...
".venv\Scripts\python.exe" -m harness.runner --mode replay
if errorlevel 1 echo       [warn] replay verdicts under the gate -- see data\harness\reports\report.json

".venv\Scripts\python.exe" -m sentinel.main simulate --scenario scan
echo       (dry run of the full detector chain -- no admin needed)

rem -- done --------------------------------------------------------------------------

echo.
echo  ============================================================
echo   Setup complete.
echo.
echo   packages live in : %CD%\.venv   (never in the system Python)
echo   blocklists       : data\blocklists\reputation.bin
echo   models           : data\models\flow_lgbm.joblib + flow_ae.npz
echo.
echo   Next:
echo     run.bat              start firewall + dashboard + honeypot
echo     run.bat admin        relaunch elevated (UAC) for blocking mode
echo     run.bat observe      start without elevation (observe-only)
echo     clean.bat            remove everything this setup installed
echo  ============================================================
echo.
if defined ASSUME_YES exit /b 0
pause
exit /b 0

rem ----------------------------------------------------------------------------
rem -- help / failure labels
rem ----------------------------------------------------------------------------
:wrongdir
echo [FAIL] sentinel\main.py not found here. Run setup.bat from the project
echo        root that contains sentinel, tools, harness and tests.
echo.
if defined ASSUME_YES exit /b 1
pause
exit /b 1

:noreq
echo [FAIL] requirements.txt not found next to setup.bat -- refusing to install.
echo.
if defined ASSUME_YES exit /b 1
pause
exit /b 1

:nopython
echo [FAIL] Python 3.11+ not found.
echo        Install it from https://www.python.org/downloads/ and tick
echo        "Add python.exe to PATH" during install, then re-run setup.bat.
echo.
if defined ASSUME_YES exit /b 1
pause
exit /b 1

:oldversion
if defined ASSUME_YES (
    echo [FAIL] Python %PYVER% found -- the pinned set is tested on 3.11+.
    echo        Install Python 3.11-3.13 and re-run, or edit requirements.txt.
)
if defined ASSUME_YES exit /b 1
choice /C YN /T 20 /D Y /N /M "      [warn] Python %PYVER% is outside the tested range (3.11+). Continue anyway? [Y/N] "
if errorlevel 2 exit /b 1
goto :banner_ok

:die
echo.
echo [FAIL] setup stopped at: %STEP%
echo        Scroll up for the exact error. Fix it and re-run setup.bat --
echo        every step is safe to redo (venv creation, pip and training are idempotent).
echo.
if defined ASSUME_YES exit /b 1
pause
exit /b 1
