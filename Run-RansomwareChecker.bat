@echo off
rem RansomwareChecker launcher - elevates and runs the read-only triage.
rem Optional arguments are passed to the script, e.g.:  Run-RansomwareChecker.bat -DaysBack 60 -Quick
setlocal
set "SCRIPT=%~dp0RansomwareChecker.ps1"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    if "%~1"=="" (
        powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -OpenReport %*
echo.
echo Exit code %errorlevel%  (0 = clean, 1 = Medium findings, 2 = High findings)
pause
