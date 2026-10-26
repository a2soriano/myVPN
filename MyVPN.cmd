@echo off
setlocal
rem This changes execution policy only for this PowerShell process.
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0windows\MyVPN.ps1"
if errorlevel 1 (
  echo.
  echo MyVPN could not start. Read the error above and the README.
  pause
)
