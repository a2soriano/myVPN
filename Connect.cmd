@echo off
setlocal
rem After first-time server setup, connect directly and show connection status.
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0windows\MyVPN.ps1" -Action Connect
if errorlevel 1 (
  echo.
  echo MyVPN could not start. Open MyVPN.cmd to inspect your setup.
  pause
)
