@echo off
setlocal
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0windows\MyVPN.ps1" -Action Disconnect
if errorlevel 1 (
  echo.
  echo MyVPN could not start. Use MyVPN.cmd or the official WireGuard app.
  pause
)
