@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build_exe.ps1"
if errorlevel 1 (
  echo.
  echo Build falhou.
  pause
  exit /b 1
)
echo.
pause
