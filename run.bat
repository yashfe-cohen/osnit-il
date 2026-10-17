@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
rem ==========================================================================================================
rem  OSNIT-IL v2.0 — Double-click to start the local server on http://localhost:8080
rem  Automatically runs first-time setup (install.bat) if .venv has not been created yet.
rem ==========================================================================================================
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo ==^> First-time setup detected ^(.venv not found^). Running install.bat automatically ...
  call "%~dp0install.bat" --no-pause
)

call ".venv\Scripts\activate.bat"
set "VENV_PY=%~dp0.venv\Scripts\python.exe"

if not exist "data" mkdir "data"
if not exist "data\archive" mkdir "data\archive"
if not exist "data\models" mkdir "data\models"
if not exist "data\inbox" mkdir "data\inbox"
if not exist "data\avatars" mkdir "data\avatars"
if not exist "data\browser_profile" mkdir "data\browser_profile"
if not exist "data\exports" mkdir "data\exports"
if not exist "osnit.env" copy /y "osnit.env.example" "osnit.env" >nul

echo ==^> Starting OSNIT-IL v2.0 on http://localhost:8080 (close this window to stop)
"%VENV_PY%" -m osnit serve --port 8080 --open %*
pause
