@echo off
rem ==========================================================================================================
rem  osnit-il - one-command setup for a fresh Windows machine.
rem  Installs the optional Python file-format packages and, if Node.js is present, the no-API browser search.
rem  Usage: double-click install.bat   then: double-click run.bat
rem ==========================================================================================================
setlocal
cd /d "%~dp0"

rem --- Python 3.10+ -----------------------------------------------------------------------------------------
where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
%PY% --version >nul 2>nul || (
  echo ERROR: Python 3.10+ is required but was not found. Install it from https://python.org and tick "Add to PATH".
  pause & exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" || (
  echo ERROR: Python 3.10 or newer is required.
  pause & exit /b 1
)
for /f "delims=" %%v in ('%PY% --version') do echo ==^> Python: %%v

rem --- optional Python packages -----------------------------------------------------------------------------
echo ==^> Installing optional Python packages (pypdf, xlrd) ...
%PY% -m pip install --upgrade --quiet --disable-pip-version-check pip 2>nul
%PY% -m pip install --quiet --disable-pip-version-check -r requirements.txt || echo    (optional packages skipped - core app still works)

rem --- data dir + config ------------------------------------------------------------------------------------
if not exist data mkdir data
if not exist osnit.env copy osnit.env.example osnit.env >nul
echo ==^> Config: osnit.env ready, data\ created

rem --- optional: no-API browser search ----------------------------------------------------------------------
where npm >nul 2>nul && (
  echo ==^> Node.js found; setting up the no-API browser search ...
  call npm install --silent
  call npx --yes playwright install chromium
  echo    Browser search ready. Enable it with OSNIT_PROVIDERS=browser in osnit.env
) || (
  echo ==^> Node.js not found - SKIPPING the optional no-API browser search.
  echo    To enable it later: install Node 18+ from https://nodejs.org, then run:
  echo        npm install ^&^& npx playwright install chromium
)

echo.
echo Tip: all data lives in the single SQLite file  data\osnit.db  (no server to run).
echo      To browse/manage it visually, install the free "DB Browser for SQLite"
echo      (https://sqlitebrowser.org) and open that file - no SQL needed, nothing to change in the app.
echo.
echo Done. Start the app by double-clicking run.bat  (opens http://localhost:8080)
pause
