@echo off
rem OSNIT-IL: double-click to start the local site on http://localhost:8080
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
%PY% -m pip install --quiet --disable-pip-version-check pypdf
if not exist data mkdir data
if not exist osnit.env copy osnit.env.example osnit.env >nul
echo Starting OSNIT-IL on http://localhost:8080  (close this window to stop)
%PY% -m osnit serve --port 8080 --open
pause
