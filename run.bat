@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
rem OSNIT-IL v2.0: double-click to start the local site on http://localhost:8080
cd /d "%~dp0"
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
if not exist data mkdir data
if not exist data\archive mkdir data\archive
if not exist data\models mkdir data\models
if not exist data\inbox mkdir data\inbox
if not exist osnit.env copy osnit.env.example osnit.env >nul
echo Starting OSNIT-IL v2.0 on http://localhost:8080 (close this window to stop)
python -m osnit serve --port 8080 --open
pause
