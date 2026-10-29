@echo off
rem ==========================================================================================================
rem  osnit-il v2.0 - One-command turnkey setup for Windows (100% Native Local, Zero Docker, GPU/CUDA First).
rem  Creates local .venv, detects NVIDIA GPU (CUDA), installs PyTorch, all v2.0 requirements, Playwright
rem  Stealth Chromium browser, verifies Tesseract OCR (heb+eng), creates data/ folders, and pre-warms models.
rem  Usage: double-click install.bat   then: double-click run.bat
rem ==========================================================================================================
chcp 65001 >nul
setlocal EnableDelayedExpansion
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

set "NO_PAUSE=0"
if /i "%~1"=="--no-pause" set "NO_PAUSE=1"

rem --- 1. Python 3.10+ Detection ----------------------------------------------------------------------------
set "BOOTSTRAP_PY=python"
where py >nul 2>nul && set "BOOTSTRAP_PY=py -3"
%BOOTSTRAP_PY% --version >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python 3.10+ is required but was not found.
  echo         Install it from https://www.python.org/downloads/ and tick "Add Python to PATH".
  if "%NO_PAUSE%"=="0" pause
  exit /b 1
)
%BOOTSTRAP_PY% -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)"
if errorlevel 1 (
  echo [ERROR] Python 3.10 or newer is required.
  if "%NO_PAUSE%"=="0" pause
  exit /b 1
)
for /f "delims=" %%v in ('%BOOTSTRAP_PY% --version') do echo ==^> Base Python: %%v

rem --- 2. Local Virtual Environment (.venv) -----------------------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
  echo ==^> Creating isolated virtual environment in .venv ...
  %BOOTSTRAP_PY% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment in .venv
    if "%NO_PAUSE%"=="0" pause
    exit /b 1
  )
)
call ".venv\Scripts\activate.bat"
set "VENV_PY=%~dp0.venv\Scripts\python.exe"
echo ==^> Activated virtual environment: %VENV_PY%

echo ==^> Upgrading pip, setuptools, and wheel ...
"%VENV_PY%" -m pip install --upgrade --quiet --disable-pip-version-check pip setuptools wheel 2>nul

rem --- 3. Auto GPU / CUDA Detection & PyTorch ---------------------------------------------------------------
echo ==^> Checking for GPU / CUDA hardware ...
where nvidia-smi >nul 2>nul
if not errorlevel 1 (
  echo ==^> NVIDIA GPU detected! Installing PyTorch with CUDA support ...
  "%VENV_PY%" -m pip install --quiet --disable-pip-version-check torch torchvision --index-url https://download.pytorch.org/whl/cu121 || "%VENV_PY%" -m pip install --quiet --disable-pip-version-check torch torchvision
) else (
  echo ==^> No NVIDIA GPU detected. Installing PyTorch CPU fallback ...
  "%VENV_PY%" -m pip install --quiet --disable-pip-version-check torch torchvision
)

rem --- 4. Install All Required v2.0 Packages ----------------------------------------------------------------
echo ==^> Installing packages from requirements.txt ...
"%VENV_PY%" -m pip uninstall --yes easyocr >nul 2>nul
"%VENV_PY%" -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo ==^> Installing packages individually to ensure maximum compatibility ...
  for /f "usebackq tokens=* delims=" %%p in ("requirements.txt") do (
    set "LINE=%%p"
    if not "!LINE!"=="" if not "!LINE:~0,1!"=="#" (
      "%VENV_PY%" -m pip install --quiet --disable-pip-version-check "!LINE!" || echo    [WARN] Optional package skipped: !LINE!
    )
  )
)

rem --- 5. Data Folders + Default Config ---------------------------------------------------------------------
if not exist "data" mkdir "data"
if not exist "data\archive" mkdir "data\archive"
if not exist "data\models" mkdir "data\models"
if not exist "data\inbox" mkdir "data\inbox"
if not exist "data\avatars" mkdir "data\avatars"
if not exist "data\browser_profile" mkdir "data\browser_profile"
if not exist "data\exports" mkdir "data\exports"
if not exist "osnit.env" copy /y "osnit.env.example" "osnit.env" >nul
echo ==^> Config: osnit.env ready; data\ [archive, models, inbox, avatars, browser_profile, exports] created.

rem --- 6. Verify Tesseract OCR & Traineddata (heb + eng) ----------------------------------------------------
echo ==^> Verifying Tesseract OCR (Hebrew + English) ...
if not exist "tools\Tesseract-OCR\tessdata" mkdir "tools\Tesseract-OCR\tessdata"
if not exist "tools\Tesseract-OCR\tessdata\heb.traineddata" (
  echo ==^> Downloading Hebrew OCR language model [heb.traineddata] ...
  "%VENV_PY%" -c "import urllib.request; urllib.request.urlretrieve('https://github.com/tesseract-ocr/tessdata_fast/raw/main/heb.traineddata', r'tools\Tesseract-OCR\tessdata\heb.traineddata')" 2>nul
)
if not exist "tools\Tesseract-OCR\tessdata\eng.traineddata" (
  echo ==^> Downloading English OCR language model [eng.traineddata] ...
  "%VENV_PY%" -c "import urllib.request; urllib.request.urlretrieve('https://github.com/tesseract-ocr/tessdata_fast/raw/main/eng.traineddata', r'tools\Tesseract-OCR\tessdata\eng.traineddata')" 2>nul
)

rem --- 7. Playwright Stealth Chromium Browser (Python .venv) ------------------------------------------------
echo ==^> Installing Playwright Chromium browser inside .venv ...
"%VENV_PY%" -m playwright install chromium || echo    [WARN] Playwright Chromium setup skipped; system Chrome/Edge auto-fallback active.

rem --- 8. Pre-Warm AI Models & Run System Readiness Check ---------------------------------------------------
echo ==^> Pre-warming and caching AI models to data\models ...
"%VENV_PY%" -m osnit warmup

echo.
echo ==========================================================================================================
echo  OSNIT-IL v2.0 Installation Complete!
echo  - Database path : data\osnit.db (SQLite WAL + FTS5)
echo  - Configuration : osnit.env
echo  - Launch server : double-click run.bat (opens http://localhost:8080)
echo ==========================================================================================================
if "%NO_PAUSE%"=="0" pause
