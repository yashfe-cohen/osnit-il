@echo off
rem ==========================================================================================================
rem  osnit-il v2.0 - One-command setup for Windows (100% Native Local, Zero Docker, GPU/CUDA First).
rem  Creates local .venv, detects NVIDIA GPU (CUDA), installs PyTorch, Tesseract OCR, DictaBERT-NER, and pre-warms models.
rem  Usage: double-click install.bat   then: double-click run.bat
rem ==========================================================================================================
setlocal
cd /d "%~dp0"

rem --- Python 3.10+ -----------------------------------------------------------------------------------------
where py >nul 2>nul && (set "BOOTSTRAP_PY=py -3") || (set "BOOTSTRAP_PY=python")
%BOOTSTRAP_PY% --version >nul 2>nul || (
  echo ERROR: Python 3.10+ is required but was not found. Install it from https://python.org and tick "Add to PATH".
  pause & exit /b 1
)
%BOOTSTRAP_PY% -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" || (
  echo ERROR: Python 3.10 or newer is required.
  pause & exit /b 1
)
for /f "delims=" %%v in ('%BOOTSTRAP_PY% --version') do echo ==^> Base Python: %%v

rem --- Local Virtual Environment (.venv) --------------------------------------------------------------------
if not exist .venv (
  echo ==^> Creating isolated virtual environment in .venv ...
  %BOOTSTRAP_PY% -m venv .venv || (
    echo ERROR: Failed to create virtual environment.
    pause & exit /b 1
  )
)
call .venv\Scripts\activate.bat
echo ==^> Activated virtual environment: %VIRTUAL_ENV%

python -m pip install --upgrade --quiet --disable-pip-version-check pip 2>nul

rem --- Auto GPU / CUDA Detection ----------------------------------------------------------------------------
echo ==^> Checking for GPU / CUDA hardware ...
where nvidia-smi >nul 2>nul && (
  echo ==^> NVIDIA GPU detected! Installing PyTorch with CUDA support ...
  pip install --quiet torch torchvision --index-url https://download.pytorch.org/whl/cu121 || pip install torch torchvision
) || (
  echo ==^> No NVIDIA GPU detected. Installing PyTorch CPU fallback ...
  pip install --quiet torch torchvision
)

rem --- Install All Required v2.0 Packages -------------------------------------------------------------------
echo ==^> Installing packages from requirements.txt ...
pip uninstall --yes easyocr 2>nul
pip install --quiet --disable-pip-version-check -r requirements.txt || echo    (some optional packages skipped)

rem --- Data Folders + Config --------------------------------------------------------------------------------
if not exist data mkdir data
if not exist data\archive mkdir data\archive
if not exist data\models mkdir data\models
if not exist data\inbox mkdir data\inbox
if not exist osnit.env copy osnit.env.example osnit.env >nul
echo ==^> Config: osnit.env ready, data\ archive\ models\ inbox\ created

rem --- Playwright Browser -----------------------------------------------------------------------------------
where npm >nul 2>nul && (
  echo ==^> Setting up Playwright browser ...
  call npm install --silent 2>nul
  call npx --yes playwright install chromium 2>nul
) || (
  python -m playwright install chromium 2>nul || echo    (Playwright browser setup optional)
)

rem --- Pre-Warm AI Models (Offline Ready) -------------------------------------------------------------------
echo ==^> Pre-warming and caching AI models to data\models ...
python -m osnit warmup

echo.
echo Tip: all data lives in the single SQLite file  data\osnit.db  (no server to run).
echo      To browse/manage it visually, install "DB Browser for SQLite" (https://sqlitebrowser.org).
echo.
echo Done! Start the app by double-clicking run.bat (opens http://localhost:8080)
pause
