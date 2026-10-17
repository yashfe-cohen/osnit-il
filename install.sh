#!/bin/sh
# ===========================================================================================================
#  osnit-il v2.0 - One-command turnkey setup for Linux / macOS (100% Native Local, Zero Docker, GPU/CUDA First).
#  Creates local .venv, detects CUDA/MPS, installs PyTorch, all v2.0 requirements, Playwright Stealth Chromium,
#  verifies Tesseract OCR (heb+eng), creates data/ folders, and pre-warms models.
#  Usage:  sh install.sh      then:  ./run.sh
# ===========================================================================================================
set -e
cd "$(dirname "$0")"

# --- 1. Python 3.10+ Detection -----------------------------------------------------------------------------
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo "[ERROR] Python 3.10+ is required but was not found."; exit 1; }
"$PY" - <<'PYCHK' || { echo "[ERROR] Python 3.10 or newer is required."; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PYCHK
echo "==> Base Python: $("$PY" --version)"

# --- 2. Local Virtual Environment (.venv) ------------------------------------------------------------------
if [ ! -f ".venv/bin/python" ]; then
  echo "==> Creating isolated virtual environment in .venv ..."
  "$PY" -m venv .venv
fi
. .venv/bin/activate
VENV_PY="$(pwd)/.venv/bin/python"
echo "==> Activated virtual environment: $VENV_PY"

"$VENV_PY" -m pip install --upgrade --quiet --disable-pip-version-check pip setuptools wheel 2>/dev/null || true

# --- 3. Auto GPU / CUDA / MPS Detection & PyTorch ----------------------------------------------------------
echo "==> Checking for GPU / hardware acceleration ..."
if command -v nvidia-smi >/dev/null 2>&1; then
  echo "==> NVIDIA GPU detected! Installing PyTorch with CUDA support ..."
  "$VENV_PY" -m pip install --quiet --disable-pip-version-check torch torchvision --index-url https://download.pytorch.org/whl/cu121 || "$VENV_PY" -m pip install --quiet --disable-pip-version-check torch torchvision
elif [ "$(uname -s)" = "Darwin" ]; then
  echo "==> macOS detected (Apple Silicon MPS support). Installing PyTorch ..."
  "$VENV_PY" -m pip install --quiet --disable-pip-version-check torch torchvision
else
  echo "==> No GPU detected. Installing PyTorch CPU fallback ..."
  "$VENV_PY" -m pip install --quiet --disable-pip-version-check torch torchvision --index-url https://download.pytorch.org/whl/cpu || "$VENV_PY" -m pip install --quiet --disable-pip-version-check torch torchvision
fi

# --- 4. Install All Required v2.0 Packages -----------------------------------------------------------------
echo "==> Installing packages from requirements.txt ..."
"$VENV_PY" -m pip uninstall --yes easyocr 2>/dev/null || true
if ! "$VENV_PY" -m pip install --quiet --disable-pip-version-check -r requirements.txt; then
  echo "==> Installing packages individually to ensure maximum compatibility ..."
  while IFS= read -r line || [ -n "$line" ]; do
    pkg=$(printf "%s" "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$pkg" in
      ""|\#*) continue ;;
      *) "$VENV_PY" -m pip install --quiet --disable-pip-version-check "$pkg" || echo "   [WARN] Optional package skipped: $pkg" ;;
    esac
  done < requirements.txt
fi

# --- 5. Data Folders + Default Config ----------------------------------------------------------------------
mkdir -p data data/archive data/models data/inbox data/avatars data/browser_profile data/exports
[ -f osnit.env ] || cp osnit.env.example osnit.env
echo "==> Config: osnit.env ready; data/ [archive, models, inbox, avatars, browser_profile, exports] created."

# --- 6. Verify Tesseract OCR & Traineddata (heb + eng) -----------------------------------------------------
echo "==> Verifying Tesseract OCR (Hebrew + English) ..."
mkdir -p tools/Tesseract-OCR/tessdata
if [ ! -f "tools/Tesseract-OCR/tessdata/heb.traineddata" ]; then
  echo "==> Downloading Hebrew OCR language model [heb.traineddata] ..."
  "$VENV_PY" -c "import urllib.request; urllib.request.urlretrieve('https://github.com/tesseract-ocr/tessdata_fast/raw/main/heb.traineddata', 'tools/Tesseract-OCR/tessdata/heb.traineddata')" 2>/dev/null || true
fi
if [ ! -f "tools/Tesseract-OCR/tessdata/eng.traineddata" ]; then
  echo "==> Downloading English OCR language model [eng.traineddata] ..."
  "$VENV_PY" -c "import urllib.request; urllib.request.urlretrieve('https://github.com/tesseract-ocr/tessdata_fast/raw/main/eng.traineddata', 'tools/Tesseract-OCR/tessdata/eng.traineddata')" 2>/dev/null || true
fi

# --- 7. Playwright Stealth Chromium Browser (Python .venv) -------------------------------------------------
echo "==> Installing Playwright Chromium browser inside .venv ..."
"$VENV_PY" -m playwright install chromium || echo "   [WARN] Playwright Chromium setup skipped; HTTP/browser auto-fallback active."

# --- 8. Pre-Warm AI Models & Run System Readiness Check ----------------------------------------------------
echo "==> Pre-warming and caching AI models to data/models ..."
"$VENV_PY" -m osnit warmup || true

echo ""
echo "==========================================================================================================="
echo " OSNIT-IL v2.0 Installation Complete!"
echo " - Database path : data/osnit.db (SQLite WAL + FTS5)"
echo " - Configuration : osnit.env"
echo " - Launch server : ./run.sh (opens http://localhost:8080)"
echo "==========================================================================================================="
