#!/bin/sh
# ===========================================================================================================
#  osnit-il v2.0 — One-command setup for Linux / macOS (100% Native Local, Zero Docker, GPU/CUDA First).
#  Creates local .venv, detects CUDA/MPS, installs PyTorch, Tesseract OCR, DictaBERT-NER, and pre-warms models.
#  Usage:  sh install.sh      then:  ./run.sh
# ===========================================================================================================
set -e
cd "$(dirname "$0")"

# --- Python 3.10+ -------------------------------------------------------------------------------------------
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo "ERROR: Python 3.10+ is required but was not found."; exit 1; }
"$PY" - <<'PYCHK' || { echo "ERROR: Python 3.10 or newer is required."; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PYCHK
echo "==> Python: $("$PY" --version)"

# --- Local Virtual Environment (.venv) ----------------------------------------------------------------------
if [ ! -d .venv ]; then
  echo "==> Creating isolated virtual environment in .venv ..."
  "$PY" -m venv .venv
fi
. .venv/bin/activate
echo "==> Activated virtual environment: $VIRTUAL_ENV"

python -m pip install --upgrade --quiet --disable-pip-version-check pip 2>/dev/null || true

# --- Auto GPU / CUDA / MPS Detection ------------------------------------------------------------------------
echo "==> Checking for GPU / hardware acceleration ..."
if command -v nvidia-smi >/dev/null 2>&1; then
  echo "==> NVIDIA GPU detected! Installing PyTorch with CUDA support ..."
  pip install --quiet torch torchvision --index-url https://download.pytorch.org/whl/cu121 || pip install torch torchvision
elif [ "$(uname -s)" = "Darwin" ]; then
  echo "==> macOS detected (Apple Silicon MPS support). Installing PyTorch ..."
  pip install --quiet torch torchvision
else
  echo "==> No GPU detected. Installing PyTorch CPU fallback ..."
  pip install --quiet torch torchvision --index-url https://download.pytorch.org/whl/cpu || pip install torch torchvision
fi

# --- Install All Required v2.0 Packages ---------------------------------------------------------------------
echo "==> Installing packages from requirements.txt ..."
pip uninstall --yes easyocr 2>/dev/null || true
pip install --quiet --disable-pip-version-check -r requirements.txt || echo "   (some optional packages skipped)"

# --- Data Folders + Config ----------------------------------------------------------------------------------
mkdir -p data data/archive data/models data/inbox
[ -f osnit.env ] || cp osnit.env.example osnit.env
echo "==> Config: osnit.env ready, data/ archive/ models/ inbox/ created"

# --- Playwright Browser -------------------------------------------------------------------------------------
if command -v npm >/dev/null 2>&1; then
  npm install --silent 2>/dev/null || true
  npx --yes playwright install chromium 2>/dev/null || true
elif command -v playwright >/dev/null 2>&1; then
  playwright install chromium 2>/dev/null || true
fi

# --- Pre-Warm AI Models (Offline Ready) ---------------------------------------------------------------------
echo "==> Pre-warming and caching AI models to data/models ..."
python -m osnit warmup || true

echo ""
echo "Done! Start the app with:   ./run.sh      (opens http://localhost:8080)"
