#!/bin/sh
# ===========================================================================================================
#  osnit-il — one-command setup for a fresh machine (Linux / macOS).
#  Installs the optional Python file-format packages and, if Node.js is present, the no-API browser search.
#  Usage:  sh install.sh      then:  ./run.sh
# ===========================================================================================================
set -e
cd "$(dirname "$0")"

# --- Python 3.10+ -------------------------------------------------------------------------------------------
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo "ERROR: Python 3.10+ is required but was not found. Install it from https://python.org"; exit 1; }
"$PY" - <<'PYCHK' || { echo "ERROR: Python 3.10 or newer is required."; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PYCHK
echo "==> Python: $("$PY" --version)"

# --- optional Python packages (pypdf, xlrd) -----------------------------------------------------------------
echo "==> Installing optional Python packages (pypdf, xlrd) ..."
"$PY" -m pip install --upgrade --quiet --disable-pip-version-check pip 2>/dev/null || true
"$PY" -m pip install --quiet --disable-pip-version-check -r requirements.txt || \
  echo "   (optional packages could not be installed — the core app still works; PDFs/.xls will be skipped)"

# --- data dir + config --------------------------------------------------------------------------------------
mkdir -p data
[ -f osnit.env ] || cp osnit.env.example osnit.env
echo "==> Config: osnit.env ready, data/ created"

# --- optional: no-API browser search (Node + Playwright + Chromium) -----------------------------------------
if command -v npm >/dev/null 2>&1; then
  echo "==> Node.js found ($(node --version)); setting up the no-API browser search ..."
  npm install --silent
  npx --yes playwright install chromium
  echo "   Browser search ready. Enable it with OSNIT_PROVIDERS=browser in osnit.env"
else
  echo "==> Node.js not found — SKIPPING the optional no-API browser search."
  echo "   To enable it later: install Node 18+ from https://nodejs.org, then run:"
  echo "       npm install && npx playwright install chromium"
fi

# --- smoke check --------------------------------------------------------------------------------------------
echo "==> Verifying the install ..."
"$PY" -m osnit stats >/dev/null 2>&1 && echo "   OK" || echo "   (first run will create the database)"

echo ""
echo "Tip: all data lives in the single SQLite file  data/osnit.db  (no server to run)."
echo "     To browse/manage it visually, install the free \"DB Browser for SQLite\""
echo "     (https://sqlitebrowser.org) and open that file — no SQL needed, nothing to change in the app."
echo ""
echo "Done. Start the app with:   ./run.sh      (opens http://localhost:8080)"
echo "Or:                         $PY -m osnit serve --port 8080 --open"
