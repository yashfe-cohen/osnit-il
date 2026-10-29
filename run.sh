#!/bin/sh
# ===========================================================================================================
#  OSNIT-IL v2.0 - Start the local server on http://localhost:8080
#  Automatically runs first-time setup (install.sh) if .venv has not been created yet.
# ===========================================================================================================
set -e
cd "$(dirname "$0")"

if [ ! -f ".venv/bin/python" ]; then
  echo "==> First-time setup detected (.venv not found). Running install.sh automatically ..."
  sh ./install.sh
fi

. .venv/bin/activate
mkdir -p data data/archive data/models data/inbox data/avatars data/browser_profile data/exports
[ -f osnit.env ] || cp osnit.env.example osnit.env

echo "==> Starting OSNIT-IL v2.0 on http://localhost:${PORT:-8080}"
exec "$(pwd)/.venv/bin/python" -m osnit serve --port "${PORT:-8080}" --open "$@"
