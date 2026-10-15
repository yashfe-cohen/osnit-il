#!/bin/sh
# OSNIT-IL v2.0: start the local site on http://localhost:8080
cd "$(dirname "$0")"
[ -f .venv/bin/activate ] && . .venv/bin/activate
mkdir -p data data/archive data/models data/inbox
[ -f osnit.env ] || cp osnit.env.example osnit.env
exec python -m osnit serve --port "${PORT:-8080}" --open "$@"
