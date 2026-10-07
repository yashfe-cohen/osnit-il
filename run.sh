#!/bin/sh
# OSNIT-IL: start the local site on http://localhost:8080
cd "$(dirname "$0")"
python3 -m pip install --quiet --disable-pip-version-check pypdf 2>/dev/null
mkdir -p data
[ -f osnit.env ] || cp osnit.env.example osnit.env
exec python3 -m osnit serve --port "${PORT:-8080}" --open "$@"
