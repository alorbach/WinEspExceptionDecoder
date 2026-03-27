#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "Virtual environment not found. Run setup.sh first."
  exit 1
fi

exec "$ROOT/.venv/bin/python" -m winespexceptiondecoder
