#!/usr/bin/env bash
# Starts only the Python security engine (FastAPI/uvicorn) on its own,
# useful for development, testing with curl/Postman, or headless use.
#
# Uses the project-local .venv created by start_app.sh if present, so
# behavior matches the full app. Falls back to whatever 'python3' resolves
# to on PATH if start_app.sh hasn't been run yet.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="$ROOT_DIR/.venv/bin/python3"

if [ -x "$VENV_PYTHON" ]; then
  PYTHON_BIN="$VENV_PYTHON"
else
  echo "No .venv found — run scripts/start_app.sh once first to set one up."
  echo "Falling back to 'python3' on PATH for this run."
  PYTHON_BIN="python3"
fi

cd "$ROOT_DIR/backend"
"$PYTHON_BIN" -m uvicorn main:app --host 127.0.0.1 --port 8765 --reload
