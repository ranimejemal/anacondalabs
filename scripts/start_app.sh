#!/usr/bin/env bash
# AegisLab launcher (macOS/Linux) — one-click setup + run.
# ---------------------------------------------------------
# On first run: creates a local Python virtual environment (.venv) at the
# project root, installs backend/requirements.txt into it, and installs the
# Electron frontend's node_modules. On every run after that, those steps are
# skipped automatically since they're already done, and it just launches.
#
# No conda, no manual "activate" step, no prior setup required — only a
# system Python 3.11+ and Node.js need to already be installed.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$ROOT_DIR/.venv"

echo "=== AegisLab setup & launch ==="

# --- 1. Find a usable system Python (3.11+) ---
PYTHON_BIN=""
for cmd in python3.12 python3.11 python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then
    ver="$("$cmd" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "0.0")"
    major="${ver%%.*}"; minor="${ver##*.}"
    if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
      PYTHON_BIN="$cmd"
      break
    fi
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  echo ""
  echo "ERROR: No Python 3.11+ interpreter found on PATH."
  echo "Install Python 3.11 or newer from https://www.python.org/downloads/ and re-run this script."
  echo "(If you use conda/pyenv/etc, just make sure 'python3' on PATH resolves to 3.11+ before running this.)"
  exit 1
fi
echo "Using system Python: $PYTHON_BIN ($("$PYTHON_BIN" --version))"

# --- 2. Create the project-local venv if it doesn't exist yet ---
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment at $VENV_DIR (first run only)..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python3"
if [ ! -x "$VENV_PYTHON" ]; then
  echo "ERROR: venv creation appears to have failed — $VENV_PYTHON not found or not executable."
  exit 1
fi

# --- 3. Install/update backend dependencies (fast no-op if already satisfied) ---
echo "Checking backend dependencies..."
"$VENV_PYTHON" -m pip install --quiet --upgrade pip
"$VENV_PYTHON" -m pip install --quiet -r "$ROOT_DIR/requirements.txt"

export AEGISLAB_PYTHON="$VENV_PYTHON"
echo "Backend will run on: $AEGISLAB_PYTHON"

# --- 4. Check Node.js / npm are present ---
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo ""
  echo "ERROR: Node.js (with npm) is required to run the AegisLab desktop app but wasn't found on PATH."
  echo "Install it from https://nodejs.org/ (LTS version) and re-run this script."
  exit 1
fi

# --- 5. Install frontend dependencies if missing ---
cd "$ROOT_DIR/frontend"
if [ ! -d "node_modules" ]; then
  echo "Installing Electron dependencies (first run only)..."
  npm install
fi

# --- 6. Optional: warn if AI/Supabase env vars aren't configured ---
if [ ! -f "$ROOT_DIR/backend/.env" ]; then
  echo ""
  echo "NOTE: backend/.env not found — AI suggestions and account sign-in will show a"
  echo "'not configured' message until you copy backend/.env.example to backend/.env"
  echo "and fill in your Supabase/Anthropic keys. Scanning itself works fine without it."
fi

echo ""
echo "Launching AegisLab..."
npm start
