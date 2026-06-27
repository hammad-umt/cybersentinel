#!/usr/bin/env bash
# Build the CyberSentinel desktop engine for Linux (PyInstaller).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKEND="$REPO_ROOT/cybersentinel-backend"
DIST_PATH="$SCRIPT_DIR/dist"
WORK_PATH="$SCRIPT_DIR/build"
DIST_DIR="$DIST_PATH/CyberSentinelEngine"
SUPERVISED_MODELS="$REPO_ROOT/supervised_learning/models"
UNSUPERVISED_MODELS="$REPO_ROOT/unsupervised_learning/models"

PYTHON="${PYTHON:-python3}"

echo "==> CyberSentinel Linux engine build"
echo "    Repo:   $REPO_ROOT"
echo "    Python: $($PYTHON --version)"

if [[ "${SKIP_INSTALL:-0}" != "1" ]]; then
  echo "==> Installing dependencies..."
  "$PYTHON" -m pip install --upgrade pip
  "$PYTHON" -m pip install -r "$BACKEND/requirements.txt"
  "$PYTHON" -m pip install -r "$REPO_ROOT/packaging/requirements-build.txt"
fi

echo "==> Running PyInstaller..."
"$PYTHON" -m PyInstaller "$SCRIPT_DIR/cybersentinel_engine.spec" \
  --noconfirm --clean \
  --distpath "$DIST_PATH" \
  --workpath "$WORK_PATH"

if [[ ! -x "$DIST_DIR/cybersentinel_engine" ]]; then
  echo "ERROR: missing $DIST_DIR/cybersentinel_engine" >&2
  exit 1
fi

echo "==> Copying ML models..."
mkdir -p "$DIST_DIR/supervised_learning/models" "$DIST_DIR/unsupervised_learning/models"
if [[ -d "$SUPERVISED_MODELS" ]]; then
  cp -a "$SUPERVISED_MODELS/." "$DIST_DIR/supervised_learning/models/"
fi
if [[ -f "$REPO_ROOT/supervised_learning/model.py" ]]; then
  cp "$REPO_ROOT/supervised_learning/model.py" "$DIST_DIR/supervised_learning/"
fi
if [[ -d "$UNSUPERVISED_MODELS" ]]; then
  cp -a "$UNSUPERVISED_MODELS/." "$DIST_DIR/unsupervised_learning/models/"
fi
for f in "$REPO_ROOT/unsupervised_learning"/*.py; do
  [[ -f "$f" ]] && cp "$f" "$DIST_DIR/unsupervised_learning/"
done

ENGINE_ENV="$DIST_DIR/engine.env"
if [[ ! -f "$ENGINE_ENV" ]]; then
  cp "$SCRIPT_DIR/engine.env.example" "$ENGINE_ENV"
  echo "WARNING: edit $ENGINE_ENV before shipping"
elif [[ -f "$BACKEND/.env" ]]; then
  cp "$BACKEND/.env" "$ENGINE_ENV"
fi

chmod +x "$DIST_DIR/cybersentinel_engine"
echo "==> Build complete: $DIST_DIR/cybersentinel_engine"
