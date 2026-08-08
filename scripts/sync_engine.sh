#!/usr/bin/env bash
# Builds the Python engine and copies it into the Flutter Linux runner folder.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLUTTER_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_REPO="${BACKEND_REPO:-$HOME/Desktop/cybersentinel}"
# Windows path when running from WSL — override BACKEND_REPO if needed
if [[ -d "/mnt/c/Users/hamma/OneDrive/Desktop/cybersentinel" ]]; then
  BACKEND_REPO="${BACKEND_REPO:-/mnt/c/Users/hamma/OneDrive/Desktop/cybersentinel}"
fi

BUILD_SCRIPT="$BACKEND_REPO/packaging/linux/build_engine.sh"
ENGINE_DIST="$BACKEND_REPO/packaging/linux/dist/CyberSentinelEngine"
FLUTTER_ENGINE="$FLUTTER_ROOT/linux/runner/engine"
BACKEND_ENV="$BACKEND_REPO/cybersentinel-backend/.env"

echo "Flutter app:  $FLUTTER_ROOT"
echo "Backend repo: $BACKEND_REPO"

if [[ ! -f "$BUILD_SCRIPT" ]]; then
  echo "ERROR: $BUILD_SCRIPT not found" >&2
  exit 1
fi

bash "$BUILD_SCRIPT"

if [[ ! -x "$ENGINE_DIST/cybersentinel_engine" ]]; then
  LEGACY="$BACKEND_REPO/cybersentinel-backend/dist/CyberSentinelEngine"
  if [[ -x "$LEGACY/cybersentinel_engine" ]]; then
    ENGINE_DIST="$LEGACY"
  else
    echo "ERROR: engine binary missing" >&2
    exit 1
  fi
fi

rm -rf "$FLUTTER_ENGINE"
cp -a "$ENGINE_DIST" "$FLUTTER_ENGINE"
chmod +x "$FLUTTER_ENGINE/cybersentinel_engine"

if [[ -f "$BACKEND_ENV" ]]; then
  cp "$BACKEND_ENV" "$FLUTTER_ENGINE/engine.env"
  echo "Synced engine.env from backend .env"
fi

chmod +x "$FLUTTER_ROOT/linux/runner/deps/"*.sh 2>/dev/null || true

echo "Engine installed at $FLUTTER_ENGINE/cybersentinel_engine"
echo "Next: flutter build linux --release"
