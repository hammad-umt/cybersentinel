#!/usr/bin/env bash
# Create CyberSentinel-linux-x64.tar.gz from flutter build bundle + engine.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLUTTER_ROOT="${FLUTTER_ROOT:-/path/to/flutter/project}"
BUNDLE_SRC="${FLUTTER_BUILD:-$FLUTTER_ROOT/build/linux/x64/release/bundle}"
ENGINE_SRC="${ENGINE_BUILD:-$SCRIPT_DIR/dist/CyberSentinelEngine}"
OUTPUT_DIR="$SCRIPT_DIR/output"
STAGING="$OUTPUT_DIR/staging"
ARCHIVE="$OUTPUT_DIR/CyberSentinel-linux-x64.tar.gz"

if [[ ! -x "$BUNDLE_SRC/cybersentinel" ]]; then
  echo "Flutter Linux bundle not found: $BUNDLE_SRC/cybersentinel" >&2
  echo "Run: flutter build linux --release" >&2
  exit 1
fi
if [[ ! -x "$ENGINE_SRC/cybersentinel_engine" ]]; then
  echo "Engine not found: $ENGINE_SRC/cybersentinel_engine" >&2
  echo "Run: packaging/linux/build_engine.sh" >&2
  exit 1
fi

rm -rf "$STAGING"
mkdir -p "$STAGING"
cp -a "$BUNDLE_SRC/." "$STAGING/"
cp -a "$ENGINE_SRC" "$STAGING/engine"
cp "$SCRIPT_DIR/install.sh" "$STAGING/install.sh"
chmod +x "$STAGING/install.sh" "$STAGING/engine/cybersentinel_engine"

mkdir -p "$OUTPUT_DIR"
tar -czf "$ARCHIVE" -C "$STAGING" .
echo "==> Created $ARCHIVE"
echo "    Users extract and run: ./install.sh"
