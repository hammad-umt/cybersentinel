#!/usr/bin/env bash
# Full Linux release prep: engine + Flutter bundle + tar.gz installer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLUTTER_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_REPO="${BACKEND_REPO:-/mnt/c/Users/hamma/OneDrive/Desktop/cybersentinel}"

echo "==> 1/3 Sync backend engine"
BACKEND_REPO="$BACKEND_REPO" bash "$SCRIPT_DIR/sync_engine.sh"

echo "==> 2/3 Flutter Linux release"
cd "$FLUTTER_ROOT"
flutter pub get
flutter build linux --release

echo "==> 3/3 Create tar.gz installer"
FLUTTER_ROOT="$FLUTTER_ROOT" \
FLUTTER_BUILD="$FLUTTER_ROOT/build/linux/x64/release/bundle" \
bash "$BACKEND_REPO/packaging/linux/bundle_release.sh"

echo ""
echo "Release archive:"
echo "  $BACKEND_REPO/packaging/linux/output/CyberSentinel-linux-x64.tar.gz"
