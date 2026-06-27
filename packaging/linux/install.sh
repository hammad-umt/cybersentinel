#!/usr/bin/env bash
# Interactive installer for CyberSentinel Linux bundle (tar.gz contents).
set -euo pipefail

APP_NAME="CyberSentinel"
INSTALL_DIR="${INSTALL_DIR:-/opt/cybersentinel}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$SCRIPT_DIR"

echo "======================================"
echo "  $APP_NAME Linux Installer"
echo "======================================"
echo ""
echo "This will install to: $INSTALL_DIR"
read -r -p "Continue? [Y/n] " reply
if [[ "${reply,,}" == "n" ]]; then
  echo "Cancelled."
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Requesting administrator privileges..."
  exec sudo INSTALL_DIR="$INSTALL_DIR" bash "$0"
fi

mkdir -p "$INSTALL_DIR"
cp -a "$BUNDLE_DIR/." "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/cybersentinel" "$INSTALL_DIR/engine/cybersentinel_engine" 2>/dev/null || true

if [[ -f "$INSTALL_DIR/deps/install_libpcap.sh" ]]; then
  echo "==> Installing libpcap if needed..."
  bash "$INSTALL_DIR/deps/install_libpcap.sh" || true
fi

if [[ -f "$INSTALL_DIR/engine/cybersentinel_engine" ]]; then
  echo "==> Applying packet capture capabilities to engine..."
  if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin+eip "$INSTALL_DIR/engine/cybersentinel_engine"
  fi
fi

if [[ "$(id -u)" -eq 0 ]]; then
  DESKTOP_DIR="/usr/share/applications"
else
  DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
fi
mkdir -p "$DESKTOP_DIR"
cat >"$DESKTOP_DIR/cybersentinel.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_NAME
Comment=Network security monitoring
Exec=$INSTALL_DIR/cybersentinel
Icon=$INSTALL_DIR/data/flutter_assets/assets/Icon-192.png
Terminal=false
Categories=Network;Security;
EOF

echo ""
echo "Installed to $INSTALL_DIR"
echo "Launch from your app menu or run: $INSTALL_DIR/cybersentinel"
