# Linux desktop release

Build on **Ubuntu/Debian** (or WSL2 with Flutter Linux desktop enabled).

## Quick release (from Flutter project)

```bash
cd "/path/to/New folder"
chmod +x scripts/*.sh linux/runner/deps/*.sh
./scripts/prepare_release_linux.sh
```

Output: `cybersentinel/packaging/linux/output/CyberSentinel-linux-x64.tar.gz`

## What end users do

```bash
tar -xzf CyberSentinel-linux-x64.tar.gz
cd CyberSentinel-linux-x64   # or extract folder name
./install.sh
```

The install wizard asks for confirmation, then:

1. Copies app to `/opt/cybersentinel`
2. Installs **libpcap** if missing (`apt` / `dnf` / `pacman`)
3. Runs **`setcap cap_net_raw,cap_net_admin+eip`** on the engine (packet capture without full root)
4. Creates a desktop menu entry

On first launch, **pkexec** may prompt once if capabilities still need applying.

## Layout after install

```
/opt/cybersentinel/
  cybersentinel              ← Flutter UI
  lib/ data/
  engine/
    cybersentinel_engine     ← FastAPI backend
    engine.env
  deps/
    apply_caps.sh
    install_libpcap.sh
```

## Manual build steps

```bash
# 1. Engine
cd cybersentinel/packaging/linux
chmod +x build_engine.sh
./build_engine.sh

# 2. Copy into Flutter + build
cd "/path/to/New folder"
./scripts/sync_engine.sh
flutter build linux --release

# 3. Tarball
FLUTTER_ROOT="/path/to/New folder" \
FLUTTER_BUILD="/path/to/New folder/build/linux/x64/release/bundle" \
./packaging/linux/bundle_release.sh
```

## Linux dev dependencies

```bash
sudo apt install clang cmake ninja-build pkg-config libgtk-3-dev libpcap-dev libcap2-bin
```

## Windows vs Linux capture

| OS | Capture dependency | Privileges |
|----|-------------------|------------|
| Windows | Npcap (bundled installer) | Administrator (UAC) |
| Linux | libpcap (`libpcap0.8`) | `cap_net_raw` on engine via `setcap` |

## .deb package (optional)

`packaging/linux/debian/` contains `control` and `postinst` templates. Point `dpkg-deb` at a staged `/opt/cybersentinel` tree for distribution on Debian/Ubuntu.
