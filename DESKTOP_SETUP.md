# CyberSentinel desktop app — exact setup for this project

**Flutter app:** `C:\Users\hamma\OneDrive\Desktop\New folder`  
**Backend repo:** `C:\Users\hamma\OneDrive\Desktop\cybersentinel`

## What happens when a user opens the app

1. Flutter starts (`cybersentinel.exe`)
2. `BackendLauncher` runs `engine\cybersentinel_engine.exe` automatically
3. App waits for `http://127.0.0.1:8000/health`
4. Login and all API calls use that local URL → Supabase in the cloud

No Python install. No manual `uvicorn`.

---

## User PC requirements (automatic)

| Requirement | How it is handled |
|-------------|-------------------|
| **Run as Administrator** | Built into `cybersentinel.exe` and `cybersentinel_engine.exe` — Windows shows one UAC prompt on launch |
| **Npcap** | Bundled in `deps\npcap-installer.exe`; installed silently by the setup wizard or on first app start |
| **Internet** | Required for Supabase |

---

## One-time setup (you, the developer)

### 1. Build and copy the engine into Flutter

Open PowerShell:

```powershell
cd "C:\Users\hamma\OneDrive\Desktop\New folder"
.\scripts\sync_engine.ps1
```

This runs `cybersentinel\packaging\windows\build_engine.ps1` and copies output to:

```
C:\Users\hamma\OneDrive\Desktop\New folder\windows\runner\engine\
  cybersentinel_engine.exe
  engine.env
  supervised_learning\models\
  unsupervised_learning\models\
  _internal\
```

`engine.env` is created from your `cybersentinel-backend\.env` if present.

### 2. Download Npcap installer (for bundling)

```powershell
cd "C:\Users\hamma\OneDrive\Desktop\New folder"
.\scripts\sync_npcap.ps1
```

### 3. Run the Flutter app

```powershell
cd "C:\Users\hamma\OneDrive\Desktop\New folder"
flutter pub get
flutter run -d windows
```

On each `flutter run` / `flutter build windows`, CMake copies `windows\runner\engine\` next to the built `.exe` as `engine\`.

### 3. Prerequisites on the PC

- **Npcap** — https://npcap.com (for live packet capture)
- **Run as Administrator** — for capture / firewall monitor

---

## Folder layout after install (end user)

```
C:\Program Files\CyberSentinel\
  cybersentinel.exe
  data\
  engine\
    cybersentinel_engine.exe
    engine.env
```

---

### Full release build (engine + Npcap + Flutter)

```powershell
cd "C:\Users\hamma\OneDrive\Desktop\New folder"
.\scripts\prepare_release.ps1
```

---

## Ship a single installer

```powershell
# 1. Sync engine (above)
cd "C:\Users\hamma\OneDrive\Desktop\New folder"
.\scripts\sync_engine.ps1

# 2. Flutter release build
flutter build windows --release

# 3. Inno Setup (install from https://jrsoftware.org/isinfo.php)
cd "C:\Users\hamma\OneDrive\Desktop\cybersentinel\packaging\windows"
iscc installer.iss `
  /DFLUTTER_BUILD="C:\Users\hamma\OneDrive\Desktop\New folder\build\windows\x64\runner\Release"
```

Output: `packaging\windows\output\CyberSentinel-Setup.exe`

---

## Code already wired in this app

| File | Role |
|------|------|
| `lib/services/backend_launcher.dart` | Starts/stops `cybersentinel_engine.exe` |
| `lib/widgets/shared/engine_boot_screen.dart` | Splash while engine boots |
| `lib/main.dart` | Boots engine before login |
| `lib/services/api_config.dart` | Uses `http://127.0.0.1:8000` |
| `windows/CMakeLists.txt` | Copies `engine/` into build output |

---

## If engine fails to start

1. Run manually to see errors:
   ```powershell
   cd "C:\Users\hamma\OneDrive\Desktop\New folder\windows\runner\engine"
   .\cybersentinel_engine.exe
   ```
2. Check `engine.env` — `DATABASE_URL` and `JWT_SECRET_KEY` must match Supabase.
3. Re-run `.\scripts\sync_engine.ps1` after backend code changes.

---

# Linux release (same Flutter project)

## Build on Linux or WSL2

```bash
cd "/path/to/New folder"
chmod +x scripts/*.sh linux/runner/deps/*.sh
./scripts/prepare_release_linux.sh
```

Ship: `cybersentinel/packaging/linux/output/CyberSentinel-linux-x64.tar.gz`

## End user install (wizard)

```bash
tar -xzf CyberSentinel-linux-x64.tar.gz
./install.sh
```

Installs to `/opt/cybersentinel`, installs **libpcap**, applies **setcap** for capture, adds menu shortcut.

## Linux vs Windows

| | Windows | Linux |
|---|---------|-------|
| Engine binary | `cybersentinel_engine.exe` | `cybersentinel_engine` |
| Capture driver | Npcap | libpcap |
| Privileges | Administrator (UAC) | `cap_net_raw` on engine |
| Sync script | `scripts/sync_engine.ps1` | `scripts/sync_engine.sh` |
| Release script | `scripts/prepare_release.ps1` | `scripts/prepare_release_linux.sh` |
| Installer | `CyberSentinel-Setup.exe` (Inno Setup) | `CyberSentinel-linux-x64.tar.gz` + `install.sh` |

See `cybersentinel/packaging/linux/README.md` for full details.
