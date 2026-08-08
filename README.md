# CyberSentinel

**Intelligent Network Security Dashboard** — A comprehensive cross-platform network security monitoring and analysis application built with Flutter and a Python-based security analysis engine.

## Features

- 🔍 **Real-time Packet Capture & Analysis** — Monitor and analyze network traffic
- 🌍 **IP Intelligence & Geolocation** — Analyze IP addresses using threat intelligence and geolocation data
- 🚨 **Security Alerts & Notifications** — Surface suspicious network activity and security alerts
- 🦠 **Virus Scanner Integration** — Scan files using integrated malware analysis capabilities
- 📊 **SOC Dashboard** — Unified Security Operations Center-style monitoring dashboard
- 🤖 **AI-Powered Copilot Assistant** — Assist with security threat analysis
- 🖥️ **Cross-platform Support** — Flutter-based application with desktop and supported platform targets
- 🔐 **JWT Authentication** — Secure user authentication and protected access
- 🛡️ **Firewall Integration** — Monitor firewall status and security information

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Requirements](#requirements)
- [Installation & Setup](#installation--setup)
- [Running the Application](#running-the-application)
- [Build Automation](#build-automation)
- [Configuration Files](#configuration-files)
- [Key Features Implementation](#key-features-implementation)
- [Development Guidelines](#development-guidelines)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Security Notes](#security-notes)
- [Performance Optimization](#performance-optimization)
- [Contributing](#contributing)
- [License](#license)
- [Support & Contact](#support--contact)

## Overview

CyberSentinel is a network security monitoring and analysis application designed to provide multiple security capabilities through a unified interface. It combines a Flutter frontend with a Python-based analysis engine and REST API communication to support packet analysis, IP intelligence, malware scanning, firewall monitoring, reporting, alerts, and AI-assisted security analysis.

## Project Structure

```text
cs-frontend/
├── lib/                          # Flutter/Dart application code
│   ├── auth/                     # Authentication and login flows
│   ├── services/                 # Core services (API, auth, firewall, etc.)
│   ├── widgets/                  # UI screens and components
│   │   ├── copilot/             # AI assistant interface
│   │   ├── dashbaord/           # Main security dashboard
│   │   ├── ip_analysis/         # IP intelligence screens
│   │   ├── packet_tracing/      # Packet capture UI
│   │   ├── reports/             # Report generation
│   │   ├── virus_scanner/       # Malware scanner interface
│   │   ├── setings/             # User settings
│   │   └── shared/              # Common widgets
│   ├── theme/                    # App colors and theming
│   ├── utils/                    # Utility functions
│   ├── main.dart                 # App entry point
│   └── app_shell.dart            # Navigation shell
├── android/                      # Android platform code
├── ios/                          # iOS platform code
├── windows/                      # Windows platform code
├── linux/                        # Linux platform code
├── macos/                        # macOS platform code
├── web/                          # Web platform code
├── scripts/                      # Build and release automation
│   ├── prepare_release.ps1       # Release preparation
│   ├── sync_engine.ps1           # Engine synchronization
│   └── sync_vcredist.ps1         # Visual C++ redistributables
├── packaging/                    # Installer and packaging resources
├── pubspec.yaml                  # Flutter dependencies
└── README.md                     # Project documentation
```

> **Note:** The directory names above preserve the names documented in the current project (`dashbaord` and `setings`). Rename them here only if the actual source directories are renamed.

## Technology Stack

- **Frontend:** Flutter (Dart)
- **Backend Communication:** RESTful API
- **Authentication:** JWT
- **Desktop Runtime / Analysis Engine:** Python
- **Package Management:** Pub
- **Build System:** Flutter build tools with platform-specific configuration
- **Version Control:** Git / GitHub

## Requirements

### Minimum System Requirements

- **RAM:** 4 GB minimum (8 GB recommended)
- **Storage:** 2 GB free space
- **Desktop OS:** Windows 10+, macOS 10.14+, or Ubuntu 18.04+
- **Mobile:** iOS 12+ or Android 8.0+

### Development Requirements

Install the tools required for the platform you intend to build:

- **Flutter SDK:** Latest compatible stable release
- **Dart SDK:** Included with Flutter
- **Android Studio / Android SDK:** For Android development
- **Xcode:** For iOS and macOS development
- **Visual Studio / MSVC Build Tools:** For Windows development
- **CMake:** 3.10+
- **Git**

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/hammad-umt/cybersentinel.git
cd cybersentinel
```

If the Flutter application is stored inside a subdirectory, navigate to that directory before running Flutter commands.

### 2. Install Flutter Dependencies

```bash
flutter pub get
```

To check the local Flutter environment:

```bash
flutter doctor
```

### 3. Configure the Backend

Configure the API endpoint according to the implementation in:

```text
lib/services/api_config.dart
```

For example, the configuration may contain values such as:

```dart
const String API_BASE_URL = 'your_backend_url';
const int API_TIMEOUT_SECONDS = 30;
```

Replace environment-specific values with the appropriate development or production configuration. Do not commit private credentials, API keys, or secrets.

### 4. Platform-Specific Setup

#### Windows

```powershell
flutter pub get
flutter build windows
```

#### macOS

```bash
cd macos
pod install
cd ..
flutter run -d macos
```

#### Linux

Install the required Linux dependencies:

```bash
sudo apt-get install libgtk-3-dev libx11-dev pkg-config cmake ninja-build libblkid-dev liblzma-dev
```

Then run:

```bash
flutter run -d linux
```

#### iOS

```bash
cd ios
pod install
cd ..
flutter run -d ios
```

#### Android

Use Android Studio or run:

```bash
flutter run -d android
```

## Running the Application

### Development Mode

List available devices:

```bash
flutter devices
```

Run on the default available device:

```bash
flutter run
```

Run on a specific device:

```bash
flutter run -d <device_id>
```

Flutter provides hot reload automatically while the application is running in debug mode.

### Release Builds

#### Windows

```bash
flutter build windows --release
```

#### macOS

```bash
flutter build macos --release
```

#### Linux

```bash
flutter build linux --release
```

#### iOS

```bash
flutter build ios --release
```

#### Android APK

```bash
flutter build apk --release
```

#### Android App Bundle

```bash
flutter build appbundle --release
```

#### Web

```bash
flutter build web --release
```

## Build Automation

The project documentation includes scripts for release preparation and engine/runtime synchronization.

### Release Scripts

```powershell
# Prepare a release
.\scripts\prepare_release.ps1

# Publish a release, if this script exists in the checked-out project
.\scripts\publish_release.ps1

# Synchronize the Python engine
.\scripts\sync_engine.ps1

# Synchronize Visual C++ redistributables
.\scripts\sync_vcredist.ps1
```

For Linux release preparation, if the corresponding script exists:

```bash
./scripts/prepare_release_linux.sh
```

### Quick Build — Windows

If available in the project:

```powershell
.\build-installer-only.ps1
```

## Configuration Files

Important project configuration and documentation files include:

- **`pubspec.yaml`** — Flutter dependencies and project configuration
- **`analysis_options.yaml`** — Dart analyzer and lint configuration
- **`devtools_options.yaml`** — Flutter DevTools preferences
- **`DESKTOP_SETUP.md`** — Desktop environment/setup documentation, if present
- **`.gitignore`** — Files and directories excluded from Git

## Key Features Implementation

### Authentication (`lib/auth/`)

The authentication area provides the application's authentication flow, including:

- Login
- Registration
- Password reset
- JWT/session management
- Protected application access

### Services (`lib/services/`)

Core services include functionality for:

- REST API communication
- Authentication/session management
- Firewall status monitoring
- Packet capture and analysis
- Security alerts
- Python/backend engine startup
- Desktop runtime configuration

### UI Widgets (`lib/widgets/`)

The application UI includes modules for:

- **Dashboard** — Main security overview
- **IP Analysis** — IP geolocation and threat intelligence
- **Packet Tracing** — Network traffic capture and visualization
- **Virus Scanner** — Malware/file scanning interface
- **Copilot Assistant** — AI-assisted security analysis
- **Reports** — Security reporting
- **Settings** — Application preferences and configuration

### Theming

The Flutter application supports:

- Light and dark themes
- Centralized application colors
- Reusable styling across screens

The project documents its application colors under:

```text
lib/theme/app_colors.dart
```

## Development Guidelines

### Code Style

Follow Dart and Flutter conventions.

Format the project with:

```bash
dart format .
```

Analyze the project with:

```bash
flutter analyze
```

### Naming Conventions

Recommended Dart conventions:

- **Files:** `snake_case` — e.g. `auth_service.dart`
- **Classes:** `PascalCase` — e.g. `AuthService`
- **Functions and variables:** `lowerCamelCase` — e.g. `fetchUserData`
- **Constants:** `lowerCamelCase` unless project conventions specify otherwise

### Folder Organization

- Group related functionality by feature
- Keep reusable utilities in shared/service utility locations
- Keep platform-specific integration in the appropriate platform directories
- Keep UI, business logic, and external-service communication separated where practical

## Testing

Run all Flutter tests:

```bash
flutter test
```

Run a specific test:

```bash
flutter test test/widget_test.dart
```

Generate a coverage report:

```bash
flutter test --coverage
```

Run static analysis:

```bash
flutter analyze
```

## Troubleshooting

### Build Failures

Clean generated build artifacts:

```bash
flutter clean
flutter pub get
```

Check the development environment:

```bash
flutter doctor -v
```

### Dependency Issues

Refresh Flutter dependencies:

```bash
flutter pub get
```

If a dependency upgrade is intentionally required:

```bash
flutter pub upgrade
```

### Platform-Specific Issues

- **Windows:** Verify Visual Studio/MSVC desktop development components
- **macOS/iOS:** Verify Xcode and CocoaPods configuration
- **Android:** Verify Android SDK and accepted licenses
- **Linux:** Verify required GTK/CMake development packages
- **Desktop runtime:** Verify the Python analysis engine and required runtime dependencies are available

## Documentation

Additional project documentation may include:

- **Setup Guide:** `DESKTOP_SETUP.md`
- **FYP Presentation Guide:** `FYP_PRESENTATION_GUIDE.md`
- **API Configuration:** `lib/services/api_config.dart`

## Security Notes

- Keep authentication tokens protected according to platform requirements
- Use HTTPS for production API communication
- Store credentials and private API keys in environment-specific configuration
- Never commit `.env` files, private keys, access tokens, or production secrets
- Validate and sanitize untrusted input
- Apply least-privilege principles when accessing packet capture or operating-system security functionality

## Performance Optimization

Recommended Flutter practices include:

- Use lazy loading where appropriate
- Paginate large datasets
- Cache suitable API responses
- Use `const` constructors where possible
- Avoid unnecessary widget rebuilds
- Perform expensive analysis outside latency-sensitive UI operations

## Contributing

For project development:

1. Create a feature branch:

   ```bash
   git checkout -b feature/your-feature
   ```

2. Commit your changes:

   ```bash
   git commit -m "Add your feature"
   ```

3. Push the branch:

   ```bash
   git push origin feature/your-feature
   ```

4. Open a pull request for review.

## License

**Proprietary — All Rights Reserved.**

Unless explicit permission is granted by the project owner, the source code and associated project materials may not be copied, modified, distributed, or used outside their authorized purpose.

## Support & Contact

For issues, bug reports, or feature requests, use the project's GitHub repository:

**CyberSentinel:** https://github.com/hammad-umt/cybersentinel

---

**Last Updated:** August 9, 2026

**Built with Flutter and Python for the CyberSentinel project.**
