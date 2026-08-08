# CyberSentinel

**Intelligent Network Security Dashboard** - A comprehensive cross-platform network security monitoring and analysis application built with Flutter.

## Features

- 🔍 **Real-time Packet Capture & Analysis** - Monitor network traffic in real-time
- 🌍 **IP Intelligence & Geolocation** - Analyze IP addresses with comprehensive threat intel
- 🚨 **Security Alerts & Notifications** - Real-time alerts for suspicious network activities
- 🦠 **Virus Scanner Integration** - Built-in malware detection capabilities
- 📊 **SOC Dashboard** - Security Operations Center-style unified monitoring
- 🤖 **AI-Powered Copilot Assistant** - Intelligent security threat analysis
- 🖥️ **Multi-platform Support** - Windows, macOS, Linux, iOS, and Android
- 🔐 **JWT Authentication** - Secure user authentication system
- 🛡️ **Firewall Integration** - Active firewall status monitoring

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Requirements](#requirements)
- [Installation & Setup](#installation--setup)
- [Running the Application](#running-the-application)
- [Build Automation](#build-automation)
- [Contributing](#contributing)
- [License](#license)

## Overview

CyberSentinel is an enterprise-grade network security tool providing comprehensive monitoring, analysis, and threat detection capabilities across all major platforms. Whether you're a security professional, system administrator, or developer, CyberSentinel offers the tools you need for effective network defense.

## Project Structure

```
cs-frontend/
├── lib/                          # Flutter/Dart application code
│   ├── auth/                     # Authentication & login flows
│   ├── services/                 # Core services (API, auth, firewall)
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
├── packaging/                    # Installer and packaging
├── pubspec.yaml                  # Flutter dependencies
└── README.md                     # This file
```

## Technology Stack

- **Frontend**: Flutter (Dart)
- **Backend**: RESTful API with JWT authentication
- **Package Management**: Pub (Dart package manager)
- **Build System**: Flutter build tools with platform-specific configs
- **Desktop Runtime**: Python-based engine for advanced analysis
- **VCS**: Git with GitHub

## Requirements

### Minimum System Requirements

- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 2GB free space
- **OS**: Windows 10+, macOS 10.14+, Ubuntu 18.04+, iOS 12+, Android 8.0+

### Development Requirements

- **Flutter SDK**: Latest stable version
- **Dart SDK**: 3.0+ (included with Flutter)
- **Android Studio** (for Android development)
- **Xcode** (for iOS/macOS development)
- **Visual Studio** or MSVC (for Windows development)
- **CMake**: 3.10+
- **Visual C++ Build Tools**

## Installation & Setup

### 1. Clone Repository

```bash
git clone https://github.com/hammad-umt/cybersentinel.git
cd cybersentinel
```

### 2. Install Dependencies

```bash
flutter pub get
flutter pub upgrade
```

### 3. Set Up Backend Configuration

Edit `lib/services/api_config.dart`:
```dart
const String API_BASE_URL = 'your_backend_url';
const int API_TIMEOUT_SECONDS = 30;
```

### 4. Platform-Specific Setup

#### Windows
```bash
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
Install dependencies:
```bash
sudo apt-get install libgtk-3-dev libx11-dev pkg-config cmake ninja-build libblkid-dev liblzma-dev
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
No additional setup required. Use Android Studio or:
```bash
flutter run -d android
```

## Running the Application

### Development Mode

```bash
# Run on default device
flutter run

# Run with specific device
flutter run -d <device_id>

# Run with hot reload enabled
flutter run --hot
```

### Release Build

```bash
# Windows
flutter build windows --release

# macOS
flutter build macos --release

# Linux
flutter build linux --release

# iOS
flutter build ios --release

# Android
flutter build apk --release
flutter build appbundle --release

# Web
flutter build web --release
```

## Build Automation

### Release Scripts

Automated release preparation:

```powershell
# Prepare release for all platforms
.\scripts\prepare_release.ps1

# Prepare release for Linux
.\scripts\prepare_release_linux.sh

# Publish release
.\scripts\publish_release.ps1

# Sync Python engine
.\scripts\sync_engine.ps1

# Sync VC++ redistributables
.\scripts\sync_vcredist.ps1
```

### Quick Build (Windows only)

```powershell
.\build-installer-only.ps1
```

## Configuration Files

- **`pubspec.yaml`** - Flutter dependencies and project configuration
- **`analysis_options.yaml`** - Dart linter configuration
- **`devtools_options.yaml`** - DevTools preferences
- **`DESKTOP_SETUP.md`** - Desktop environment setup guide
- **`.gitignore`** - Git exclusions (build artifacts, dependencies, etc.)

## Key Features Implementation

### Authentication (`lib/auth/`)
- Login screen with email/password
- Registration flow
- Password reset functionality
- JWT token management
- Protected route authentication

### Services (`lib/services/`)
- **API Service** - RESTful backend communication
- **Auth Service** - User authentication and session management
- **Firewall Monitor** - System firewall status tracking
- **Packet Capture** - Network packet interception and analysis
- **Security Alert** - Real-time threat notifications
- **Backend Launcher** - Python engine initialization
- **Desktop Runtime Config** - Platform-specific settings

### UI Widgets (`lib/widgets/`)
- **Dashboard** - Main security overview
- **IP Analysis** - IP geolocation and threat intel
- **Packet Tracing** - Network traffic visualization
- **Virus Scanner** - Malware detection interface
- **Copilot Assistant** - AI-powered threat analysis
- **Reports** - Security report generation
- **Settings** - User preferences and configuration

### Theming
- Light and dark mode support
- Custom color scheme (`lib/theme/app_colors.dart`)
- Consistent UI across all platforms

## Development Guidelines

### Code Style

- Follow Dart effective practices: https://dart.dev/guides/language/effective-dart
- Use `dart format` for code formatting
- Enable linting with `analysis_options.yaml`

### Naming Conventions

- Files: `snake_case` (e.g., `auth_service.dart`)
- Classes: `PascalCase` (e.g., `AuthService`)
- Functions/variables: `camelCase` (e.g., `fetchUserData`)
- Constants: `lowerCamelCase` (e.g., `apiBaseUrl`)

### Folder Organization

- One main class per file
- Related functionality grouped by feature
- Shared utilities in `utils/` directory
- Platform-specific code in platform directories

## Testing

```bash
# Run all tests
flutter test

# Run specific test
flutter test test/widget_test.dart

# Generate coverage report
flutter test --coverage
```

## Troubleshooting

### Common Issues

**Build Failures**
- Run `flutter clean` to remove build cache
- Update Flutter: `flutter upgrade`
- Check platform requirements are installed

**Dependency Issues**
- Clear pub cache: `flutter pub cache clean`
- Reinstall dependencies: `rm pubspec.lock && flutter pub get`

**Platform-Specific Issues**
- See `DESKTOP_SETUP.md` for Windows/Linux setup
- For iOS: Check Xcode version compatibility
- For Android: Verify Android SDK versions in `android/build.gradle`

## Contributing

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Commit changes: `git commit -am 'Add new feature'`
3. Push to branch: `git push origin feature/your-feature`
4. Submit pull request

## Documentation

- **Setup Guide**: See `DESKTOP_SETUP.md`
- **Presentation**: See `FYP_PRESENTATION_GUIDE.md`
- **API Config**: See `lib/services/api_config.dart`

## Security Notes

- JWT tokens are stored securely per platform standards
- API endpoints require HTTPS in production
- Sensitive credentials should be stored in environment variables
- Do not commit `.env` files or private keys

## Performance Optimization

- Use lazy loading for heavy widgets
- Implement pagination for large datasets
- Cache API responses where appropriate
- Use const constructors for widgets

## Platform Versions

- **Flutter**: Latest stable
- **Dart**: 3.0+
- **Android**: API 21+ (minSdkVersion)
- **iOS**: 12.0+
- **Windows**: Windows 10+
- **macOS**: 10.14+
- **Linux**: Ubuntu 18.04+

## License

[Your License Here]

## Support

For issues, bug reports, or feature requests, please create an issue on GitHub.

## Authors

- **Development Team**: CyberSentinel Project

## Changelog

### Latest Version
- Multi-platform support (Windows, macOS, Linux, iOS, Android, Web)
- Real-time packet capture and analysis
- AI-powered threat detection
- Security Copilot assistant
- Enhanced UI/UX with light/dark themes
- JWT authentication system
- Comprehensive IP intelligence
- Firewall monitoring integration

---

**Last Updated**: August 9, 2026

**Repository**: [CyberSentinel on GitHub](https://github.com/hammad-umt/cybersentinel)

---

## License

This project is proprietary software. All rights reserved. Unauthorized copying, modification, or distribution is prohibited.

## Support & Contact

For issues, bug reports, or feature requests, please create an issue on GitHub.

---

**Built with ❤️ using Flutter**
 
 
