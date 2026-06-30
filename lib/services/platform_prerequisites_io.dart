import 'dart:io';

import 'package:cybersentinel/services/linux_prerequisites.dart';
import 'package:cybersentinel/services/windows_prerequisites.dart';

Future<void> ensureReady() async {
  if (Platform.isWindows) {
    await WindowsPrerequisites.ensureReady();
    return;
  }
  if (Platform.isLinux) {
    await LinuxPrerequisites.ensureReady();
    return;
  }
}

String get bootTitle => 'Starting CyberSentinel…';

String get bootSubtitle {
  if (Platform.isWindows) {
    return 'Starting local security engine on http://127.0.0.1:8000';
  }
  if (Platform.isLinux) {
    return 'Starting local security engine';
  }
  return 'Starting local security engine';
}

bool get supportsDesktopEngine => Platform.isWindows || Platform.isLinux;
