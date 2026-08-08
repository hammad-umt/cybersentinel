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
    return 'Preparing your desktop workspace';
  }
  if (Platform.isLinux) {
    return 'Preparing your desktop workspace';
  }
  return 'Preparing your desktop workspace';
}

bool get supportsDesktopEngine => Platform.isWindows || Platform.isLinux;
