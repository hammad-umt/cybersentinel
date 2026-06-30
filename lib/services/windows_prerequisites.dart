import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;

/// Ensures Npcap is installed for live packet capture (Windows only).
class WindowsPrerequisites {
  WindowsPrerequisites._();

  static const npcapDownloadUrl = 'https://npcap.com/#download';

  /// Call before packet capture. Does not block app login if Npcap is missing.
  static Future<void> ensureReady() async {
    if (!Platform.isWindows) return;

    if (isNpcapInstalled()) {
      debugPrint('[CyberSentinel] Npcap is installed');
      return;
    }

    final installer = _findNpcapInstaller();
    if (installer == null) {
      debugPrint(
        '[CyberSentinel] Npcap not installed — packet capture unavailable until '
        'you re-run the installer or install Npcap from $npcapDownloadUrl',
      );
      return;
    }

    debugPrint('[CyberSentinel] Installing Npcap silently: $installer');
    final result = await Process.run(
      installer,
      const [
        '/S',
        '/loopback_support=yes',
        '/admin_only=yes',
        '/winpcap_mode=no',
      ],
      runInShell: true,
    );

    if (result.exitCode != 0) {
      final detail = '${result.stderr}'.trim();
      debugPrint(
        '[CyberSentinel] Npcap install failed (exit ${result.exitCode}). '
        '${detail.isEmpty ? "Run CyberSentinel as Administrator once." : detail}',
      );
      return;
    }

    await Future<void>.delayed(const Duration(seconds: 4));

    if (!isNpcapInstalled()) {
      debugPrint(
        '[CyberSentinel] Npcap installer finished but driver not detected — '
        'restart Windows, then try packet capture again.',
      );
      return;
    }
    debugPrint('[CyberSentinel] Npcap installed successfully');
  }

  static bool isNpcapInstalled() {
    const dllPaths = [
      r'C:\Windows\System32\Npcap\wpcap.dll',
      r'C:\Windows\System32\wpcap.dll',
    ];
    for (final path in dllPaths) {
      if (File(path).existsSync()) return true;
    }
    return false;
  }

  static String? _findNpcapInstaller() {
    final exeDir = p.dirname(Platform.resolvedExecutable);
    final candidates = [
      p.join(exeDir, 'deps', 'npcap-installer.exe'),
      p.normalize(p.join(exeDir, '..', 'deps', 'npcap-installer.exe')),
      p.join(exeDir, '..', '..', 'deps', 'npcap-installer.exe'),
    ];
    for (final path in candidates) {
      if (File(path).existsSync()) return p.normalize(path);
    }
    return null;
  }
}
