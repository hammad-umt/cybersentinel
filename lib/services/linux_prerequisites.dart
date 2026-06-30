import 'dart:io';

import 'package:cybersentinel/services/backend_launcher.dart';
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;

/// Ensures libpcap and packet-capture capabilities on Linux.
class LinuxPrerequisites {
  LinuxPrerequisites._();

  static Future<void> ensureReady() async {
    if (!Platform.isLinux) return;

    await _ensureLibpcap();
    await _ensureEngineCapabilities();
    debugPrint('[CyberSentinel] Linux capture prerequisites OK');
  }

  static Future<bool> hasLibpcap() async {
    final ld = await Process.run('ldconfig', ['-p']);
    if (ld.exitCode == 0 && '${ld.stdout}'.contains('libpcap.so')) {
      return true;
    }
    const fallbacks = [
      '/usr/lib/x86_64-linux-gnu/libpcap.so.0.8',
      '/usr/lib64/libpcap.so.0.8',
      '/usr/lib/libpcap.so.0.8',
    ];
    for (final path in fallbacks) {
      if (File(path).existsSync()) return true;
    }
    return false;
  }

  static Future<void> _ensureLibpcap() async {
    if (await hasLibpcap()) {
      debugPrint('[CyberSentinel] libpcap is available');
      return;
    }

    final bundled = _findBundledScript('install_libpcap.sh');
    if (bundled != null) {
      debugPrint('[CyberSentinel] Installing libpcap via $bundled');
      final result = await Process.run('pkexec', ['bash', bundled]);
      if (result.exitCode == 0 && await hasLibpcap()) return;
    }

    if (await File('/usr/bin/apt-get').exists()) {
      final result = await Process.run(
        'pkexec',
        ['apt-get', 'install', '-y', 'libpcap0.8'],
      );
      if (result.exitCode == 0 && await hasLibpcap()) return;
    } else if (await File('/usr/bin/dnf').exists()) {
      final result = await Process.run(
        'pkexec',
        ['dnf', 'install', '-y', 'libpcap'],
      );
      if (result.exitCode == 0 && await hasLibpcap()) return;
    } else if (await File('/usr/bin/pacman').exists()) {
      final result = await Process.run(
        'pkexec',
        ['pacman', '-S', '--noconfirm', 'libpcap'],
      );
      if (result.exitCode == 0 && await hasLibpcap()) return;
    }

    throw StateError(
      'libpcap is required for packet capture.\n'
      'Install it with your package manager, for example:\n'
      '  sudo apt install libpcap0.8   # Ubuntu/Debian\n'
      '  sudo dnf install libpcap      # Fedora',
    );
  }

  static Future<void> _ensureEngineCapabilities() async {
    final engine = BackendLauncher.instance.engineExecutable;
    if (!File(engine).existsSync()) return;

    if (await _engineHasCaptureCaps(engine)) {
      debugPrint('[CyberSentinel] Engine already has cap_net_raw');
      return;
    }

    if (Platform.environment['USER'] == 'root') {
      await _applyCaps(engine);
      return;
    }

    final script = _findBundledScript('apply_caps.sh');
    if (script != null) {
      final result = await Process.run('pkexec', ['bash', script, engine]);
      if (result.exitCode == 0 && await _engineHasCaptureCaps(engine)) {
        return;
      }
    }

    final direct = await Process.run(
      'pkexec',
      ['setcap', 'cap_net_raw,cap_net_admin+eip', engine],
    );
    if (direct.exitCode == 0 && await _engineHasCaptureCaps(engine)) {
      return;
    }

    throw StateError(
      'Packet capture needs elevated permissions on the engine binary.\n'
      'Run once:\n'
      '  sudo setcap cap_net_raw,cap_net_admin+eip "$engine"\n'
      'Or launch CyberSentinel from the official .deb / install.sh.',
    );
  }

  static Future<bool> _engineHasCaptureCaps(String enginePath) async {
    final cap = await Process.run('getcap', [enginePath]);
    if (cap.exitCode != 0) return false;
    return '${cap.stdout}'.contains('cap_net_raw');
  }

  static Future<void> _applyCaps(String enginePath) async {
    await Process.run(
      'setcap',
      ['cap_net_raw,cap_net_admin+eip', enginePath],
    );
  }

  static String? _findBundledScript(String name) {
    final exeDir = p.dirname(Platform.resolvedExecutable);
    for (final base in [
      p.join(exeDir, 'deps'),
      p.normalize(p.join(exeDir, '..', 'deps')),
      p.join(exeDir, '..', '..', 'deps'),
    ]) {
      final path = p.normalize(p.join(base, name));
      if (File(path).existsSync()) return path;
    }
    return null;
  }
}
