import 'dart:async';
import 'dart:io';

import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/desktop_runtime_config.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Starts the bundled local backend service that powers the desktop API and chatbot routes.
class BackendLauncher {
  BackendLauncher._();
  static final BackendLauncher instance = BackendLauncher._();

  static const Duration healthTimeout = Duration(seconds: 90);
  static const Duration healthPollInterval = Duration(milliseconds: 500);

  Process? _process;
  bool _starting = false;
  int _port = DesktopRuntimeConfig.defaultPort;
  final List<String> _engineLogTail = [];
  static const int _maxLogLines = 24;
  IOSink? _engineLogFileSink;

  void _appendEngineLog(String line) {
    final trimmed = line.trim();
    if (trimmed.isEmpty) return;
    _engineLogTail.add(trimmed);
    if (_engineLogTail.length > _maxLogLines) {
      _engineLogTail.removeAt(0);
    }
    debugPrint('[engine] $trimmed');
  }

  String get _engineLogHint {
    if (_engineLogTail.isEmpty) {
      return 'Open $engineDirectory\\engine.log if present (configuration errors are written there).';
    }
    return 'Recent engine output:\n${_engineLogTail.join('\n')}';
  }

  String get engineBinaryName {
    if (Platform.isWindows) return 'cybersentinel_engine.exe';
    if (Platform.isLinux) return 'cybersentinel_engine';
    return 'cybersentinel_engine';
  }

  String get _appDataEngineDirectoryPath {
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData != null && appData.isNotEmpty) {
        return p.join(
          appData,
          DesktopRuntimeConfig.appDataFolderName,
          DesktopRuntimeConfig.runtimeFolderName,
          'engine',
        );
      }
    }

    if (Platform.isLinux || Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return p.join(
          home,
          '.local',
          'share',
          DesktopRuntimeConfig.appDataFolderName,
          DesktopRuntimeConfig.runtimeFolderName,
          'engine',
        );
      }
    }

    return '';
  }

  String get engineDirectory {
    final appDataEngine = _appDataEngineDirectoryPath;
    if (appDataEngine.isNotEmpty && _engineExists(appDataEngine)) {
      return appDataEngine;
    }

    final executableDir = p.dirname(Platform.resolvedExecutable);

    final besideExe = p.join(executableDir, 'engine');
    if (_engineExists(besideExe)) return besideExe;

    final runnerEngine = p.normalize(p.join(executableDir, '..', 'engine'));
    if (_engineExists(runnerEngine)) return runnerEngine;

    return besideExe;
  }

  Future<String> get appDataRuntimeDirectory async {
    final dir = await getApplicationSupportDirectory();
    final runtimeDir = p.join(
      dir.path,
      DesktopRuntimeConfig.appDataFolderName,
      DesktopRuntimeConfig.runtimeFolderName,
    );
    await Directory(runtimeDir).create(recursive: true);
    return runtimeDir;
  }

  Future<String> get appDataEngineDirectory async {
    final runtimeDir = await appDataRuntimeDirectory;
    final engineDir = p.join(runtimeDir, 'engine');
    await Directory(engineDir).create(recursive: true);
    return engineDir;
  }

  String get engineExecutable => p.join(engineDirectory, engineBinaryName);

  Future<String> get runtimeEngineExecutable async {
    final engineDir = await appDataEngineDirectory;
    return p.join(engineDir, engineBinaryName);
  }

  Future<String> _resolveEngineDirectory() async {
    final appDataDir = _appDataEngineDirectoryPath;
    if (appDataDir.isNotEmpty && _engineExists(appDataDir)) {
      return appDataDir;
    }

    final packagedDir = engineDirectory;
    if (appDataDir.isNotEmpty &&
        packagedDir.isNotEmpty &&
        _engineExists(packagedDir)) {
      await _installEngineToAppData(packagedDir, appDataDir);
      return appDataDir;
    }

    return packagedDir;
  }

  Future<void> _installEngineToAppData(
    String sourceDir,
    String targetDir,
  ) async {
    final source = Directory(sourceDir);
    if (!source.existsSync()) return;

    final target = Directory(targetDir);
    await target.create(recursive: true);
    await for (final entity in source.list(
      recursive: false,
      followLinks: false,
    )) {
      final targetPath = p.join(targetDir, p.basename(entity.path));
      if (entity is File) {
        await entity.copy(targetPath);
      } else if (entity is Directory) {
        await _installEngineToAppData(entity.path, targetPath);
      }
    }
  }

  bool get isRunning => _process != null;

  bool _engineExists(String dir) =>
      File(p.join(dir, engineBinaryName)).existsSync();

  String get _syncScriptHint {
    if (Platform.isWindows) {
      return 'Run: .\\scripts\\sync_engine.ps1 from the Flutter project folder.';
    }
    if (Platform.isLinux) {
      return 'Run: ./scripts/sync_engine.sh from the Flutter project folder.';
    }
    return 'Bundle the desktop engine next to this app.';
  }

  Future<void> start() async {
    if (_process != null || _starting) return;
    _starting = true;

    try {
      if (kIsWeb) {
        await _ensureRemoteBackendReady();
        return;
      }

      if (!Platform.isWindows && !Platform.isLinux) {
        debugPrint('[CyberSentinel] Desktop engine not supported on this OS.');
        return;
      }

      _port = await _resolveAvailablePort();
      final baseUrl = DesktopRuntimeConfig.buildBaseUrl(port: _port);
      ApiConfig.baseUrl = baseUrl;
      await ApiConfig.saveBaseUrl(baseUrl);

      final engineDir = await _resolveEngineDirectory();
      final exe = p.join(engineDir, engineBinaryName);
      if (!File(exe).existsSync()) {
        throw StateError('Security engine not found at $exe\n$_syncScriptHint');
      }

      if (await _isHealthyAt(baseUrl)) {
        debugPrint('[CyberSentinel] Engine already running at $baseUrl');
        return;
      }

      debugPrint('[CyberSentinel] Starting local backend service: $exe');
      _engineLogTail.clear();
      _process = await Process.start(
        exe,
        const [],
        workingDirectory: engineDir,
        environment: {
          ...Platform.environment,
          'HOST': DesktopRuntimeConfig.host,
          'PORT': '$_port',
          'DEBUG': 'false',
          'RATE_LIMIT_PER_MINUTE': '0',
        },
      );

      // Open (or append) the engine.log next to the engine binary so installed
      // copies capture runtime output for diagnostics.
      try {
        final logFile = File(p.join(engineDir, 'engine.log'));
        _engineLogFileSink = logFile.openWrite(mode: FileMode.append);
      } catch (e) {
        debugPrint('[CyberSentinel] Failed to open engine.log: $e');
      }

      _process!.stderr.transform(const SystemEncoding().decoder).listen((data) {
        _appendEngineLog(data);
        try {
          _engineLogFileSink?.write(data);
        } catch (_) {}
      });
      _process!.stdout.transform(const SystemEncoding().decoder).listen((data) {
        _appendEngineLog(data);
        try {
          _engineLogFileSink?.write(data);
        } catch (_) {}
      });

      final exitCompleter = Completer<int>();
      unawaited(
        _process!.exitCode.then((code) {
          debugPrint('[CyberSentinel] Engine exited ($code)');
          if (!exitCompleter.isCompleted) exitCompleter.complete(code);
          _process = null;
          try {
            _engineLogFileSink?.flush();
          } catch (_) {}
          try {
            _engineLogFileSink?.close();
          } catch (_) {}
          _engineLogFileSink = null;
        }),
      );

      final ok = await _waitForHealth(
        baseUrl,
        onEarlyExit: exitCompleter.future,
      );
      if (!ok) {
        final exitCode = exitCompleter.isCompleted
            ? await exitCompleter.future
            : null;
        await stop();
        final exitDetail = exitCode == null
            ? 'The engine process did not finish starting.'
            : 'The engine process exited early (code $exitCode).';
        throw StateError(
          'Security engine did not respond on $baseUrl within $healthTimeout.\n'
          '$exitDetail\n'
          'Check the bundled engine files in $engineDir\n'
          '$_engineLogHint',
        );
      }
      debugPrint('[CyberSentinel] Backend service ready at $baseUrl');
    } finally {
      _starting = false;
    }
  }

  Future<int> _resolveAvailablePort() async {
    const startPort = DesktopRuntimeConfig.defaultPort;
    for (var port = startPort; port < startPort + 50; port++) {
      if (await _isPortAvailable(port)) return port;
    }
    throw StateError(
      'No available desktop runtime port found in the expected range.',
    );
  }

  Future<bool> _isPortAvailable(int port) async {
    try {
      final socket = await ServerSocket.bind(
        InternetAddress.loopbackIPv4,
        port,
        shared: false,
      );
      await socket.close();
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<void> stop() async {
    final proc = _process;
    _process = null;
    if (proc == null) return;
    proc.kill(ProcessSignal.sigterm);
    await proc.exitCode.timeout(
      const Duration(seconds: 5),
      onTimeout: () {
        proc.kill(ProcessSignal.sigkill);
        return -1;
      },
    );
    try {
      _engineLogFileSink?.flush();
    } catch (_) {}
    try {
      _engineLogFileSink?.close();
    } catch (_) {}
    _engineLogFileSink = null;
  }

  Future<bool> _waitForHealth(
    String baseUrl, {
    Future<int>? onEarlyExit,
  }) async {
    final deadline = DateTime.now().add(healthTimeout);
    while (DateTime.now().isBefore(deadline)) {
      if (onEarlyExit != null) {
        final early = await Future.any<int?>([
          onEarlyExit,
          Future<int?>.delayed(healthPollInterval, () => null),
        ]);
        if (early != null) return false;
      }
      if (await _isHealthyAt(baseUrl)) return true;
      await Future<void>.delayed(healthPollInterval);
    }
    return false;
  }

  Future<void> _ensureRemoteBackendReady() async {
    final base = ApiConfig.baseUrl.trim().replaceAll(RegExp(r'/+$'), '');
    if (base.isEmpty) {
      throw StateError(
        'Service URL is not configured.\n'
        'Open Settings and connect CyberSentinel to its service endpoint.',
      );
    }
    final ok = await _isHealthyAt(base);
    if (!ok) {
      throw StateError(
        'The CyberSentinel service at $base is not responding.\n'
        'Check that the desktop service is running and reachable.',
      );
    }
    debugPrint('[CyberSentinel] Remote service ready at $base');
  }

  Future<bool> _isHealthyAt(String baseUrl) async {
    try {
      final response = await http
          .get(Uri.parse('$baseUrl/health'))
          .timeout(const Duration(seconds: 5));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }
}
