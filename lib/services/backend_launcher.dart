import 'dart:async';
import 'dart:io';

import 'package:cybersentinel/services/api_config.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;

/// Starts the bundled FastAPI engine next to the Flutter desktop executable.
class BackendLauncher {
  BackendLauncher._();
  static final BackendLauncher instance = BackendLauncher._();

  static const String apiBaseUrl = 'http://127.0.0.1:8000';
  static const Duration healthTimeout = Duration(seconds: 90);
  static const Duration healthPollInterval = Duration(milliseconds: 500);

  Process? _process;
  bool _starting = false;
  final List<String> _engineLogTail = [];
  static const int _maxLogLines = 24;

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

  String get engineDirectory {
    final executableDir = p.dirname(Platform.resolvedExecutable);

    final besideExe = p.join(executableDir, 'engine');
    if (_engineExists(besideExe)) return besideExe;

    // flutter run: windows/runner or linux/runner relative engine folder
    final runnerEngine = p.normalize(p.join(executableDir, '..', 'engine'));
    if (_engineExists(runnerEngine)) return runnerEngine;

    return besideExe;
  }

  String get engineExecutable => p.join(engineDirectory, engineBinaryName);

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

      final exe = engineExecutable;
      if (!File(exe).existsSync()) {
        throw StateError(
          'Backend engine not found at $exe\n$_syncScriptHint',
        );
      }

      if (await _isHealthy()) {
        debugPrint('[CyberSentinel] Engine already running at $apiBaseUrl');
        return;
      }

      debugPrint('[CyberSentinel] Starting engine: $exe');
      _engineLogTail.clear();
      _process = await Process.start(
        exe,
        const [],
        workingDirectory: engineDirectory,
      );

      _process!.stderr.transform(const SystemEncoding().decoder).listen(
        _appendEngineLog,
      );
      _process!.stdout.transform(const SystemEncoding().decoder).listen(
        _appendEngineLog,
      );

      final exitCompleter = Completer<int>();
      unawaited(_process!.exitCode.then((code) {
        debugPrint('[CyberSentinel] Engine exited ($code)');
        if (!exitCompleter.isCompleted) exitCompleter.complete(code);
        _process = null;
      }));

      final ok = await _waitForHealth(onEarlyExit: exitCompleter.future);
      if (!ok) {
        final exitCode = exitCompleter.isCompleted ? await exitCompleter.future : null;
        await stop();
        final exitDetail = exitCode == null
            ? 'The engine process is still running but did not pass the health check.'
            : 'The engine process exited early (code $exitCode).';
        throw StateError(
          'Engine did not respond on $apiBaseUrl within $healthTimeout.\n'
          '$exitDetail\n'
          'Check engine.env in $engineDirectory\n'
          '$_engineLogHint',
        );
      }
      debugPrint('[CyberSentinel] Engine ready at $apiBaseUrl');
    } finally {
      _starting = false;
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
  }

  Future<bool> _waitForHealth({Future<int>? onEarlyExit}) async {
    final deadline = DateTime.now().add(healthTimeout);
    while (DateTime.now().isBefore(deadline)) {
      if (onEarlyExit != null) {
        final early = await Future.any<int?>([
          onEarlyExit,
          Future<int?>.delayed(healthPollInterval, () => null),
        ]);
        if (early != null) return false;
      }
      if (await _isHealthy()) return true;
      await Future<void>.delayed(healthPollInterval);
    }
    return false;
  }

  Future<void> _ensureRemoteBackendReady() async {
    final base = ApiConfig.baseUrl.trim().replaceAll(RegExp(r'/+$'), '');
    if (base.isEmpty) {
      throw StateError(
        'Backend URL is not configured.\n'
        'Start the API with python run.py, then set the URL in Settings.',
      );
    }
    final ok = await _isHealthyAt(base);
    if (!ok) {
      throw StateError(
        'Cannot reach the backend at $base.\n'
        'Start the FastAPI server (python run.py) and check CORS allows this origin.',
      );
    }
    debugPrint('[CyberSentinel] Remote backend ready at $base');
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

  Future<bool> _isHealthy() async => _isHealthyAt(apiBaseUrl);
}
