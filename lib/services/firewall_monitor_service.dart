import 'dart:async';

import 'package:flutter/foundation.dart';

import 'api_config.dart';
import 'api_service.dart';

/// App-wide Windows firewall log monitor state (survives page navigation).
class FirewallMonitorService extends ChangeNotifier {
  FirewallMonitorService._();

  static final instance = FirewallMonitorService._();

  bool isMonitoring = false;
  bool isLoading = false;
  String? lastError;
  String statusMessage = 'Stopped';
  int alertsGenerated = 0;

  Timer? _pollTimer;
  bool _initialized = false;

  static const _pollInterval = Duration(seconds: 10);

  Future<void> initialize() async {
    if (_initialized) return;
    _initialized = true;
    await syncStatus();
    _startPolling();
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(_pollInterval, (_) => syncStatus(silent: true));
  }

  Future<void> syncStatus({bool silent = false}) async {
    if (!ApiConfig.isConfigured) {
      isMonitoring = false;
      if (!silent) notifyListeners();
      return;
    }

    try {
      final status = await ApiService.instance.getFirewallMonitorStatus();
      isMonitoring = status['is_running'] == true ||
          status['running'] == true ||
          status['active'] == true;
      alertsGenerated = _readInt(status['alerts_generated']);
      statusMessage = status['message']?.toString() ??
          (isMonitoring ? 'Monitoring Windows firewall log' : 'Monitor stopped');
      lastError = null;
    } catch (e) {
      if (!silent) {
        lastError = e.toString().replaceFirst('Exception: ', '');
      }
    }

    if (!silent) notifyListeners();
  }

  Future<void> startMonitor() async {
    if (!ApiConfig.isConfigured) {
      throw Exception('Please sign in to continue');
    }

    isLoading = true;
    lastError = null;
    notifyListeners();

    try {
      final res = await ApiService.instance.startFirewallMonitor();
      isMonitoring = res['is_running'] == true ||
          res['running'] == true ||
          res['active'] == true;
      statusMessage = res['message']?.toString() ?? 'Firewall monitor started';
      alertsGenerated = _readInt(res['alerts_generated']);
    } catch (e) {
      lastError = e.toString().replaceFirst('Exception: ', '');
      rethrow;
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  Future<void> stopMonitor() async {
    isLoading = true;
    lastError = null;
    notifyListeners();

    try {
      await ApiService.instance.stopFirewallMonitor();
      isMonitoring = false;
      statusMessage = 'Monitor stopped';
    } catch (e) {
      lastError = e.toString().replaceFirst('Exception: ', '');
      rethrow;
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  int _readInt(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    return int.tryParse(value?.toString() ?? '') ?? 0;
  }
}
