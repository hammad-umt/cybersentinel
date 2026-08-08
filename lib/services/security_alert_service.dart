import 'dart:async';

import 'package:flutter/material.dart';

import 'api_config.dart';
import 'api_service.dart';
import 'firewall_monitor_service.dart';
import 'packet_capture_service.dart';

/// Real-time security alerts surfaced across the whole app.
class SecurityAlert {
  const SecurityAlert({
    required this.id,
    required this.title,
    required this.message,
    required this.severity,
    required this.source,
    required this.timestamp,
    this.isRead = false,
  });

  final String id;
  final String title;
  final String message;
  final String severity;
  final String source;
  final DateTime timestamp;
  final bool isRead;

  SecurityAlert copyWith({bool? isRead}) => SecurityAlert(
    id: id,
    title: title,
    message: message,
    severity: severity,
    source: source,
    timestamp: timestamp,
    isRead: isRead ?? this.isRead,
  );
}

class SecurityAlertService extends ChangeNotifier {
  SecurityAlertService._();

  static final instance = SecurityAlertService._();

  final List<SecurityAlert> alerts = [];
  final Set<String> _seenIds = {};
  final Set<String> _dismissedFingerprints = {};
  Timer? _pollTimer;
  Timer? _bannerTimer;
  bool _initialized = false;
  bool _initialLoadDone = false;

  SecurityAlert? bannerAlert;

  static const _maxAlerts = 50;
  static const _pollInterval = Duration(seconds: 8);
  static const _bannerDuration = Duration(seconds: 6);

  int get unreadCount => alerts.where((a) => !a.isRead).length;

  Future<void> initialize() async {
    if (_initialized) return;
    _initialized = true;

    PacketCaptureService.instance.addListener(_onCaptureUpdate);
    FirewallMonitorService.instance.addListener(_onMonitorUpdate);
    _pollTimer = Timer.periodic(_pollInterval, (_) => _pollFirewallAlerts());
    await _pollFirewallAlerts();
    _initialLoadDone = true;
  }

  void disposeService() {
    _pollTimer?.cancel();
    _bannerTimer?.cancel();
    PacketCaptureService.instance.removeListener(_onCaptureUpdate);
    FirewallMonitorService.instance.removeListener(_onMonitorUpdate);
  }

  void _onCaptureUpdate() {
    final capture = PacketCaptureService.instance;
    for (final packet in capture.packets) {
      if (packet.status != 'suspicious' && packet.status != 'malicious') {
        continue;
      }
      final id = 'packet:${packet.key}:${packet.status}';
      if (_seenIds.contains(id)) {
        continue;
      }
      _pushAlert(
        id: id,
        title: 'Suspicious traffic detected',
        message: '${packet.ip}:${packet.port} classified as ${packet.status}',
        severity: packet.status == 'malicious' ? 'high' : 'medium',
        source: 'packet_capture',
      );
    }
  }

  void _onMonitorUpdate() {}

  Future<void> _pollFirewallAlerts() async {
    if (!ApiConfig.isConfigured) return;

    try {
      final data = await ApiService.instance.getFirewallAlerts(pageSize: 10);
      for (final raw in data['alerts'] as List? ?? []) {
        if (raw is! Map) continue;
        final map = Map<String, dynamic>.from(raw);
        final severity = map['severity']?.toString().toLowerCase() ?? '';
        if (!_isElevatedSeverity(severity)) continue;

        final id = 'fw:${map['id'] ?? map['alert_id'] ?? map['src_ip']}';
        if (_seenIds.contains(id)) continue;

        _pushAlert(
          id: id,
          title: 'Firewall threat detected',
          message:
              '${map['src_ip'] ?? 'Unknown IP'} — ${map['rule'] ?? map['severity'] ?? 'suspicious activity'}',
          severity: severity,
          source: 'firewall',
          showToast: _initialLoadDone,
        );
      }
    } catch (_) {}
  }

  bool _isElevatedSeverity(String severity) {
    return severity == 'high' ||
        severity == 'critical' ||
        severity == 'medium' ||
        severity == 'suspicious' ||
        severity == 'malicious';
  }

  void _pushAlert({
    required String id,
    required String title,
    required String message,
    required String severity,
    required String source,
    bool showToast = true,
  }) {
    final fingerprint = _alertFingerprint(
      title: title,
      message: message,
      severity: severity,
      source: source,
    );
    if (_dismissedFingerprints.contains(fingerprint)) return;
    _seenIds.add(id);
    final alert = SecurityAlert(
      id: id,
      title: title,
      message: message,
      severity: severity,
      source: source,
      timestamp: DateTime.now(),
    );
    alerts.insert(0, alert);
    if (alerts.length > _maxAlerts) {
      final removed = alerts.sublist(_maxAlerts);
      alerts.removeRange(_maxAlerts, alerts.length);
      for (final r in removed) {
        _seenIds.remove(r.id);
      }
    }
    if (showToast) _showBanner(alert);
    notifyListeners();
  }

  String _alertFingerprint({
    required String title,
    required String message,
    required String severity,
    required String source,
  }) {
    return [
      source,
      severity,
      title,
      message,
    ].map((part) => part.trim().toLowerCase()).join('|');
  }

  void _showBanner(SecurityAlert alert) {
    bannerAlert = alert;
    _bannerTimer?.cancel();
    _bannerTimer = Timer(_bannerDuration, () {
      bannerAlert = null;
      notifyListeners();
    });
    notifyListeners();
  }

  void dismissBanner() {
    bannerAlert = null;
    _bannerTimer?.cancel();
    notifyListeners();
  }

  void dismissAlert(String id) {
    final index = alerts.indexWhere((a) => a.id == id);
    if (index == -1) return;
    _dismissedFingerprints.add(
      _alertFingerprint(
        title: alerts[index].title,
        message: alerts[index].message,
        severity: alerts[index].severity,
        source: alerts[index].source,
      ),
    );
    alerts.removeAt(index);
    notifyListeners();
  }

  void markAllRead() {
    for (var i = 0; i < alerts.length; i++) {
      if (!alerts[i].isRead) alerts[i] = alerts[i].copyWith(isRead: true);
    }
    notifyListeners();
  }

  void clearAlerts() {
    for (final alert in alerts) {
      _dismissedFingerprints.add(
        _alertFingerprint(
          title: alert.title,
          message: alert.message,
          severity: alert.severity,
          source: alert.source,
        ),
      );
    }
    alerts.clear();
    bannerAlert = null;
    _bannerTimer?.cancel();
    notifyListeners();
  }
}
