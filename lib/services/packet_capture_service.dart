import 'dart:async';

import 'package:flutter/foundation.dart';

import 'api_config.dart';
import 'api_service.dart';

/// App-wide packet capture state. Keeps polling and capture running across page navigation.
class PacketCaptureService extends ChangeNotifier {
  PacketCaptureService._();

  static final instance = PacketCaptureService._();

  bool isCapturing = false;
  bool isLoading = true;
  bool isLoadingInterfaces = false;
  String? lastError;
  String statusMessage = 'Paused';
  String? activeInterfaceName;
  int packetsCaptured = 0;
  List<LivePacket> packets = [];
  List<CaptureInterface> interfaces = [];
  int? selectedInterfaceIndex;
  String bpfFilter = '';
  bool useTshark = false;
  int packetLimit = 100;
  int timeoutSeconds = 30;

  Timer? _pollTimer;
  bool _initialized = false;
  bool _refreshInFlight = false;
  DateTime? _lastEventsFetch;
  DateTime? _lastStatusSync;
  DateTime _rateLimitUntil = DateTime.fromMillisecondsSinceEpoch(0);

  static const _pollInterval = Duration(seconds: 5);
  static const _eventsInterval = Duration(seconds: 30);
  static const _statusInterval = Duration(seconds: 15);
  static const _rateLimitBackoff = Duration(seconds: 60);
  static const _eventsPageSize = 25;

  Future<void> initialize() async {
    if (_initialized) return;
    _initialized = true;
    await loadInterfaces();
    await syncStatus();
    await refreshPackets(force: true);
    _startPolling();
  }

  Future<void> loadInterfaces() async {
    if (!ApiConfig.isConfigured) return;

    isLoadingInterfaces = true;
    notifyListeners();

    try {
      final data = await ApiService.instance.getCaptureInterfaces();
      interfaces = CaptureInterface.parseList(data);
      _ensureSelectedInterface();
      lastError = interfaces.isEmpty ? 'No capture interfaces found on backend' : null;
    } catch (e) {
      if (interfaces.isEmpty) {
        lastError = e.toString().replaceFirst('Exception: ', '');
      }
    } finally {
      isLoadingInterfaces = false;
      notifyListeners();
    }
  }

  void selectInterface(int index) {
    if (isCapturing) return;
    selectedInterfaceIndex = index;
    notifyListeners();
  }

  void setBpfFilter(String value) {
    if (isCapturing) return;
    bpfFilter = value;
    notifyListeners();
  }

  void setUseTshark(bool value) {
    if (isCapturing) return;
    useTshark = value;
    notifyListeners();
  }

  CaptureInterface? get selectedInterface {
    if (selectedInterfaceIndex == null || interfaces.isEmpty) return null;
    for (final iface in interfaces) {
      if (iface.index == selectedInterfaceIndex) return iface;
    }
    return interfaces.first;
  }

  void _ensureSelectedInterface() {
    if (interfaces.isEmpty) {
      selectedInterfaceIndex = null;
      return;
    }

    if (activeInterfaceName != null) {
      for (final iface in interfaces) {
        if (iface.name.toLowerCase() == activeInterfaceName!.toLowerCase()) {
          selectedInterfaceIndex = iface.index;
          return;
        }
      }
    }

    final current = selectedInterfaceIndex;
    if (current != null && interfaces.any((i) => i.index == current)) return;

    selectedInterfaceIndex = interfaces.first.index;
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(_pollInterval, (_) => _pollTick());
  }

  Future<void> _pollTick() async {
    if (_refreshInFlight || DateTime.now().isBefore(_rateLimitUntil)) return;

    _refreshInFlight = true;
    try {
      final now = DateTime.now();
      if (_lastStatusSync == null ||
          now.difference(_lastStatusSync!) >= _statusInterval) {
        await syncStatus(silent: true);
        _lastStatusSync = now;
      }
      await refreshPackets(silent: true, force: true);
    } finally {
      _refreshInFlight = false;
    }
  }

  bool _isRateLimited(Object error) {
    final message = error.toString().toLowerCase();
    return message.contains('429') || message.contains('too many requests');
  }

  bool _shouldFetchEvents({required bool force}) {
    if (DateTime.now().isBefore(_rateLimitUntil)) return false;
    if (force) return true;
    if (isCapturing) return false;
    final last = _lastEventsFetch;
    if (last == null) return true;
    return DateTime.now().difference(last) >= _eventsInterval;
  }

  Future<void> syncStatus({bool silent = false}) async {
    if (!ApiConfig.isConfigured) {
      isCapturing = false;
      if (!silent) notifyListeners();
      return;
    }

    try {
      final status = await ApiService.instance.getCaptureStatus();
      isCapturing = _readIsRunning(status);
      activeInterfaceName = status['interface']?.toString();
      packetsCaptured = _readInt(status['packets_captured'] ?? status['packets_classified']);
      statusMessage = status['message']?.toString() ??
          (isCapturing
              ? 'Capture running on ${activeInterfaceName ?? selectedInterface?.name ?? 'interface'}'
              : 'Capture stopped');
      _ensureSelectedInterface();
      lastError = null;
    } catch (e) {
      if (!silent) lastError = e.toString().replaceFirst('Exception: ', '');
    }

    if (!silent) notifyListeners();
  }

  Future<void> startCapture() async {
    if (!ApiConfig.isConfigured) {
      throw Exception('Set your API key in Settings');
    }

    lastError = null;
    isLoading = true;
    notifyListeners();

    try {
      final res = await ApiService.instance.startCapture(
        interfaceIndex: selectedInterfaceIndex ?? 0,
        packetLimit: packetLimit,
        timeoutSeconds: timeoutSeconds,
        bpfFilter: bpfFilter,
        useTshark: useTshark,
      );
      isCapturing = _readIsRunning(res);
      activeInterfaceName = res['interface']?.toString() ?? selectedInterface?.name;
      packetsCaptured = _readInt(res['packets_captured']);
      statusMessage = res['message']?.toString() ??
          'Capture started on ${activeInterfaceName ?? selectedInterface?.name ?? 'interface'}';
      await refreshPackets(silent: true, force: true);
    } catch (e) {
      lastError = e.toString().replaceFirst('Exception: ', '');
      rethrow;
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  Future<void> stopCapture() async {
    lastError = null;
    isLoading = true;
    notifyListeners();

    try {
      await ApiService.instance.stopCapture();
      isCapturing = false;
      statusMessage = 'Capture stopped';
      await refreshPackets(silent: true, force: true);
    } catch (e) {
      lastError = e.toString().replaceFirst('Exception: ', '');
      rethrow;
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  Future<void> refreshPackets({bool silent = false, bool force = false}) async {
    if (!ApiConfig.isConfigured) {
      isLoading = false;
      if (!silent) notifyListeners();
      return;
    }

    if (!silent) {
      isLoading = true;
      notifyListeners();
    }

    final merged = <String, LivePacket>{};

    if (isCapturing) {
      try {
        final data = await ApiService.instance.getCapturedPackets();
        packetsCaptured = _readInt(data['total'] ?? data['packets_captured']);
        for (final item in ApiService.extractList(data, keys: const ['packets', 'events', 'results', 'data'])) {
          final packet = LivePacket.fromApi(item, fromCapture: true);
          merged[packet.key] = packet;
        }
      } catch (e) {
        if (_isRateLimited(e)) {
          _rateLimitUntil = DateTime.now().add(_rateLimitBackoff);
        } else if (!silent) {
          lastError = e.toString().replaceFirst('Exception: ', '');
        }
      }
    }

    if (_shouldFetchEvents(force: force)) {
      try {
        final events = await ApiService.instance.getPacketEvents(pageSize: _eventsPageSize);
        for (final item in ApiService.extractList(events, keys: const ['events', 'results', 'data', 'packets'])) {
          final packet = LivePacket.fromApi(item, fromCapture: false);
          merged.putIfAbsent(packet.key, () => packet);
        }
        _lastEventsFetch = DateTime.now();
        if (merged.isNotEmpty || !silent) lastError = null;
      } catch (e) {
        if (_isRateLimited(e)) {
          _rateLimitUntil = DateTime.now().add(_rateLimitBackoff);
        } else if (!silent && merged.isEmpty) {
          lastError = e.toString().replaceFirst('Exception: ', '');
        }
      }
    } else if (merged.isEmpty && packets.isNotEmpty) {
      // Keep showing cached packets while throttled / between event polls.
      for (final packet in packets) {
        merged[packet.key] = packet;
      }
    }

    if (merged.isNotEmpty) {
      packets = merged.values.toList()..sort((a, b) => b.sortKey.compareTo(a.sortKey));
    }
    isLoading = false;
    notifyListeners();
  }

  bool _readIsRunning(Map<String, dynamic> data) {
    return data['is_running'] == true ||
        data['capturing'] == true ||
        data['is_capturing'] == true ||
        data['active'] == true ||
        data['status']?.toString().toLowerCase() == 'running';
  }

  int _readInt(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    return int.tryParse(value?.toString() ?? '') ?? 0;
  }
}

class CaptureInterface {
  const CaptureInterface({
    required this.index,
    required this.name,
    this.description = '',
  });

  final int index;
  final String name;
  final String description;

  String get label => description.isNotEmpty ? '$name — $description' : name;

  static List<CaptureInterface> parseList(Map<String, dynamic> data) {
    final maps = ApiService.extractList(
      data,
      keys: const ['interfaces', 'results', 'data'],
    );

    if (maps.isNotEmpty) {
      return [
        for (var i = 0; i < maps.length; i++)
          CaptureInterface.fromApi(maps[i], fallbackIndex: i),
      ];
    }

    final raw = data['interfaces'];
    if (raw is! List) return [];

    return [
      for (var i = 0; i < raw.length; i++)
        if (raw[i] is String)
          CaptureInterface(index: i, name: raw[i] as String)
        else if (raw[i] is Map)
          CaptureInterface.fromApi(
            Map<String, dynamic>.from(raw[i] as Map),
            fallbackIndex: i,
          ),
    ];
  }

  factory CaptureInterface.fromApi(Map<String, dynamic> m, {required int fallbackIndex}) {
    final indexValue = m['index'] ?? m['interface_index'] ?? m['id'] ?? fallbackIndex;
    final index = indexValue is int
        ? indexValue
        : int.tryParse(indexValue.toString()) ?? fallbackIndex;

    final name = m['name'] ??
        m['interface'] ??
        m['display_name'] ??
        m['friendly_name'] ??
        m['description'] ??
        'Interface $index';

    final description = m['description']?.toString() ??
        m['friendly_name']?.toString() ??
        m['type']?.toString() ??
        '';

    return CaptureInterface(
      index: index,
      name: name.toString(),
      description: description == name.toString() ? '' : description,
    );
  }
}

class LivePacket {
  const LivePacket({
    required this.ip,
    required this.port,
    required this.protocol,
    required this.size,
    required this.status,
    required this.time,
    required this.sortKey,
    required this.raw,
  });

  final String ip;
  final String port;
  final String protocol;
  final String size;
  final String status;
  final String time;
  final String sortKey;
  final String raw;

  String get key => '$ip|$port|$time|$protocol';

  static LivePacket fromApi(Map<String, dynamic> p, {required bool fromCapture}) {
    final prediction = p['prediction'] ??
        p['risk_level'] ??
        p['classification'] ??
        p['label'] ??
        'Normal';
    final timestamp = p['timestamp'] ?? p['captured_at'] ?? p['created_at'];
    return LivePacket(
      ip: p['src_ip']?.toString() ?? p['ip']?.toString() ?? '-',
      port: (p['dst_port'] ?? p['port'])?.toString() ?? '-',
      protocol: p['protocol']?.toString() ?? '-',
      size: _formatSize(p['pkt_size'] ?? p['packet_size'] ?? p['size']),
      status: _normalizeStatus(prediction.toString()),
      time: _formatTime(timestamp),
      sortKey: timestamp?.toString() ?? '',
      raw: p['raw_hex']?.toString() ?? p['hex']?.toString() ?? p['raw']?.toString() ?? '',
    );
  }

  static String _normalizeStatus(String raw) {
    final s = raw.toLowerCase();
    if (s.contains('malicious') || s.contains('critical') || s.contains('high')) {
      return 'malicious';
    }
    if (s.contains('suspicious') || s.contains('medium') || s.contains('warn')) {
      return 'suspicious';
    }
    return 'normal';
  }

  static String _formatTime(dynamic timestamp) {
    if (timestamp == null) return '-';
    final ts = timestamp.toString();
    if (ts.length >= 19) return ts.substring(11, 19);
    if (ts.length >= 8 && ts.contains(':')) return ts;
    return ts;
  }

  static String _formatSize(dynamic size) {
    if (size == null) return '-';
    final n = size is num ? size.toInt() : int.tryParse(size.toString()) ?? 0;
    if (n <= 0) return '-';
    if (n >= 1024) return '${(n / 1024).toStringAsFixed(1)} KB';
    return '$n B';
  }
}
