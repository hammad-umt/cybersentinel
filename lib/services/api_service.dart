import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:http/http.dart' as http;

import 'api_config.dart';
import 'auth_service.dart';
import 'ip_intel_parser.dart';

/// Simple helper for all CyberSentinel backend calls.
class ApiService {
  ApiService._();

  static final instance = ApiService._();

  Map<String, String> get _headers => {
        ...ApiConfig.authHeaders,
        'Content-Type': 'application/json',
      };

  Map<String, String> get _authOnlyHeaders => ApiConfig.authHeaders;

  Uri _uri(String path, [Map<String, String>? query]) {
    return Uri.parse('${ApiConfig.baseUrl}$path')
        .replace(queryParameters: query);
  }

  Future<Map<String, dynamic>> _get(String path,
      {Map<String, String>? query}) async {
    final response = await http.get(_uri(path, query), headers: _headers);
    return _parseJson(response);
  }

  Future<Map<String, dynamic>> _post(String path, {Object? body}) async {
    final response = await http.post(
      _uri(path),
      headers: _headers,
      body: body == null ? null : jsonEncode(body),
    );
    return _parseJson(response);
  }

  Future<Map<String, dynamic>> _patch(String path) async {
    final response = await http.patch(_uri(path), headers: _headers);
    return _parseJson(response);
  }

  Map<String, dynamic> _parseJson(http.Response response) {
    Map<String, dynamic>? data;
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) {
        data = decoded;
      } else if (response.statusCode < 400) {
        return {'success': true, 'data': decoded};
      }
    } catch (_) {}

    if (response.statusCode == 401) {
      AuthService.instance.handleUnauthorized();
      final detail = data?['detail']?.toString();
      throw AuthException(
        detail ?? 'Session expired. Please log in again.',
      );
    }

    if (response.statusCode >= 400 || data?['success'] == false) {
      final detail = data?['detail'];
      final message = detail is List
          ? detail.map((e) => e.toString()).join(', ')
          : detail?.toString();
      if (response.statusCode == 429) {
        throw Exception('Too Many Requests (429)');
      }
      throw Exception(message ?? 'Request failed (${response.statusCode})');
    }

    return data ?? {'success': true};
  }

  /// Pulls a list of maps from common API response shapes.
  static List<Map<String, dynamic>> extractList(
    Map<String, dynamic> data, {
    required List<String> keys,
  }) {
    for (final key in keys) {
      final value = data[key];
      if (value is List) {
        return [
          for (final item in value)
            if (item is Map) Map<String, dynamic>.from(item),
        ];
      }
    }

    final nested = data['data'];
    if (nested is Map<String, dynamic>) {
      return extractList(nested, keys: keys);
    }

    return [];
  }

  // --- System ---

  Future<Map<String, dynamic>> getHealth() async {
    final response = await http.get(_uri('/health'));
    return _parseJson(response);
  }

  // --- Dashboard ---

  Future<Map<String, dynamic>> getDashboardSummary() =>
      _get('/api/v1/dashboard/summary');

  // --- Threat ---

  Future<Map<String, dynamic>> getTopThreats({int limit = 10}) =>
      _get('/api/v1/threat/top', query: {'limit': '$limit'});

  Future<Map<String, dynamic>> getThreatScore(String ip) =>
      _get('/api/v1/threat/score/$ip');

  // --- Packet ---

  Future<Map<String, dynamic>> getPacketEvents({
    int page = 1,
    int pageSize = 50,
    String? prediction,
  }) {
    final query = {'page': '$page', 'page_size': '$pageSize'};
    if (prediction != null) query['prediction'] = prediction;
    return _get('/api/v1/packet/events', query: query);
  }

  // --- Firewall ---

  Future<Map<String, dynamic>> getFirewallAlerts({
    int page = 1,
    int pageSize = 50,
    String? severity,
    bool unacknowledgedOnly = false,
  }) {
    final query = {
      'page': '$page',
      'page_size': '$pageSize',
      'unacknowledged_only': '$unacknowledgedOnly',
    };
    if (severity != null) query['severity'] = severity;
    return _get('/api/v1/firewall/alerts', query: query);
  }

  Future<Map<String, dynamic>> acknowledgeAlert(String alertId) =>
      _patch('/api/v1/firewall/alerts/$alertId/acknowledge');

  Future<Map<String, dynamic>> getFirewallIntel(String ip) =>
      _get('/api/v1/firewall/intel/ip/$ip');

  /// IP reputation from AbuseIPDB + GeoIP (same backend route).
  Future<IpGeoIntel?> getIpGeoIntel(String ip) async {
    final data = await getFirewallIntel(ip);
    return IpGeoIntel.fromResponse(data);
  }

  Future<Map<String, dynamic>> startFirewallMonitor() => _post(
        '/api/v1/firewall/monitor/start',
        body: {},
      );

  Future<Map<String, dynamic>> stopFirewallMonitor() =>
      _post('/api/v1/firewall/monitor/stop', body: {});

  Future<Map<String, dynamic>> getFirewallMonitorStatus() =>
      _get('/api/v1/firewall/monitor/status');

  Future<Map<String, dynamic>> analyzeFirewallLog(
    PlatformFile file, {
    String source = 'auto',
  }) async {
    final request = http.MultipartRequest(
      'POST',
      _uri('/api/v1/firewall/analyze', {'source': source}),
    );
    request.headers.addAll(_authOnlyHeaders);
    request.files.add(http.MultipartFile.fromBytes(
      'file',
      file.bytes!,
      filename: file.name,
    ));

    final streamed = await request.send();
    final response = await http.Response.fromStream(streamed);
    return _parseJson(response);
  }

  Future<List<int>> downloadFirewallAlertsCsv() async {
    final response = await http.get(
      _uri('/api/v1/firewall/alerts.csv'),
      headers: _authOnlyHeaders,
    );
    if (response.statusCode == 401) {
      await AuthService.instance.handleUnauthorized();
      throw AuthException('Session expired. Please log in again.');
    }
    if (response.statusCode >= 400) {
      throw Exception('Export failed (${response.statusCode})');
    }
    return response.bodyBytes;
  }

  // --- Capture ---

  Future<Map<String, dynamic>> getCaptureInterfaces() =>
      _get('/api/v1/capture/interfaces');

  Future<Map<String, dynamic>> startCapture({
    required int interfaceIndex,
    int packetLimit = 100,
    int timeoutSeconds = 30,
    String bpfFilter = '',
    bool useTshark = false,
  }) =>
      _post('/api/v1/capture/start', body: {
        'interface_index': interfaceIndex,
        'packet_limit': packetLimit,
        'timeout_seconds': timeoutSeconds,
        'bpf_filter': bpfFilter,
        'use_tshark': useTshark,
      });

  Future<Map<String, dynamic>> stopCapture() =>
      _post('/api/v1/capture/stop', body: {});

  Future<Map<String, dynamic>> getCaptureStatus() =>
      _get('/api/v1/capture/status');

  Future<Map<String, dynamic>> getCapturedPackets() =>
      _get('/api/v1/capture/packets');

  // --- Intel (VirusTotal) ---

  Future<Map<String, dynamic>> scanFile(PlatformFile file) async {
    final request = http.MultipartRequest('POST', _uri('/api/v1/intel/file'));
    request.headers.addAll(_authOnlyHeaders);
    request.files.add(http.MultipartFile.fromBytes(
      'file',
      file.bytes!,
      filename: file.name,
    ));

    final streamed = await request.send();
    final response = await http.Response.fromStream(streamed);
    return _parseJson(response);
  }

  Future<Map<String, dynamic>> scanUrl(String url) {
    final trimmed = url.trim();
    if (trimmed.isEmpty) {
      throw Exception('URL is required');
    }
    return _post('/api/v1/intel/url', body: {'url': trimmed});
  }

  // --- Copilot ---

  Future<Map<String, dynamic>> askCopilot({
    required String question,
    String? ip,
  }) =>
      _post('/api/v1/copilot/ask', body: {
        'question': question,
        if (ip != null) 'ip': ip,
      });

  // --- Response ---

  Future<Map<String, dynamic>> createResponseAction({
    required String targetIp,
    required String action,
    required String reason,
    String? requestedBy,
    bool execute = false,
  }) =>
      _post('/api/v1/response/actions', body: {
        'target_ip': targetIp,
        'action': action,
        'reason': reason,
        'requested_by': requestedBy ?? AuthService.instance.email,
        'execute': execute,
      });

  // --- Reports ---

  Future<List<int>> downloadSummaryReport() async {
    final response = await http.get(
      _uri('/api/v1/reports/summary.pdf'),
      headers: _authOnlyHeaders,
    );
    if (response.statusCode == 401) {
      await AuthService.instance.handleUnauthorized();
      throw AuthException('Session expired. Please log in again.');
    }
    if (response.statusCode >= 400) {
      throw Exception('Report download failed (${response.statusCode})');
    }
    return response.bodyBytes;
  }
}
