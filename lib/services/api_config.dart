import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'desktop_runtime_config.dart';

/// Stores backend URL and JWT session on the device.
class ApiConfig {
  ApiConfig._();

  static final FlutterSecureStorage _secure = const FlutterSecureStorage();

  static const String defaultBaseUrl = 'http://127.0.0.1:8000';
  static const String defaultChatbotBaseUrl = defaultBaseUrl;

  static String baseUrl = defaultBaseUrl;
  static String chatbotBaseUrl = defaultChatbotBaseUrl;

  static String get desktopBaseUrl =>
      DesktopRuntimeConfig.buildBaseUrl(port: DesktopRuntimeConfig.defaultPort);
  static String accessToken = '';
  static String userEmail = '';
  static String userRole = '';

  static String _normalizeBaseUrl(String url) {
    return url.trim().replaceAll(RegExp(r'/+$'), '');
  }

  static Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = _normalizeBaseUrl(prefs.getString('base_url') ?? defaultBaseUrl);
    chatbotBaseUrl = _normalizeBaseUrl(
      prefs.getString('chatbot_base_url') ?? defaultChatbotBaseUrl,
    );
    accessToken = prefs.getString('access_token') ?? '';
    userEmail = prefs.getString('user_email') ?? '';
    userRole = prefs.getString('user_role') ?? '';
  }

  static Future<void> saveBaseUrl(String url) async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = _normalizeBaseUrl(url);
    await prefs.setString('base_url', baseUrl);
  }

  static Future<void> saveChatbotBaseUrl(String url) async {
    final prefs = await SharedPreferences.getInstance();
    chatbotBaseUrl = _normalizeBaseUrl(url);
    await prefs.setString('chatbot_base_url', chatbotBaseUrl);
  }

  static Future<void> saveSession({
    required String token,
    required String email,
    required String role,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    accessToken = token;
    userEmail = email;
    userRole = role;
    await prefs.setString('access_token', token);
    await prefs.setString('user_email', email);
    await prefs.setString('user_role', role);
  }

  static Future<void> clearSession() async {
    final prefs = await SharedPreferences.getInstance();
    accessToken = '';
    userEmail = '';
    userRole = '';
    await prefs.remove('access_token');
    await prefs.remove('user_email');
    await prefs.remove('user_role');
  }

  static bool get isConfigured => accessToken.isNotEmpty;

  static Map<String, String> get authHeaders {
    if (accessToken.isEmpty) return {};
    return {'Authorization': 'Bearer $accessToken'};
  }

  // Per-user secure API keys (VirusTotal / AbuseIPDB)
  static String _vtKeyName(String email) =>
      'vt_api_key:${email.trim().toLowerCase()}';
  static String _abuseKeyName(String email) =>
      'abuse_api_key:${email.trim().toLowerCase()}';

  static Future<void> saveVirusTotalKey(String key, {String? forEmail}) async {
    final email = (forEmail ?? userEmail).trim();
    if (email.isEmpty) {
      throw Exception('No user email available to save key for');
    }
    await _secure.write(key: _vtKeyName(email), value: key);
  }

  static Future<String?> loadVirusTotalKey({String? forEmail}) async {
    final email = (forEmail ?? userEmail).trim();
    if (email.isEmpty) return null;
    return await _secure.read(key: _vtKeyName(email));
  }

  static Future<void> deleteVirusTotalKey({String? forEmail}) async {
    final email = (forEmail ?? userEmail).trim();
    if (email.isEmpty) return;
    await _secure.delete(key: _vtKeyName(email));
  }

  static Future<void> saveAbuseIpDbKey(String key, {String? forEmail}) async {
    final email = (forEmail ?? userEmail).trim();
    if (email.isEmpty)
      throw Exception('No user email available to save key for');
    await _secure.write(key: _abuseKeyName(email), value: key);
  }

  static Future<String?> loadAbuseIpDbKey({String? forEmail}) async {
    final email = (forEmail ?? userEmail).trim();
    if (email.isEmpty) return null;
    return await _secure.read(key: _abuseKeyName(email));
  }

  static Future<void> deleteAbuseIpDbKey({String? forEmail}) async {
    final email = (forEmail ?? userEmail).trim();
    if (email.isEmpty) return;
    await _secure.delete(key: _abuseKeyName(email));
  }
}
