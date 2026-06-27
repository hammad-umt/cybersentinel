import 'package:shared_preferences/shared_preferences.dart';

/// Stores backend URL and JWT session on the device.
class ApiConfig {
  ApiConfig._();

  static const defaultBaseUrl = 'http://127.0.0.1:8000';

  static String baseUrl = defaultBaseUrl;
  static String accessToken = '';
  static String userEmail = '';
  static String userRole = '';

  static Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = prefs.getString('base_url') ?? defaultBaseUrl;
    accessToken = prefs.getString('access_token') ?? '';
    userEmail = prefs.getString('user_email') ?? '';
    userRole = prefs.getString('user_role') ?? '';
  }

  static Future<void> saveBaseUrl(String url) async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = url.trim().replaceAll(RegExp(r'/+$'), '');
    await prefs.setString('base_url', baseUrl);
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
}
