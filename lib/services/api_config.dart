import 'package:shared_preferences/shared_preferences.dart';

/// Stores backend URL and API key on the device.
class ApiConfig {
  ApiConfig._();

  static const defaultBaseUrl = 'http://127.0.0.1:8000';
  static const defaultApiKey = 'sk_cybersentinel_prod_v1_8f4e2b9c1a7d5e3f';

  static String baseUrl = defaultBaseUrl;
  static String apiKey = defaultApiKey;

  static Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = prefs.getString('base_url') ?? defaultBaseUrl;

    final savedKey = prefs.getString('api_key');
    apiKey = (savedKey != null && savedKey.trim().isNotEmpty)
        ? savedKey.trim()
        : defaultApiKey;
  }

  static Future<void> save({required String url, required String key}) async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = url.trim().replaceAll(RegExp(r'/+$'), '');
    apiKey = key.trim();
    await prefs.setString('base_url', baseUrl);
    await prefs.setString('api_key', apiKey);
  }

  static bool get isConfigured => apiKey.isNotEmpty;
}
