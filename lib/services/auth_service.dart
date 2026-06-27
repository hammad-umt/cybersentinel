import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'api_config.dart';

/// Manages user authentication state and auth API calls.
class AuthService extends ChangeNotifier {
  AuthService._();

  static final instance = AuthService._();

  bool _initialized = false;
  bool _loading = true;
  Map<String, dynamic>? _user;

  bool get isInitialized => _initialized;
  bool get isLoading => _loading;
  bool get isAuthenticated => ApiConfig.isConfigured && _user != null;
  Map<String, dynamic>? get user => _user;
  String get role => _user?['role']?.toString() ?? ApiConfig.userRole;
  String get email => _user?['email']?.toString() ?? ApiConfig.userEmail;

  bool get isAdmin => role == 'Administrator';
  bool get isAnalystOrAbove =>
      isAdmin || role == 'Analyst' || role == 'SeniorManagement';

  Uri _uri(String path, [Map<String, String>? query]) {
    return Uri.parse('${ApiConfig.baseUrl}$path')
        .replace(queryParameters: query);
  }

  Future<void> initialize() async {
    if (_initialized) return;
    await ApiConfig.load();

    if (ApiConfig.isConfigured) {
      try {
        _user = await _fetchMe();
      } catch (_) {
        await ApiConfig.clearSession();
        _user = null;
      }
    }

    _loading = false;
    _initialized = true;
    notifyListeners();
  }

  Future<Map<String, dynamic>> login({
    required String email,
    required String password,
  }) async {
    final body = {
      'username': email.trim(),
      'password': password,
    };
    final encoded = body.entries
        .map(
          (e) =>
              '${Uri.encodeComponent(e.key)}=${Uri.encodeComponent(e.value)}',
        )
        .join('&');

    final response = await http.post(
      _uri('/api/v1/auth/token'),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: encoded,
    );

    final data = _parseJson(response);
    final token = data['access_token']?.toString() ?? '';
    if (token.isEmpty) {
      throw Exception('Login failed: no access token returned');
    }

    await ApiConfig.saveSession(
      token: token,
      email: data['email']?.toString() ?? email.trim(),
      role: data['role']?.toString() ?? 'Analyst',
    );

    _user = await _fetchMe();
    notifyListeners();
    return data;
  }

  Future<Map<String, dynamic>> register({
    required String email,
    required String password,
  }) async {
    final response = await http.post(
      _uri('/api/v1/auth/register'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email.trim(), 'password': password}),
    );
    return _parseJson(response);
  }

  Future<Map<String, dynamic>> forgotPassword({required String email}) async {
    final response = await http.post(
      _uri('/api/v1/auth/forgot-password'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email.trim()}),
    );
    return _parseJson(response);
  }

  Future<Map<String, dynamic>> validateResetToken(String token) async {
    final response = await http.get(
      _uri('/api/v1/auth/reset-password/validate', {'token': token}),
    );
    return _parseJson(response);
  }

  Future<Map<String, dynamic>> resetPassword({
    required String token,
    required String newPassword,
  }) async {
    final response = await http.post(
      _uri('/api/v1/auth/reset-password'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'token': token, 'new_password': newPassword}),
    );
    return _parseJson(response);
  }

  Future<Map<String, dynamic>> _fetchMe() async {
    final response = await http.get(
      _uri('/api/v1/auth/me'),
      headers: {
        ...ApiConfig.authHeaders,
        'Content-Type': 'application/json',
      },
    );
    final data = _parseJson(response);
    _user = data;
    if (data['email'] != null) {
      await ApiConfig.saveSession(
        token: ApiConfig.accessToken,
        email: data['email'].toString(),
        role: data['role']?.toString() ?? ApiConfig.userRole,
      );
    }
    return data;
  }

  Future<void> refreshProfile() async {
    if (!ApiConfig.isConfigured) return;
    _user = await _fetchMe();
    notifyListeners();
  }

  Future<void> logout() async {
    try {
      if (ApiConfig.isConfigured) {
        await http.post(
          _uri('/api/v1/auth/logout'),
          headers: {
            ...ApiConfig.authHeaders,
            'Content-Type': 'application/json',
          },
        );
      }
    } catch (_) {
      // Clear local session even if revoke fails.
    }

    await ApiConfig.clearSession();
    _user = null;
    notifyListeners();
  }

  Future<void> handleUnauthorized() async {
    if (!ApiConfig.isConfigured) return;
    await ApiConfig.clearSession();
    _user = null;
    notifyListeners();
  }

  Map<String, dynamic> _parseJson(http.Response response) {
    Map<String, dynamic>? data;
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) {
        data = decoded;
      }
    } catch (_) {}

    if (response.statusCode == 401) {
      throw AuthException(
        data?['detail']?.toString() ?? 'Session expired. Please log in again.',
      );
    }

    if (response.statusCode >= 400 || data?['success'] == false) {
      final detail = data?['detail'];
      final message = detail is List
          ? detail.map((e) => e.toString()).join(', ')
          : detail?.toString();
      throw Exception(message ?? 'Request failed (${response.statusCode})');
    }

    return data ?? {'success': true};
  }
}

class AuthException implements Exception {
  AuthException(this.message);
  final String message;

  @override
  String toString() => message;
}
