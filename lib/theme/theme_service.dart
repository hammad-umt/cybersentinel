import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'app_colors.dart';

/// Persists and broadcasts light/dark appearance across the app.
class ThemeService extends ChangeNotifier {
  ThemeService._();

  static final instance = ThemeService._();

  static const _prefKey = 'app_theme';

  ThemeMode _mode = ThemeMode.dark;

  ThemeMode get mode => _mode;
  bool get isLight => _mode == ThemeMode.light;

  Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_prefKey) ?? 'dark';
    _apply(saved == 'light' ? ThemeMode.light : ThemeMode.dark, notify: false);
  }

  Future<void> setMode(ThemeMode mode) async {
    _apply(mode);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      _prefKey,
      mode == ThemeMode.light ? 'light' : 'dark',
    );
  }

  Future<void> setFromName(String name) =>
      setMode(name == 'light' ? ThemeMode.light : ThemeMode.dark);

  String get themeName => isLight ? 'light' : 'dark';

  void _apply(ThemeMode mode, {bool notify = true}) {
    _mode = mode;
    AppColors.setLightMode(mode == ThemeMode.light);
    if (notify) notifyListeners();
  }
}
