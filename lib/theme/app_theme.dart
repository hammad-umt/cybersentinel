import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Builds Material [ThemeData] for light and dark — does not mutate [AppColors].
abstract final class AppTheme {
  static ThemeData light() => _build(Brightness.light);
  static ThemeData dark() => _build(Brightness.dark);

  static ThemeData _build(Brightness brightness) {
    final isLight = brightness == Brightness.light;
    final bg = isLight ? const Color(0xFFF1F5F9) : const Color(0xFF0A0E1A);
    final panel = isLight ? const Color(0xFFFFFFFF) : const Color(0xFF0F1420);
    final borderElevated = isLight ? const Color(0xFFCBD5E1) : const Color(0xFF2A2F3E);
    final textPrimary = isLight ? const Color(0xFF0F172A) : const Color(0xFFFFFFFF);
    const cyan = Color(0xFF06B6D4);
    const cyanLight = Color(0xFF22D3EE);

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      scaffoldBackgroundColor: bg,
      colorScheme: ColorScheme.fromSeed(
        seedColor: cyan,
        brightness: brightness,
        surface: panel,
      ),
      textTheme: GoogleFonts.interTextTheme(
        ThemeData(brightness: brightness).textTheme,
      ),
      textSelectionTheme: TextSelectionThemeData(
        selectionColor: isLight
            ? cyan.withValues(alpha: 0.25)
            : Colors.white.withValues(alpha: 0.3),
        cursorColor: cyanLight,
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: panel,
        contentTextStyle: TextStyle(color: textPrimary),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: BorderSide(color: borderElevated),
        ),
      ),
      dividerColor: borderElevated,
    );
  }
}
