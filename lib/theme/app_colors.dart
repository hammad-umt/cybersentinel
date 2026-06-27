import 'package:flutter/material.dart';

/// CyberSentinel design tokens — supports light and dark appearance.
abstract final class AppColors {
  static bool _isLight = false;

  static void setLightMode(bool value) => _isLight = value;
  static bool get isLight => _isLight;

  // Surfaces
  static Color get bg => _isLight ? const Color(0xFFF1F5F9) : const Color(0xFF0A0E1A);
  static Color get panel => _isLight ? const Color(0xFFFFFFFF) : const Color(0xFF0F1420);
  static Color get card => _isLight ? const Color(0xFFFFFFFF) : const Color(0xFF0F1420);
  static Color get chartBg => _isLight ? const Color(0xFFF8FAFC) : const Color(0xFF0B1120);
  static Color get alertItemBg => _isLight ? const Color(0xFFF1F5F9) : const Color(0xFF1A1F2E);
  static Color get rowHover => _isLight ? const Color(0xFFE2E8F0) : const Color(0xFF1A1F2E);

  // Borders
  static Color get border => _isLight ? const Color(0xFFE2E8F0) : const Color(0xFF1A1F2E);
  static Color get borderElevated => _isLight ? const Color(0xFFCBD5E1) : const Color(0xFF2A2F3E);
  static Color get borderHover => _isLight ? const Color(0xFF94A3B8) : const Color(0xFF3A3F4E);

  // Brand / accent (unchanged across themes)
  static const cyan = Color(0xFF06B6D4);
  static const cyanLight = Color(0xFF22D3EE);
  static const cyanHover = Color(0xFF0891B2);

  // Text
  static Color get textPrimary => _isLight ? const Color(0xFF0F172A) : const Color(0xFFFFFFFF);
  static Color get textMuted => _isLight ? const Color(0xFF64748B) : const Color(0xFF9CA3AF);
  static Color get textDim => _isLight ? const Color(0xFF94A3B8) : const Color(0xFF6B7280);
  static Color get textLabel => _isLight ? const Color(0xFF475569) : const Color(0xFF667085);
  static Color get textDisabled => _isLight ? const Color(0xFFCBD5E1) : const Color(0xFF4B5563);

  // Semantic
  static const red = Color(0xFFEF4444);
  static const redLight = Color(0xFFF87171);
  static const orange = Color(0xFFF97316);
  static const orangeLight = Color(0xFFFB923C);
  static const yellow = Color(0xFFEAB308);
  static const yellowLight = Color(0xFFFACC15);
  static const green = Color(0xFF10B981);
  static const greenLight = Color(0xFF34D399);
  static const blue = Color(0xFF3B82F6);
  static const blueLight = Color(0xFF60A5FA);
  static const purple = Color(0xFFA855F7);
  static const violet = Color(0xFF8B5CF6);
  static const amber = Color(0xFFF59E0B);
  static const grey = Color(0xFF6B7280);

  // Chart lines
  static const chartNormal = Color(0xFF10B981);
  static const chartSuspicious = Color(0xFFF59E0B);
  static const chartMalicious = Color(0xFFEF4444);

  // Donut segments
  static const donutHttp = Color(0xFF06B6D4);
  static const donutSsh = Color(0xFF10B981);
  static const donutFtp = Color(0xFFF59E0B);
  static const donutDns = Color(0xFF8B5CF6);
  static const donutOther = Color(0xFF6B7280);

  static const cardRadius = 10.0;
  static const cardPadding = 24.0;
}
