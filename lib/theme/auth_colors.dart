import 'package:flutter/material.dart';

/// Fixed dark palette for sign-in / register flows — independent of app theme.
abstract final class AuthColors {
  static const bg = Color(0xFF0A0E1A);
  static const panel = Color(0xFF0F1420);
  static const inputBg = Color(0xFF121826);
  static const cardDeep = Color(0xFF111827);
  static const border = Color(0xFF1A1F2E);
  static const borderElevated = Color(0xFF2A2F3E);

  static const textPrimary = Color(0xFFFFFFFF);
  static const textMuted = Color(0xFF9CA3AF);
  static const textDim = Color(0xFF6B7280);

  static const cyan = Color(0xFF06B6D4);
  static const cyanLight = Color(0xFF22D3EE);
  static const violet = Color(0xFF8B5CF6);

  static const redLight = Color(0xFFF87171);
  static const orangeLight = Color(0xFFFB923C);
  static const yellowLight = Color(0xFFFACC15);
  static const greenLight = Color(0xFF34D399);
}
