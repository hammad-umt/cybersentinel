import 'package:flutter/material.dart';

/// Exact Figma Make CyberSentinel design tokens.
abstract final class AppColors {
  // Surfaces
  static const bg = Color(0xFF0A0E1A);
  static const panel = Color(0xFF0F1420);
  static const card = Color(0xFF0F1420);
  static const chartBg = Color(0xFF0B1120);
  static const alertItemBg = Color(0xFF1A1F2E);
  static const rowHover = Color(0xFF1A1F2E);

  // Borders
  static const border = Color(0xFF1A1F2E);
  static const borderElevated = Color(0xFF2A2F3E);
  static const borderHover = Color(0xFF3A3F4E);

  // Brand / accent
  static const cyan = Color(0xFF06B6D4);
  static const cyanLight = Color(0xFF22D3EE);
  static const cyanHover = Color(0xFF0891B2);

  // Text
  static const textPrimary = Color(0xFFFFFFFF);
  static const textMuted = Color(0xFF9CA3AF);
  static const textDim = Color(0xFF6B7280);
  static const textLabel = Color(0xFF667085);
  static const textDisabled = Color(0xFF4B5563);

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

  // Donut segments (Figma order)
  static const donutHttp = Color(0xFF06B6D4);
  static const donutSsh = Color(0xFF10B981);
  static const donutFtp = Color(0xFFF59E0B);
  static const donutDns = Color(0xFF8B5CF6);
  static const donutOther = Color(0xFF6B7280);

  static const cardRadius = 10.0;
  static const cardPadding = 24.0;
}
