import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';

/// Figma card — #0F1420 bg, #1A1F2E border, hover cyan/30.
class CyberCard extends StatefulWidget {
  const CyberCard({super.key, required this.child, this.padding});

  final Widget child;
  final EdgeInsetsGeometry? padding;

  @override
  State<CyberCard> createState() => _CyberCardState();
}

class _CyberCardState extends State<CyberCard> {
  bool _hovering = false;

  @override
  Widget build(BuildContext context) {
    return MouseRegion(
      onEnter: (_) => setState(() => _hovering = true),
      onExit: (_) => setState(() => _hovering = false),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
        width: double.infinity,
        padding: widget.padding ?? const EdgeInsets.all(AppColors.cardPadding),
        decoration: BoxDecoration(
          color: AppColors.card,
          borderRadius: BorderRadius.circular(AppColors.cardRadius),
          border: Border.all(
            color: _hovering
                ? AppColors.cyan.withValues(alpha: 0.3)
                : AppColors.border,
          ),
        ),
        child: widget.child,
      ),
    );
  }
}

/// Figma badge — 10% fill, 20% border, uppercase 11px.
class CyberBadge extends StatelessWidget {
  const CyberBadge({super.key, required this.label, required this.color});

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.2)),
      ),
      child: Text(
        label.toLowerCase(),
        style: TextStyle(
          color: color,
          fontSize: 11,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

Color severityColor(String? severity) {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return AppColors.redLight;
    case 'high':
      return AppColors.orangeLight;
    case 'medium':
      return AppColors.yellowLight;
    case 'low':
      return AppColors.blueLight;
    default:
      return AppColors.textMuted;
  }
}

IconData severityIcon(String? severity) {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return Icons.cancel_outlined;
    case 'high':
      return Icons.warning_amber_rounded;
    default:
      return Icons.shield_outlined;
  }
}

String timeAgo(String? timestamp) {
  if (timestamp == null) return '-';
  try {
    final time = DateTime.parse(timestamp);
    final diff = DateTime.now().difference(time);
    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  } catch (_) {
    return timestamp.length > 16 ? timestamp.substring(11, 16) : timestamp;
  }
}

String alertTitle(Map<String, dynamic> alert) {
  final label = alert['cluster_label']?.toString();
  if (label != null && label.isNotEmpty) return label;
  final signals = alert['attack_signals'];
  if (signals is List && signals.isNotEmpty) {
    return signals.first.toString();
  }
  return 'Threat Detected';
}
