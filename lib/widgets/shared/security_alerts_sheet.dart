import 'package:cybersentinel/services/navigation_intent_service.dart';
import 'package:cybersentinel/services/security_alert_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

void showSecurityAlertsPanel(BuildContext context) {
  SecurityAlertService.instance.markAllRead();
  showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    builder: (ctx) {
      final w = MediaQuery.sizeOf(ctx).width;
      final h = MediaQuery.sizeOf(ctx).height;
      final isWide = w >= 900;
      if (!isWide) return const SecurityAlertsPanel();

      // Desktop: render a right-side drawer panel (fixed width),
      // avoiding DraggableScrollableSheet (which tends to expand full-width in modal sheets).
      return Align(
        alignment: Alignment.bottomRight,
        child: SizedBox(
          width: 520,
          height: (h * 0.82).clamp(520, 860),
          child: const SecurityAlertsPanelDesktop(),
        ),
      );
    },
  );
}

class SecurityAlertsPanel extends StatelessWidget {
  const SecurityAlertsPanel({super.key});

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.55,
      minChildSize: 0.35,
      maxChildSize: 0.9,
      builder: (context, scrollController) {
        return _AlertsPanelScaffold(scrollController: scrollController);
      },
    );
  }
}

class SecurityAlertsPanelDesktop extends StatelessWidget {
  const SecurityAlertsPanelDesktop({super.key});

  @override
  Widget build(BuildContext context) {
    final scrollController = ScrollController();
    return _AlertsPanelScaffold(scrollController: scrollController);
  }
}

class _AlertsPanelScaffold extends StatelessWidget {
  const _AlertsPanelScaffold({required this.scrollController});

  final ScrollController scrollController;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: AppColors.panel,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
        border: Border.all(color: AppColors.borderElevated),
      ),
      child: ListenableBuilder(
        listenable: SecurityAlertService.instance,
        builder: (context, _) {
          final service = SecurityAlertService.instance;
          final alerts = service.alerts;

          return Column(
            children: [
              const SizedBox(height: 10),
              Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: AppColors.borderElevated,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 16, 12, 8),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: AppColors.cyan.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Icon(Icons.notifications_active, color: AppColors.cyanLight, size: 22),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Security alerts',
                            style: GoogleFonts.inter(
                              color: AppColors.textPrimary,
                              fontSize: 18,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                          Text(
                            alerts.isEmpty
                                ? 'Monitoring packets & firewall events'
                                : '${alerts.length} recent alert${alerts.length == 1 ? '' : 's'}',
                            style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 12),
                          ),
                        ],
                      ),
                    ),
                    if (alerts.isNotEmpty)
                      TextButton(
                        onPressed: service.clearAlerts,
                        style: TextButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                          minimumSize: Size.zero,
                          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        ),
                        child: Text('Clear all', style: TextStyle(color: AppColors.cyanLight)),
                      ),
                    const SizedBox(width: 4),
                    IconButton(
                      onPressed: () => Navigator.pop(context),
                      tooltip: 'Close',
                      icon: Icon(Icons.close, color: AppColors.textMuted),
                    ),
                  ],
                ),
              ),
              const Divider(height: 1),
              Expanded(
                child: alerts.isEmpty
                    ? Center(
                        child: Padding(
                          padding: const EdgeInsets.all(32),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(Icons.verified_user_outlined, color: AppColors.textDim, size: 48),
                              const SizedBox(height: 16),
                              Text(
                                'No alerts yet',
                                style: GoogleFonts.inter(
                                  color: AppColors.textPrimary,
                                  fontSize: 16,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              const SizedBox(height: 8),
                              Text(
                                'Suspicious packets and firewall threats will appear here with real-time notifications.',
                                textAlign: TextAlign.center,
                                style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 13, height: 1.4),
                              ),
                            ],
                          ),
                        ),
                      )
                    : ListView.builder(
                        controller: scrollController,
                        padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
                        itemCount: alerts.length,
                        itemBuilder: (context, i) => _AlertCard(
                          alert: alerts[i],
                          onDismiss: () => service.dismissAlert(alerts[i].id),
                        ),
                      ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _AlertCard extends StatelessWidget {
  const _AlertCard({required this.alert, required this.onDismiss});

  final SecurityAlert alert;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final color = _severityColor(alert.severity);
    final sourceLabel = alert.source == 'firewall' ? 'Firewall' : 'Packet capture';
    final sourceIcon = alert.source == 'firewall' ? Icons.shield_outlined : Icons.lan_outlined;

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: AppColors.bg,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: IntrinsicHeight(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(
              width: 4,
              decoration: BoxDecoration(
                color: color,
                borderRadius: const BorderRadius.horizontal(left: Radius.circular(12)),
              ),
            ),
            Expanded(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(14, 12, 8, 12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: color.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            alert.severity.toUpperCase(),
                            style: GoogleFonts.inter(
                              color: color,
                              fontSize: 10,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Icon(sourceIcon, size: 14, color: AppColors.textDim),
                        const SizedBox(width: 4),
                        Text(
                          sourceLabel,
                          style: GoogleFonts.inter(color: AppColors.textDim, fontSize: 11),
                        ),
                        const Spacer(),
                        Text(
                          _formatTime(alert.timestamp),
                          style: GoogleFonts.inter(color: AppColors.textDim, fontSize: 11),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      alert.title,
                      style: GoogleFonts.inter(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      alert.message,
                      style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 13, height: 1.35),
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        if (_extractIp(alert.message) != null)
                          TextButton.icon(
                            onPressed: () {
                              Navigator.pop(context);
                              NavigationIntentService.instance
                                  .openIpAnalysis(_extractIp(alert.message)!);
                            },
                            icon: Icon(Icons.open_in_new, size: 14, color: AppColors.cyanLight),
                            label: Text('Investigate IP', style: TextStyle(color: AppColors.cyanLight)),
                          ),
                        const Spacer(),
                        IconButton(
                          onPressed: onDismiss,
                          icon: Icon(Icons.close, size: 18, color: AppColors.textDim),
                          tooltip: 'Dismiss',
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  String? _extractIp(String message) {
    final match = RegExp(r'\b(?:\d{1,3}\.){3}\d{1,3}\b').firstMatch(message);
    return match?.group(0);
  }

  Color _severityColor(String severity) {
    switch (severity.toLowerCase()) {
      case 'high':
      case 'critical':
      case 'malicious':
        return AppColors.redLight;
      case 'medium':
      case 'suspicious':
        return AppColors.orangeLight;
      default:
        return AppColors.cyanLight;
    }
  }

  String _formatTime(DateTime time) {
    final diff = DateTime.now().difference(time);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }
}

/// Floating toast shown briefly when a new alert arrives.
class SecurityAlertToast extends StatelessWidget {
  const SecurityAlertToast({super.key, required this.alert, required this.onDismiss});

  final SecurityAlert alert;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final color = alert.severity == 'high' || alert.severity == 'malicious'
        ? AppColors.redLight
        : AppColors.orangeLight;
    final maxW = MediaQuery.sizeOf(context).width - 32;

    return Material(
      elevation: 8,
      borderRadius: BorderRadius.circular(12),
      color: AppColors.panel,
      child: Container(
        constraints: BoxConstraints(maxWidth: maxW.clamp(280, 360)),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: 0.4)),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.warning_amber_rounded, color: color, size: 22),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    alert.title,
                    style: GoogleFonts.inter(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    alert.message,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 12),
                  ),
                ],
              ),
            ),
            IconButton(
              onPressed: onDismiss,
              icon: Icon(Icons.close, size: 18, color: AppColors.textDim),
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            ),
          ],
        ),
      ),
    );
  }
}
