import 'package:cybersentinel/auth/require_auth.dart';
import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/firewall_monitor_service.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/utils/file_export.dart';
import 'package:cybersentinel/widgets/shared/animated_widgets.dart';
import 'package:cybersentinel/widgets/shared/cyber_card.dart';
import 'package:cybersentinel/widgets/shared/page_header.dart';
import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class FirewallLogsContent extends StatelessWidget {
  const FirewallLogsContent({super.key});

  @override
  Widget build(BuildContext context) {
    return ColoredBox(
      color: AppColors.bg,
      child: const FirewallLogsScreen(),
    );
  }
}

class FirewallLogsPage extends StatelessWidget {
  const FirewallLogsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return RequireAuth(
      child: Scaffold(
        backgroundColor: AppColors.bg,
        body: SafeArea(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              buildSidebarPanel(context, 2),
              Expanded(
                child: Column(
                  children: [
                    buildTopNavbar(context, 'Firewall Logs'),
                    const Expanded(child: FirewallLogsScreen()),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class FirewallLogsScreen extends StatefulWidget {
  const FirewallLogsScreen({super.key});

  @override
  State<FirewallLogsScreen> createState() => _FirewallLogsScreenState();
}

class _FirewallLogsScreenState extends State<FirewallLogsScreen> {
  final ScrollController _scrollController = ScrollController();
  final _monitor = FirewallMonitorService.instance;
  List<Map<String, dynamic>> _alerts = [];
  bool _loading = true;
  String? _error;
  String? _anomalyMessage;

  @override
  void initState() {
    super.initState();
    _monitor.addListener(_onMonitorUpdate);
    _loadAlerts();
  }

  @override
  void dispose() {
    _monitor.removeListener(_onMonitorUpdate);
    _scrollController.dispose();
    super.dispose();
  }

  void _onMonitorUpdate() {
    if (mounted) setState(() {});
  }

  Future<void> _loadAlerts() async {
    if (!ApiConfig.isConfigured) {
      setState(() {
        _loading = false;
        _error = 'Please sign in to continue';
      });
      return;
    }

    try {
      final data = await ApiService.instance.getFirewallAlerts(pageSize: 20);
      setState(() {
        _alerts = (data['alerts'] as List? ?? []).cast<Map<String, dynamic>>();
        _loading = false;
        _error = null;
      });
    } catch (e) {
      setState(() {
        _error = e.toString().replaceFirst('Exception: ', '');
        _loading = false;
      });
    }
  }

  Future<void> _uploadLogs() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['log', 'txt', 'csv'],
      withData: true,
    );
    if (result == null || result.files.isEmpty) return;

    setState(() => _loading = true);
    try {
      final analysis = await ApiService.instance.analyzeFirewallLog(result.files.first);
      final signals = (analysis['threat_signals'] as List? ?? []);
      if (signals.isNotEmpty) {
        final top = signals.first as Map<String, dynamic>;
        _anomalyMessage =
            'Detected ${signals.length} threat signal(s). Top: ${top['src_ip']} (${top['severity']})';
      }
      await _loadAlerts();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Firewall log analyzed')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))),
        );
      }
      setState(() => _loading = false);
    }
  }

  Future<void> _exportAlerts() async {
    try {
      final bytes = await ApiService.instance.downloadFirewallAlertsCsv();
      final path = await saveBytesToFile(
        bytes: bytes,
        fileName: 'firewall_alerts.csv',
        extension: 'csv',
      );
      if (mounted && path != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('CSV saved to $path')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))),
        );
      }
    }
  }

  Future<void> _toggleMonitor(bool enabled) async {
    try {
      if (enabled) {
        await _monitor.startMonitor();
      } else {
        await _monitor.stopMonitor();
      }
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(enabled ? 'Monitor started' : 'Monitor stopped')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))),
        );
      }
    }
  }

  Color _severityColor(String severity) {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return AppColors.redLight;
      case 'medium':
        return AppColors.orangeLight;
      case 'low':
        return AppColors.greenLight;
      default:
        return AppColors.textMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    return SmoothDataView(
      loading: _loading,
      error: _error,
      onRetry: _loadAlerts,
      loadingWidget: const Padding(
        padding: EdgeInsets.all(32),
        child: ShimmerBox(height: 500, width: double.infinity, borderRadius: 10),
      ),
      child: FadeSlideIn(
        child: Scrollbar(
          controller: _scrollController,
          child: SingleChildScrollView(
            controller: _scrollController,
            padding: const EdgeInsets.fromLTRB(32, 24, 32, 32),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const PageHeader(
                  title: 'Firewall logs & alerts',
                  subtitle: 'Upload logs, monitor live alerts, and export findings for investigation.',
                  icon: Icons.shield_outlined,
                ),
                _buildTopActionBar(),
                const SizedBox(height: 24),
                LayoutBuilder(
                  builder: (context, c) {
                    if (c.maxWidth > 900) {
                      return Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Expanded(flex: 2, child: _buildActivityCard()),
                          const SizedBox(width: 16),
                          Expanded(child: _buildInsightsCard()),
                        ],
                      );
                    }
                    return Column(
                      children: [
                        _buildActivityCard(),
                        const SizedBox(height: 16),
                        _buildInsightsCard(),
                      ],
                    );
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildTopActionBar() {
    return CyberCard(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      child: Row(
        children: [
          _ActionButton(
            label: 'Upload Logs',
            icon: Icons.upload_outlined,
            filled: true,
            onTap: _uploadLogs,
          ),
          const SizedBox(width: 12),
          _ActionButton(
            label: 'Export CSV',
            icon: Icons.download_outlined,
            filled: false,
            onTap: _exportAlerts,
          ),
          const Spacer(),
          Checkbox(
            value: _monitor.isMonitoring,
            onChanged: (value) {
              _toggleMonitor(value ?? false);
            },
            activeColor: AppColors.cyan,
            checkColor: Colors.white,
            side: BorderSide(color: AppColors.cyan.withValues(alpha: 0.6), width: 1.5),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
          ),
          const SizedBox(width: 4),
          Text(
            'Live monitor',
            style: GoogleFonts.inter(
              color: AppColors.textMuted,
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActivityCard() {
    return CyberCard(
      padding: EdgeInsets.zero,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(24, 24, 24, 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Firewall Activity',
                  style: GoogleFonts.inter(
                    color: AppColors.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  '${_alerts.length} alerts loaded',
                  style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 13),
                ),
              ],
            ),
          ),
          _buildTableHeader(),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.all(24),
              child: Text(_error!, style: TextStyle(color: AppColors.redLight)),
            )
          else if (_alerts.isEmpty)
            Padding(
              padding: const EdgeInsets.all(24),
              child: Text('No firewall alerts yet', style: TextStyle(color: AppColors.textMuted)),
            )
          else
            ..._alerts.map(_buildTableRow),
        ],
      ),
    );
  }

  Widget _buildTableHeader() {
    return Container(
      height: 44,
      color: AppColors.alertItemBg,
      padding: const EdgeInsets.symmetric(horizontal: 24),
      child: Row(
        children: [
          for (final col in [
            ('IP ADDRESS', 3),
            ('PORT', 1),
            ('ACTION', 2),
            ('RULE', 3),
            ('TIMESTAMP', 3),
          ])
            Expanded(
              flex: col.$2,
              child: Center(
                child: Text(
                  col.$1,
                  style: GoogleFonts.inter(
                    color: AppColors.textLabel,
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.4,
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildTableRow(Map<String, dynamic> row) {
    final severity = (row['severity']?.toString() ?? 'low').toLowerCase();
    final statusColor = _severityColor(severity);

    return Container(
      height: 46,
      padding: const EdgeInsets.symmetric(horizontal: 24),
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: AppColors.border)),
      ),
      child: Row(
        children: [
          Expanded(
            flex: 3,
            child: Text(
              row['src_ip']?.toString() ?? '-',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(
                color: AppColors.textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            flex: 1,
            child: Text(
              '${row['attack_signals'] ?? 0}',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 12),
            ),
          ),
          Expanded(
            flex: 2,
            child: Center(child: _SeverityBadge(label: severity, color: statusColor)),
          ),
          Expanded(
            flex: 3,
            child: Text(
              row['cluster_label']?.toString() ?? '-',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 12),
            ),
          ),
          Expanded(
            flex: 3,
            child: Text(
              row['timestamp']?.toString().substring(0, 19) ?? '-',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(color: AppColors.textDim, fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInsightsCard() {
    final highCount = _alerts.where((a) {
      final s = a['severity']?.toString().toLowerCase() ?? '';
      return s == 'high' || s == 'critical';
    }).length;
    final lowCount = _alerts.length - highCount;
    final total = _alerts.isNotEmpty ? _alerts.length : 1;
    final topIps = _alerts.take(4).toList();

    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.bar_chart_rounded, color: AppColors.cyanLight, size: 22),
              const SizedBox(width: 10),
              Text(
                'Insights',
                style: GoogleFonts.inter(
                  color: AppColors.textPrimary,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          Text('Actions (Last Hour)', style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 12)),
          const SizedBox(height: 12),
          _InsightBar(label: 'High/Critical', value: highCount, color: AppColors.redLight, factor: highCount / total),
          const SizedBox(height: 12),
          _InsightBar(label: 'Other', value: lowCount, color: AppColors.greenLight, factor: lowCount / total),
          const SizedBox(height: 16),
          Divider(color: AppColors.borderElevated),
          const SizedBox(height: 16),
          Text('Top Blocked IPs', style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 12)),
          const SizedBox(height: 12),
          for (final item in topIps)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _TopIpRow(
                ip: item['src_ip']?.toString() ?? '-',
                label: item['severity']?.toString() ?? '-',
              ),
            ),
          const SizedBox(height: 16),
          Divider(color: AppColors.borderElevated),
          const SizedBox(height: 16),
          _buildAnomalyCard(),
        ],
      ),
    );
  }

  Widget _buildAnomalyCard() {
    final message = _anomalyMessage ??
        (_alerts.isNotEmpty
            ? 'Latest alert: ${_alerts.first['src_ip']} — ${_alerts.first['severity']}'
            : 'No anomalies detected yet. Upload a firewall log to analyze.');

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.orange.withValues(alpha: AppColors.isLight ? 0.08 : 0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.orange.withValues(alpha: 0.35)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Anomaly Detected',
            style: GoogleFonts.inter(
              color: AppColors.orangeLight,
              fontSize: 14,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            message,
            style: GoogleFonts.inter(
              color: AppColors.textMuted,
              fontSize: 12,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }
}

class _ActionButton extends StatelessWidget {
  const _ActionButton({
    required this.label,
    required this.icon,
    required this.filled,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final bool filled;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: BoxDecoration(
            color: filled ? AppColors.cyan : AppColors.alertItemBg,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: filled ? AppColors.cyan : AppColors.borderElevated),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, color: filled ? Colors.white : AppColors.textPrimary, size: 18),
              const SizedBox(width: 8),
              Text(
                label,
                style: GoogleFonts.inter(
                  color: filled ? Colors.white : AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SeverityBadge extends StatelessWidget {
  const _SeverityBadge({required this.label, required this.color});
  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.28)),
      ),
      child: Text(
        label,
        style: GoogleFonts.inter(color: color, fontSize: 10, fontWeight: FontWeight.w600),
      ),
    );
  }
}

class _InsightBar extends StatelessWidget {
  const _InsightBar({
    required this.label,
    required this.value,
    required this.color,
    required this.factor,
  });

  final String label;
  final int value;
  final Color color;
  final double factor;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(label, style: GoogleFonts.inter(color: color, fontSize: 12, fontWeight: FontWeight.w500)),
            const Spacer(),
            Text('$value', style: GoogleFonts.inter(color: AppColors.textPrimary, fontSize: 12, fontWeight: FontWeight.w600)),
          ],
        ),
        const SizedBox(height: 6),
        ClipRRect(
          borderRadius: BorderRadius.circular(999),
          child: LinearProgressIndicator(
            value: factor.clamp(0.0, 1.0),
            minHeight: 8,
            backgroundColor: AppColors.border,
            color: color,
          ),
        ),
      ],
    );
  }
}

class _TopIpRow extends StatelessWidget {
  const _TopIpRow({required this.ip, required this.label});
  final String ip;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: AppColors.alertItemBg,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              ip,
              style: GoogleFonts.inter(
                color: AppColors.textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Text(label, style: GoogleFonts.inter(color: AppColors.textDim, fontSize: 11)),
        ],
      ),
    );
  }
}
