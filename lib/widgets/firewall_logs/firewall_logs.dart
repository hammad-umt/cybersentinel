import 'dart:io';

import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/widgets/shared/animated_widgets.dart';
import 'package:cybersentinel/widgets/shared/cyber_card.dart';
import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

class FirewallLogsContent extends StatelessWidget {
  const FirewallLogsContent({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: AppColors.bg,
      child: const FirewallLogsScreen(),
    );
  }
}

class FirewallLogsPage extends StatelessWidget {
  const FirewallLogsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            buildSidebarPanel(context, 2),
            Expanded(
              child: Column(
                children: [
                  buildTopNavbar(context, 'Firewall Logs'),
                  Expanded(
                    child: Container(
                      color: const Color(0xFF0B1020),
                      child: const FirewallLogsScreen(),
                    ),
                  ),
                ],
              ),
            ),
          ],
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
  bool _autoFetchLogs = false;
  List<Map<String, dynamic>> _alerts = [];
  bool _loading = true;
  String? _error;
  String? _anomalyMessage;

  @override
  void initState() {
    super.initState();
    _loadAlerts();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadAlerts() async {
    if (!ApiConfig.isConfigured) {
      setState(() {
        _loading = false;
        _error = 'Set your API key in Settings';
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
      final path = await FilePicker.platform.saveFile(
        fileName: 'firewall_alerts.csv',
        type: FileType.custom,
        allowedExtensions: ['csv'],
      );
      if (path != null) {
        await File(path).writeAsBytes(bytes);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Saved to $path')),
          );
        }
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
        await ApiService.instance.startFirewallMonitor();
      } else {
        await ApiService.instance.stopFirewallMonitor();
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
      setState(() => _autoFetchLogs = !enabled);
    }
  }

  Color getStatusColor(String status) {
    switch (status) {
      case 'blocked':
        return const Color(0xFFFF3B57);
      case 'allowed':
        return const Color(0xFF18E26D);
      default:
        return Colors.white;
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
            padding: const EdgeInsets.fromLTRB(18, 18, 18, 18),
            child: ConstrainedBox(
              constraints: const BoxConstraints(minWidth: 1180),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  _buildTopActionBar(),
                  const SizedBox(height: 28),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(flex: 2, child: _buildActivityCard()),
                      const SizedBox(width: 18),
                      Expanded(child: _buildInsightsCard()),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildTopActionBar() {
    return Container(
      height: 100,
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
      decoration: BoxDecoration(
        color: const Color(0xFF0A0E1A),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: const Color(0xFF20283A)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          _buildTopButton(
            label: 'Upload Logs',
            icon: Icons.upload_outlined,
            filled: true,
            onTap: _uploadLogs,
          ),
          const SizedBox(width: 14),
          _buildTopButton(
            label: 'Export',
            icon: Icons.download_outlined,
            filled: false,
            onTap: _exportAlerts,
          ),
          const Spacer(),
          Row(
            children: [
              Checkbox(
                value: _autoFetchLogs,
                onChanged: (value) {
                  final enabled = value ?? false;
                  setState(() => _autoFetchLogs = enabled);
                  _toggleMonitor(enabled);
                },
                activeColor: const Color(0xFFB44BDA),
                checkColor: Colors.white,
                side: const BorderSide(color: Color(0xFFB44BDA), width: 2),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(4),
                ),
              ),
              const SizedBox(width: 4),
              const Text(
                'Auto-fetch logs',
                style: TextStyle(
                  color: Color(0xFF9DACC3),
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildTopButton({
    required String label,
    required IconData icon,
    required bool filled,
    required VoidCallback onTap,
  }) {
    final background = filled ? Colors.cyan : const Color(0xFF1B2233);
    final borderColor = filled ? Colors.cyan : const Color(0xFF31384A);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(18),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          decoration: BoxDecoration(
            color: background,
            borderRadius: BorderRadius.circular(18),
            border: Border.all(color: borderColor),
          ),
          child: Row(
            children: [
              Icon(icon, color: Colors.white, size: 34),
              const SizedBox(width: 8),
              Text(
                label,
                style: const TextStyle(color: Colors.white, fontSize: 15),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildActivityCard() {
    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF0A0E1A),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: const Color.fromARGB(255, 16, 22, 42)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(24, 30, 24, 14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Firewall Activity',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  '${_alerts.length} alerts loaded',
                  style: const TextStyle(
                    color: Color(0xFF9DA9BD),
                    fontSize: 12,
                    fontWeight: FontWeight.w400,
                  ),
                ),
              ],
            ),
          ),
          _buildTableHeader(),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.all(24),
              child: Text(_error!, style: const TextStyle(color: Color(0xFFF87171))),
            )
          else if (_alerts.isEmpty)
            const Padding(
              padding: EdgeInsets.all(24),
              child: Text('No firewall alerts yet', style: TextStyle(color: Color(0xFF9DA9BD))),
            )
          else
            ..._alerts.map((row) => _buildTableRow(row)),
        ],
      ),
    );
  }

  Widget _buildTableHeader() {
    const headerStyle = TextStyle(
      color: Color(0xFF7E889C),
      fontSize: 13,
      fontWeight: FontWeight.w700,
      letterSpacing: 0.4,
    );

    return Container(
      height: 46,
      color: const Color(0xFF1A2030),
      padding: const EdgeInsets.symmetric(horizontal: 24),
      child: const Row(
        children: [
          Expanded(
            flex: 3,
            child: Center(child: Text('IP ADDRESS', style: headerStyle)),
          ),
          Expanded(
            flex: 1,
            child: Center(child: Text('PORT', style: headerStyle)),
          ),
          Expanded(
            flex: 2,
            child: Center(child: Text('ACTION', style: headerStyle)),
          ),
          Expanded(
            flex: 3,
            child: Center(child: Text('RULE', style: headerStyle)),
          ),
          Expanded(
            flex: 3,
            child: Center(child: Text('TIMESTAMP', style: headerStyle)),
          ),
        ],
      ),
    );
  }

  Widget _buildTableRow(Map<String, dynamic> row) {
    final severity = (row['severity']?.toString() ?? 'low').toLowerCase();
    final isHigh = severity == 'high' || severity == 'critical';
    final status = isHigh ? 'blocked' : 'allowed';
    final statusColor = getStatusColor(status);

    return Container(
      height: 46,
      padding: const EdgeInsets.symmetric(horizontal: 24),
      decoration: const BoxDecoration(
        border: Border(bottom: BorderSide(color: Color(0xFF202838), width: 1)),
      ),
      child: Row(
        children: [
          Expanded(
            flex: 3,
            child: Center(
              child: Text(
                row['src_ip']?.toString() ?? '-',
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ),
          Expanded(
            flex: 1,
            child: Center(
              child: Text(
                '${row['attack_signals'] ?? 0}',
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Color(0xFF9DA9BD),
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
          ),
          Expanded(
            flex: 2,
            child: Center(child: _buildStatusBadge(severity, statusColor)),
          ),
          Expanded(
            flex: 3,
            child: Center(
              child: Text(
                row['cluster_label']?.toString() ?? '-',
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Color(0xFF8C96A8),
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
          ),
          Expanded(
            flex: 3,
            child: Center(
              child: Text(
                row['timestamp']?.toString().substring(0, 19) ?? '-',
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Color(0xFF9DA9BD),
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatusBadge(String label, Color color) {
    return Container(
      constraints: const BoxConstraints(minWidth: 78),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.25)),
      ),
      child: Text(
        label,
        textAlign: TextAlign.center,
        style: TextStyle(
          color: color,
          fontSize: 10,
          fontWeight: FontWeight.w600,
        ),
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

    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF0A0E1A),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: const Color(0xFF20283A)),
      ),
      padding: const EdgeInsets.fromLTRB(24, 24, 24, 22),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.bar_chart_rounded, color: Color(0xFF16C6E8), size: 22),
              SizedBox(width: 10),
              Text(
                'Insights',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 22),
          const Text(
            'Actions (Last Hour)',
            style: TextStyle(
              color: Color(0xFF98A3B6),
              fontSize: 12,
              fontWeight: FontWeight.w400,
            ),
          ),
          const SizedBox(height: 16),
          _buildInsightRow('High/Critical', highCount, const Color(0xFFFF3B57), highCount / total),
          const SizedBox(height: 12),
          _buildInsightRow('Other', lowCount, const Color(0xFF18E26D), lowCount / total),
          const SizedBox(height: 18),
          const Divider(color: Color(0xFF242B3B), height: 1),
          const SizedBox(height: 18),
          const Text(
            'Top Blocked IPs',
            style: TextStyle(
              color: Color(0xFF98A3B6),
              fontSize: 12,
              fontWeight: FontWeight.w400,
            ),
          ),
          const SizedBox(height: 14),
          ...topIps.map(
            (item) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _buildTopBlockedRow(
                item['src_ip']?.toString() ?? '-',
                item['severity']?.toString() ?? '-',
              ),
            ),
          ),
          const SizedBox(height: 18),
          const Divider(color: Color(0xFF242B3B), height: 1),
          const SizedBox(height: 26),
          _buildAnomalyCard(),
        ],
      ),
    );
  }

  Widget _buildInsightRow(
    String label,
    int value,
    Color color,
    double widthFactor,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              label,
              style: TextStyle(
                color: color,
                fontSize: 12,
                fontWeight: FontWeight.w500,
              ),
            ),
            const Spacer(),
            Text(
              '$value',
              style: const TextStyle(
                color: Colors.white,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
        const SizedBox(height: 6),
        Container(
          height: 8,
          decoration: BoxDecoration(
            color: const Color(0xFF0A0E1A),
            borderRadius: BorderRadius.circular(999),
          ),
          child: Align(
            alignment: Alignment.centerLeft,
            child: FractionallySizedBox(
              widthFactor: widthFactor,
              child: Container(
                decoration: BoxDecoration(
                  color: color,
                  borderRadius: BorderRadius.circular(999),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildTopBlockedRow(String ip, String rule) {
    return Container(
      height: 38,
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: BoxDecoration(
        color: const Color(0xFF161D2D),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              ip,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Text(
            rule,
            style: const TextStyle(
              color: Color(0xFF8C96A8),
              fontSize: 10,
              fontWeight: FontWeight.w500,
            ),
          ),
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
      padding: const EdgeInsets.fromLTRB(14, 16, 14, 16),
      decoration: BoxDecoration(
        color: const Color(0xFF2C1D16),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF7A3D18)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Anomaly Detected',
            style: TextStyle(
              color: Color(0xFFFF8A00),
              fontSize: 14,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            message,
            style: const TextStyle(
              color: Color(0xFFC9D2E4),
              fontSize: 12,
              fontWeight: FontWeight.w400,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }
}
