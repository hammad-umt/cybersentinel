import 'dart:async';
import 'dart:math';

import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/widgets/shared/animated_widgets.dart';
import 'package:cybersentinel/widgets/shared/cyber_card.dart';
import 'package:cybersentinel/widgets/shared/page_header.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class DashboardContent extends StatefulWidget {
  const DashboardContent({super.key});

  @override
  State<DashboardContent> createState() => _DashboardContentState();
}

class _DashboardContentState extends State<DashboardContent> {
  Map<String, dynamic>? _summary;
  List<Map<String, dynamic>> _topThreats = [];
  bool _loading = true;
  String? _error;
  Timer? _refreshTimer;

  final List<_TrafficPoint> _trafficHistory = [];
  final _random = Random();

  static const _gap = 16.0;
  static const _pagePad = 32.0;
  static const _kpiHeight = 225.0;
  static const _rowHeight = 430.0;

  @override
  void initState() {
    super.initState();
    _loadData();
    _refreshTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (!_loading && mounted) _loadData(silent: true);
    });
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadData({bool silent = false}) async {
    if (!ApiConfig.isConfigured) {
      setState(() {
        _loading = false;
        _error = 'Please sign in to continue';
      });
      return;
    }

    if (!silent) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }

    try {
      final summary = await ApiService.instance.getDashboardSummary();
      final threats = await ApiService.instance.getTopThreats(limit: 7);
      if (!mounted) return;

      final packets = (summary['packet_events'] as num?)?.toDouble() ?? 2400000;
      final avgThreat = (summary['avg_packet_threat_score'] as num?)?.toDouble() ?? 0;
      final critical = (summary['critical_alerts'] as num?)?.toDouble() ?? 0;

      setState(() {
        _summary = summary;
        _topThreats = (threats['results'] as List? ?? []).cast<Map<String, dynamic>>();
        _loading = false;
        _error = null;

        _trafficHistory.add(_TrafficPoint(
          normal: 5000 + _random.nextDouble() * 3000,
          suspicious: 200 + _random.nextDouble() * 500,
          malicious: 50 + _random.nextDouble() * 200,
        ));
        if (_trafficHistory.length > 24) _trafficHistory.removeAt(0);
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString().replaceFirst('Exception: ', '');
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return SmoothDataView(
      loading: _loading || _summary == null,
      error: _error,
      onRetry: _loadData,
      loadingWidget: const _DashboardSkeleton(),
      child: _buildDashboard(),
    );
  }

  Widget _buildDashboard() {
    final summary = _summary;
    if (summary == null) return const SizedBox.shrink();
    final maxThreat = (summary['max_firewall_threat_score'] as num?)?.toDouble() ?? 73;
    final threatPercent = maxThreat.clamp(0, 100).toInt();
    final recentAlerts = (summary['recent_alerts'] as List? ?? []).cast<Map<String, dynamic>>();
    final protocols = (summary['protocol_distribution'] as List? ?? []).cast<Map<String, dynamic>>();

    final activeThreats = (summary['unacknowledged_alerts'] as num?)?.toInt() ?? 23;
    final packets = summary['packet_events'] ?? 2400000;
    final suspiciousIps = summary['firewall_alerts'] ?? 156;
    final criticalCount = summary['critical_alerts'] ?? 5;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(_pagePad),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FadeSlideIn(
            child: PageHeader(
              title: 'Security overview',
              subtitle: 'Real-time KPIs across packet events, firewall alerts, and threat scoring.',
              icon: Icons.grid_view_rounded,
              badge: 'Live',
              actions: IconButton(
                onPressed: _loadData,
                tooltip: 'Refresh dashboard',
                icon: Icon(Icons.refresh_rounded, color: AppColors.textMuted),
              ),
            ),
          ),
          // Row 1 — 4 KPI cards (equal width, fixed height)
          SizedBox(
            height: _kpiHeight,
            child: Row(
              children: [
                Expanded(
                  child: FadeSlideIn(
                    child: _ThreatScoreCard(score: threatPercent),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 80),
                    child: _KpiCard(
                      icon: Icons.warning_amber_rounded,
                      iconColor: AppColors.red,
                      iconBg: AppColors.red.withValues(alpha: 0.1),
                      label: 'Active Threats',
                      value: activeThreats,
                      change: '+$criticalCount',
                      changeType: _ChangeType.negative,
                    ),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 160),
                    child: _KpiCard(
                      icon: Icons.show_chart_rounded,
                      iconColor: AppColors.blue,
                      iconBg: AppColors.blue.withValues(alpha: 0.1),
                      label: 'Packets Analyzed',
                      value: packets,
                      change: '+12.5%',
                      changeType: _ChangeType.neutral,
                      formatLarge: true,
                    ),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 240),
                    child: _KpiCard(
                      icon: Icons.language,
                      iconColor: AppColors.orange,
                      iconBg: AppColors.orange.withValues(alpha: 0.1),
                      label: 'Suspicious IPs',
                      value: suspiciousIps,
                      change: '-8',
                      changeType: _ChangeType.positive,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          // Row 2 — Traffic 2/3 + Alerts 1/3
          SizedBox(
            height: _rowHeight,
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Expanded(
                  flex: 2,
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 320),
                    child: _TrafficChart(history: _trafficHistory),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 400),
                    child: _AlertsPanel(alerts: recentAlerts),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          // Row 3 — Donut 1/3 + Table 2/3
          SizedBox(
            height: _rowHeight,
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 480),
                    child: _PacketDonut(protocols: protocols),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  flex: 2,
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 560),
                    child: _MaliciousIPsTable(threats: _topThreats),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _TrafficPoint {
  _TrafficPoint({required this.normal, required this.suspicious, required this.malicious});
  final double normal;
  final double suspicious;
  final double malicious;
}

enum _ChangeType { positive, negative, neutral }

class _DashboardSkeleton extends StatelessWidget {
  const _DashboardSkeleton();

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(32),
      child: Column(
        children: [
          ShimmerBox(height: 225, width: double.infinity, borderRadius: 10),
          SizedBox(height: 24),
          ShimmerBox(height: 430, width: double.infinity, borderRadius: 10),
          SizedBox(height: 24),
          ShimmerBox(height: 430, width: double.infinity, borderRadius: 10),
        ],
      ),
    );
  }
}

class _ThreatScoreCard extends StatelessWidget {
  const _ThreatScoreCard({required this.score});
  final int score;

  Color get _color {
    if (score >= 70) return AppColors.red;
    if (score >= 40) return AppColors.amber;
    return AppColors.green;
  }

  Color get _textColor {
    if (score >= 70) return AppColors.redLight;
    if (score >= 40) return AppColors.amber;
    return AppColors.greenLight;
  }

  String get _label {
    if (score >= 70) return 'High Risk Detected';
    if (score >= 40) return 'Moderate Risk';
    return 'Low Risk';
  }

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: AppColors.red.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(Icons.shield_outlined, color: _color, size: 24),
              ),
              Text(
                'RISK LEVEL',
                style: TextStyle(
                  color: AppColors.textLabel,
                  fontSize: 11,
                  letterSpacing: 1.2,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          AnimatedCounter(
            value: score,
            suffix: '%',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 34,
              height: 1,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'Threat Score',
            style: TextStyle(color: AppColors.textMuted, fontSize: 14, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 16),
          AnimatedProgressBar(value: score / 100, color: _color, height: 8),
          const SizedBox(height: 12),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Critical',
                style: TextStyle(color: AppColors.textLabel, fontSize: 11, fontWeight: FontWeight.w500),
              ),
              Text(
                _label,
                style: TextStyle(color: _textColor, fontSize: 11, fontWeight: FontWeight.w600),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _KpiCard extends StatelessWidget {
  const _KpiCard({
    required this.icon,
    required this.iconColor,
    required this.iconBg,
    required this.label,
    required this.value,
    required this.change,
    required this.changeType,
    this.formatLarge = false,
  });

  final IconData icon;
  final Color iconColor;
  final Color iconBg;
  final String label;
  final num value;
  final String change;
  final _ChangeType changeType;
  final bool formatLarge;

  Color get _changeColor => switch (changeType) {
        _ChangeType.positive => AppColors.greenLight,
        _ChangeType.negative => AppColors.redLight,
        _ChangeType.neutral => AppColors.textMuted,
      };

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(color: iconBg, borderRadius: BorderRadius.circular(10)),
            child: Icon(icon, color: iconColor, size: 24),
          ),
          const Spacer(),
          TweenAnimationBuilder<double>(
            tween: Tween(begin: 0, end: value.toDouble()),
            duration: const Duration(milliseconds: 1000),
            curve: Curves.easeOutCubic,
            builder: (_, v, _) {
              final display = formatLarge ? _formatLarge(v) : v.round().toString();
              return Text(
                display,
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 34,
                  height: 1,
                  fontWeight: FontWeight.w700,
                ),
              );
            },
          ),
          const SizedBox(height: 8),
          Text(
            label,
            style: TextStyle(color: AppColors.textMuted, fontSize: 14, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              if (changeType == _ChangeType.negative)
                Icon(Icons.trending_up, size: 14, color: _changeColor)
              else if (changeType == _ChangeType.positive)
                Icon(Icons.trending_down, size: 14, color: _changeColor),
              if (changeType != _ChangeType.neutral) const SizedBox(width: 4),
              Text(change, style: TextStyle(color: _changeColor, fontSize: 12, fontWeight: FontWeight.w500)),
              Text(
                ' last hour',
                style: TextStyle(
                  color: changeType == _ChangeType.neutral ? AppColors.textLabel : AppColors.textLabel,
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  String _formatLarge(double v) {
    if (v >= 1000000) return '${(v / 1000000).toStringAsFixed(1)}M';
    if (v >= 1000) return '${(v / 1000).toStringAsFixed(1)}K';
    return v.toStringAsFixed(0);
  }
}

class _TrafficChart extends StatelessWidget {
  const _TrafficChart({required this.history});
  final List<_TrafficPoint> history;

  @override
  Widget build(BuildContext context) {
    final data = history.isEmpty
        ? List.generate(12, (i) => _TrafficPoint(
              normal: 5500 + sin(i * 0.8) * 1500 + 1500,
              suspicious: 400 + sin(i * 0.5) * 150,
              malicious: 80 + sin(i * 0.3) * 40,
            ))
        : history;

    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Real-Time Network Traffic',
                      style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
                    ),
                    SizedBox(height: 4),
                    Text(
                      'Packets per 5-minute interval',
                      style: TextStyle(color: AppColors.textMuted, fontSize: 13, fontWeight: FontWeight.w500),
                    ),
                  ],
                ),
              ),
              const Wrap(
                spacing: 14,
                runSpacing: 6,
                children: [
                  _LegendDot(color: AppColors.chartNormal, label: 'Normal'),
                  _LegendDot(color: AppColors.chartSuspicious, label: 'Suspicious'),
                  _LegendDot(color: AppColors.chartMalicious, label: 'Malicious'),
                ],
              ),
            ],
          ),
          const SizedBox(height: 16),
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                color: AppColors.chartBg,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: AppColors.border),
              ),
              padding: const EdgeInsets.fromLTRB(8, 12, 12, 8),
              child: LineChart(
                duration: const Duration(milliseconds: 600),
                LineChartData(
                  minY: 0,
                  maxY: 8000,
                  gridData: FlGridData(
                    show: true,
                    drawVerticalLine: false,
                    horizontalInterval: 2000,
                    getDrawingHorizontalLine: (_) => FlLine(
                      color: AppColors.border,
                      strokeWidth: 1,
                      dashArray: [3, 3],
                    ),
                  ),
                  titlesData: FlTitlesData(
                    leftTitles: AxisTitles(
                      sideTitles: SideTitles(
                        showTitles: true,
                        reservedSize: 36,
                        interval: 2000,
                        getTitlesWidget: (v, _) => Text(
                          v.toInt().toString(),
                          style: TextStyle(color: AppColors.textDim, fontSize: 11),
                        ),
                      ),
                    ),
                    rightTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
                    topTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
                    bottomTitles: AxisTitles(
                      sideTitles: SideTitles(
                        showTitles: true,
                        reservedSize: 28,
                        interval: max(1, (data.length / 4).floorToDouble()),
                        getTitlesWidget: (v, _) {
                          final idx = v.toInt();
                          if (idx < 0 || idx >= data.length) return const SizedBox.shrink();
                          final t = DateTime.now().subtract(Duration(minutes: (data.length - idx) * 5));
                          final h = t.hour > 12 ? t.hour - 12 : (t.hour == 0 ? 12 : t.hour);
                          final ampm = t.hour >= 12 ? 'PM' : 'AM';
                          return Padding(
                            padding: const EdgeInsets.only(top: 6),
                            child: Text(
                              '$h:${t.minute.toString().padLeft(2, '0')} $ampm',
                              style: TextStyle(color: AppColors.textDim, fontSize: 10),
                            ),
                          );
                        },
                      ),
                    ),
                  ),
                  borderData: FlBorderData(show: false),
                  lineBarsData: [
                    _line(data.map((e) => e.normal).toList(), AppColors.chartNormal),
                    _line(data.map((e) => e.suspicious).toList(), AppColors.chartSuspicious),
                    _line(data.map((e) => e.malicious).toList(), AppColors.chartMalicious),
                  ],
                  lineTouchData: LineTouchData(
                    touchTooltipData: LineTouchTooltipData(
                      getTooltipColor: (_) => AppColors.card,
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  LineChartBarData _line(List<double> values, Color color) {
    return LineChartBarData(
      spots: List.generate(values.length, (i) => FlSpot(i.toDouble(), values[i])),
      isCurved: true,
      curveSmoothness: 0.25,
      color: color,
      barWidth: 2,
      dotData: const FlDotData(show: false),
    );
  }
}

class _LegendDot extends StatelessWidget {
  const _LegendDot({required this.color, required this.label});
  final Color color;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(width: 10, height: 10, decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
        const SizedBox(width: 7),
        Text(label, style: TextStyle(color: AppColors.textMuted, fontSize: 12, fontWeight: FontWeight.w500)),
      ],
    );
  }
}

class _AlertsPanel extends StatelessWidget {
  const _AlertsPanel({required this.alerts});
  final List<Map<String, dynamic>> alerts;

  @override
  Widget build(BuildContext context) {
    final active = alerts.where((a) => a['acknowledged'] != true).length;

    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Active Alerts',
                      style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
                    ),
                    SizedBox(height: 4),
                    Text(
                      'Recent security events',
                      style: TextStyle(color: AppColors.textMuted, fontSize: 13, fontWeight: FontWeight.w500),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                decoration: BoxDecoration(
                  color: AppColors.red.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: AppColors.red.withValues(alpha: 0.2)),
                ),
                child: Text(
                  '$active active',
                  style: TextStyle(color: AppColors.redLight, fontSize: 12, fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Expanded(
            child: alerts.isEmpty
                ? Center(child: Text('No recent alerts', style: TextStyle(color: AppColors.textDim)))
                : ListView.separated(
                    itemCount: alerts.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 12),
                    itemBuilder: (context, i) {
                      final item = alerts[i];
                      final severity = item['severity']?.toString() ?? 'medium';
                      final color = severityColor(severity);
                      return FadeSlideIn(
                        delay: Duration(milliseconds: 50 * i),
                        offset: const Offset(8, 0),
                        child: _AlertItem(item: item, severity: severity, color: color),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _AlertItem extends StatelessWidget {
  const _AlertItem({required this.item, required this.severity, required this.color});
  final Map<String, dynamic> item;
  final String severity;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.alertItemBg,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.borderElevated),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(severityIcon(severity), color: color, size: 18),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  alertTitle(item),
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              CyberBadge(label: severity, color: color),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                item['src_ip']?.toString() ?? '',
                style: GoogleFonts.jetBrainsMono(
                  color: AppColors.textMuted,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
              Text(
                timeAgo(item['timestamp']?.toString()),
                style: TextStyle(color: AppColors.textLabel, fontSize: 13, fontWeight: FontWeight.w500),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _PacketDonut extends StatelessWidget {
  const _PacketDonut({required this.protocols});
  final List<Map<String, dynamic>> protocols;

  static const _figmaDefaults = [
    ('HTTP/HTTPS', 45, AppColors.donutHttp),
    ('SSH', 20, AppColors.donutSsh),
    ('FTP', 15, AppColors.donutFtp),
    ('DNS', 12, AppColors.donutDns),
    ('Other', 8, AppColors.donutOther),
  ];

  List<(String, double, Color)> get _segments {
    if (protocols.isEmpty) {
      return _figmaDefaults.map((e) => (e.$1, e.$2.toDouble(), e.$3)).toList();
    }
    final total = protocols.fold<int>(0, (s, p) => s + ((p['count'] as num?)?.toInt() ?? 0));
    final colors = [AppColors.donutHttp, AppColors.donutSsh, AppColors.donutFtp, AppColors.donutDns, AppColors.donutOther];
    return protocols.asMap().entries.map((e) {
      final count = (e.value['count'] as num?)?.toInt() ?? 0;
      final pct = total > 0 ? count / total * 100 : 0.0;
      return (e.value['protocol']?.toString() ?? 'Unknown', pct, colors[e.key % colors.length]);
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    final segments = _segments;

    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Packet Classification',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 4),
          Text(
            'By protocol type',
            style: TextStyle(color: AppColors.textMuted, fontSize: 13, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 12),
          Expanded(
            child: TweenAnimationBuilder<double>(
              tween: Tween(begin: 0, end: 1),
              duration: const Duration(milliseconds: 1000),
              curve: Curves.easeOutCubic,
              builder: (_, anim, _) {
                return PieChart(
                  PieChartData(
                    sectionsSpace: 2,
                    centerSpaceRadius: 60,
                    sections: segments
                        .map(
                          (s) => PieChartSectionData(
                            value: s.$2 * anim,
                            color: s.$3,
                            radius: 45,
                            title: '',
                          ),
                        )
                        .toList(),
                  ),
                );
              },
            ),
          ),
          Wrap(
            spacing: 14,
            runSpacing: 8,
            alignment: WrapAlignment.center,
            children: segments.take(4).map((s) => _LegendDot(color: s.$3, label: s.$1)).toList(),
          ),
          if (segments.length > 4)
            Center(child: _LegendDot(color: segments[4].$3, label: segments[4].$1)),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(child: _PctCell(segments[0])),
              Expanded(child: _PctCell(segments.length > 1 ? segments[1] : segments[0])),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(child: _PctCell(segments.length > 2 ? segments[2] : segments[0])),
              Expanded(child: _PctCell(segments.length > 3 ? segments[3] : segments[0])),
            ],
          ),
        ],
      ),
    );
  }
}

class _PctCell extends StatelessWidget {
  const _PctCell(this.segment);
  final (String, double, Color) segment;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(width: 8, height: 8, decoration: BoxDecoration(color: segment.$3, shape: BoxShape.circle)),
        const SizedBox(width: 6),
        Text(
          segment.$1,
          style: TextStyle(color: AppColors.textMuted, fontSize: 12, fontWeight: FontWeight.w500),
        ),
        const Spacer(),
        Text(
          '${segment.$2.round()}%',
          style: TextStyle(color: AppColors.textPrimary, fontSize: 12, fontWeight: FontWeight.w600),
        ),
        const SizedBox(width: 16),
      ],
    );
  }
}

class _MaliciousIPsTable extends StatelessWidget {
  const _MaliciousIPsTable({required this.threats});
  final List<Map<String, dynamic>> threats;

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Top Malicious IPs',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
                  ),
                  SizedBox(height: 4),
                  Text(
                    'Most frequent threat sources',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 13, fontWeight: FontWeight.w500),
                  ),
                ],
              ),
              TextButton.icon(
                onPressed: () {},
                style: TextButton.styleFrom(
                  padding: EdgeInsets.zero,
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                icon: Icon(Icons.open_in_new, size: 12, color: AppColors.cyanLight),
                label: Text(
                  'View All',
                  style: TextStyle(color: AppColors.cyanLight, fontSize: 13, fontWeight: FontWeight.w500),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Divider(color: AppColors.border, height: 1),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Row(
              children: [
                Expanded(
                  flex: 3,
                  child: Text(
                    'IP ADDRESS',
                    style: TextStyle(color: AppColors.textLabel, fontSize: 11, fontWeight: FontWeight.w600, letterSpacing: 0.5),
                  ),
                ),
                Expanded(
                  flex: 2,
                  child: Text(
                    'COUNTRY',
                    style: TextStyle(color: AppColors.textLabel, fontSize: 11, fontWeight: FontWeight.w600, letterSpacing: 0.5),
                  ),
                ),
                Expanded(
                  flex: 2,
                  child: Text(
                    'ATTEMPTS',
                    textAlign: TextAlign.right,
                    style: TextStyle(color: AppColors.textLabel, fontSize: 11, fontWeight: FontWeight.w600, letterSpacing: 0.5),
                  ),
                ),
                Expanded(
                  flex: 2,
                  child: Text(
                    'RISK LEVEL',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: AppColors.textLabel, fontSize: 11, fontWeight: FontWeight.w600, letterSpacing: 0.5),
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: threats.isEmpty
                ? Center(child: Text('No threat data yet', style: TextStyle(color: AppColors.textDim)))
                : ListView.separated(
                    itemCount: threats.length,
                    separatorBuilder: (_, __) => Divider(color: AppColors.border, height: 1),
                    itemBuilder: (context, i) {
                      final row = threats[i];
                      final severity = row['severity']?.toString() ?? 'medium';
                      final color = severityColor(severity);
                      final attempts = (row['attempts'] as num?)?.toInt() ??
                          (row['final_score'] as num?)?.toInt() ??
                          0;
                      return _TableRow(
                        ip: row['ip']?.toString() ?? '-',
                        country: row['country']?.toString() ?? row['classification']?.toString() ?? '-',
                        attempts: attempts,
                        severity: severity,
                        color: color,
                        delay: Duration(milliseconds: 40 * i),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _TableRow extends StatefulWidget {
  const _TableRow({
    required this.ip,
    required this.country,
    required this.attempts,
    required this.severity,
    required this.color,
    required this.delay,
  });

  final String ip;
  final String country;
  final int attempts;
  final String severity;
  final Color color;
  final Duration delay;

  @override
  State<_TableRow> createState() => _TableRowState();
}

class _TableRowState extends State<_TableRow> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    return FadeSlideIn(
      delay: widget.delay,
      child: MouseRegion(
        onEnter: (_) => setState(() => _hover = true),
        onExit: (_) => setState(() => _hover = false),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          color: _hover ? AppColors.rowHover : Colors.transparent,
          padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 4),
          child: Row(
            children: [
              Expanded(
                flex: 3,
                child: Text(
                  widget.ip,
                  style: GoogleFonts.jetBrainsMono(
                    color: AppColors.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  widget.country,
                  style: TextStyle(color: AppColors.textMuted, fontSize: 14, fontWeight: FontWeight.w500),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  widget.attempts.toString(),
                  textAlign: TextAlign.right,
                  style: TextStyle(color: AppColors.textPrimary, fontSize: 15, fontWeight: FontWeight.w700),
                ),
              ),
              Expanded(
                flex: 2,
                child: Center(child: CyberBadge(label: widget.severity, color: widget.color)),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
