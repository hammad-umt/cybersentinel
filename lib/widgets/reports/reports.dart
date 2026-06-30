import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/utils/file_export.dart';
import 'package:cybersentinel/widgets/shared/animated_widgets.dart';
import 'package:cybersentinel/widgets/shared/cyber_card.dart';
import 'package:cybersentinel/widgets/shared/page_header.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

String _formatShortDate(DateTime d) =>
    '${_months[d.month - 1]} ${d.day.toString().padLeft(2, '0')}';

String _formatGeneratedAt(DateTime d) {
  final hour = d.hour.toString().padLeft(2, '0');
  final minute = d.minute.toString().padLeft(2, '0');
  return '${_formatShortDate(d)}, ${d.year} · $hour:$minute';
}

class ReportsContent extends StatefulWidget {
  const ReportsContent({super.key});

  @override
  State<ReportsContent> createState() => _ReportsContentState();
}

class _ReportsContentState extends State<ReportsContent> {
  Map<String, dynamic>? _summary;
  bool _loading = true;
  bool _generating = false;
  bool _downloadingPdf = false;
  bool _exportingCsv = false;
  bool _reportReady = false;
  DateTime? _generatedAt;

  static const _gap = 16.0;
  static const _pagePad = 32.0;
  static const _summaryCardHeight = 104.0;

  @override
  void initState() {
    super.initState();
    _loadSummary();
  }

  Future<void> _loadSummary() async {
    if (!ApiConfig.isConfigured) {
      setState(() => _loading = false);
      return;
    }
    try {
      final summary = await ApiService.instance.getDashboardSummary();
      if (mounted) {
        setState(() {
          _summary = summary;
          _loading = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _generateReport() async {
    if (!ApiConfig.isConfigured) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please sign in to generate reports')),
      );
      return;
    }

    setState(() => _generating = true);
    try {
      final summary = await ApiService.instance.getDashboardSummary();
      if (!mounted) return;
      setState(() {
        _summary = summary;
        _reportReady = true;
        _generatedAt = DateTime.now();
        _generating = false;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Security report generated successfully')),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() => _generating = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))),
      );
    }
  }

  Future<void> _downloadPdf() async {
    if (!_reportReady && _summary == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Generate a report first, then export')),
      );
      return;
    }

    setState(() => _downloadingPdf = true);
    try {
      final bytes = await ApiService.instance.downloadSummaryReport();
      final path = await saveBytesToFile(
        bytes: bytes,
        fileName: 'cybersentinel_report.pdf',
        extension: 'pdf',
      );
      if (mounted && path != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('PDF saved to $path')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))),
        );
      }
    } finally {
      if (mounted) setState(() => _downloadingPdf = false);
    }
  }

  Future<void> _exportCsv() async {
    if (!_reportReady && _summary == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Generate a report first, then export')),
      );
      return;
    }

    setState(() => _exportingCsv = true);
    try {
      final bytes = await ApiService.instance.downloadFirewallAlertsCsv();
      final path = await saveBytesToFile(
        bytes: bytes,
        fileName: 'cybersentinel_report.csv',
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
    } finally {
      if (mounted) setState(() => _exportingCsv = false);
    }
  }

  String get _dateRangeLabel {
    if (_generatedAt != null) {
      return 'Generated ${_formatGeneratedAt(_generatedAt!)}';
    }
    final now = DateTime.now();
    final start = now.subtract(const Duration(days: 6));
    return 'Weekly summary: ${_formatShortDate(start)} - ${_formatShortDate(now)}, ${now.year}';
  }

  @override
  Widget build(BuildContext context) {
    return SmoothDataView(
      loading: _loading,
      loadingWidget: const SingleChildScrollView(
        padding: EdgeInsets.all(32),
        child: Column(
          children: [
            ShimmerBox(height: 88, width: double.infinity, borderRadius: 10),
            SizedBox(height: 24),
            ShimmerBox(height: 104, width: double.infinity, borderRadius: 10),
            SizedBox(height: 24),
            ShimmerBox(height: 360, width: double.infinity, borderRadius: 10),
          ],
        ),
      ),
      child: _buildReports(),
    );
  }

  Widget _buildReports() {
    final s = _summary ?? {};
    final threats = (s['unacknowledged_alerts'] as num?)?.toInt() ?? 413;
    final blocked = (s['firewall_alerts'] as num?)?.toInt() ?? 364;
    final uniqueIps = (s['packet_events'] as num?)?.toInt() ?? 247;
    final successRate = (threats + blocked) > 0 ? ((blocked / (threats + blocked)) * 100).round() : 88;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(_pagePad),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          PageHeader(
            title: 'Security reports',
            subtitle: 'Export executive summaries and review detection metrics over time.',
            icon: Icons.description_outlined,
            badge: _reportReady ? 'Ready' : null,
          ),
          FadeSlideIn(
            child: CyberCard(
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Security Reports',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 20,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          _dateRangeLabel,
                          style: TextStyle(color: AppColors.textMuted, fontSize: 14),
                        ),
                      ],
                    ),
                  ),
                  ElevatedButton.icon(
                    onPressed: _generating ? null : _generateReport,
                    icon: _generating
                        ? SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: AppColors.textPrimary,
                            ),
                          )
                        : Icon(Icons.description_outlined, size: 16),
                    label: Text(
                      _generating ? 'Generating...' : 'Generate Report',
                      style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.border,
                      foregroundColor: AppColors.textPrimary,
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                        side: BorderSide(color: AppColors.borderElevated),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  OutlinedButton.icon(
                    onPressed: _exportingCsv ? null : _exportCsv,
                    icon: _exportingCsv
                        ? SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: AppColors.textPrimary,
                            ),
                          )
                        : Icon(Icons.table_chart_outlined, size: 16),
                    label: Text(
                      _exportingCsv ? 'Exporting...' : 'Export CSV',
                      style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
                    ),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppColors.textPrimary,
                      side: BorderSide(color: AppColors.borderElevated),
                      backgroundColor: AppColors.border,
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                  ),
                  const SizedBox(width: 12),
                  ElevatedButton.icon(
                    onPressed: _downloadingPdf ? null : _downloadPdf,
                    icon: _downloadingPdf
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                          )
                        : Icon(Icons.download_outlined, size: 16),
                    label: Text(
                      _downloadingPdf ? 'Exporting...' : 'Export PDF',
                      style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.cyan,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),
          SizedBox(
            height: _summaryCardHeight,
            child: Row(
              children: [
                Expanded(
                  child: FadeSlideIn(
                    child: _SummaryCard(
                      label: 'Total Threats',
                      value: threats,
                      trend: '+12%',
                      trendUp: true,
                      trendColor: AppColors.redLight,
                    ),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 80),
                    child: _SummaryCard(
                      label: 'Threats Blocked',
                      value: blocked,
                      trend: '+8%',
                      trendUp: true,
                      trendColor: AppColors.greenLight,
                    ),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 160),
                    child: _SummaryCard(
                      label: 'Success Rate',
                      value: successRate,
                      suffix: '%',
                      trend: '+3%',
                      trendUp: true,
                      trendColor: AppColors.greenLight,
                    ),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 240),
                    child: _SummaryCard(
                      label: 'Unique IPs',
                      value: uniqueIps,
                      trend: '-5%',
                      trendUp: false,
                      trendColor: AppColors.orangeLight,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          SizedBox(
            height: 380,
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 320),
                    child: _ThreatTrendChart(threats: threats, blocked: blocked),
                  ),
                ),
                const SizedBox(width: _gap),
                Expanded(
                  child: FadeSlideIn(
                    delay: const Duration(milliseconds: 400),
                    child: const _ThreatSourcePie(),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          FadeSlideIn(
            delay: const Duration(milliseconds: 480),
            child: SizedBox(height: 380, child: _AttackTypesBar(threats: threats)),
          ),
        ],
      ),
    );
  }
}

/// Figma summary card — compact: label on top, white value + colored trend on bottom row.
class _SummaryCard extends StatelessWidget {
  const _SummaryCard({
    required this.label,
    required this.value,
    required this.trend,
    required this.trendUp,
    required this.trendColor,
    this.suffix = '',
  });

  final String label;
  final int value;
  final String trend;
  final bool trendUp;
  final Color trendColor;
  final String suffix;

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(color: AppColors.textMuted, fontSize: 14, fontWeight: FontWeight.w400),
          ),
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Expanded(
                child: TweenAnimationBuilder<double>(
                  tween: Tween(begin: 0, end: value.toDouble()),
                  duration: const Duration(milliseconds: 900),
                  curve: Curves.easeOutCubic,
                  builder: (_, v, _) => Text(
                    '${v.round()}$suffix',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 30,
                      height: 1,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    trendUp ? Icons.trending_up : Icons.trending_down,
                    size: 16,
                    color: trendColor,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    trend,
                    style: TextStyle(color: trendColor, fontSize: 14, fontWeight: FontWeight.w500),
                  ),
                ],
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ThreatTrendChart extends StatelessWidget {
  const _ThreatTrendChart({required this.threats, required this.blocked});
  final int threats;
  final int blocked;

  static const _dates = ['Apr 06', 'Apr 07', 'Apr 08', 'Apr 09', 'Apr 10', 'Apr 11', 'Apr 12'];
  static const _threatTrend = [45.0, 52.0, 38.0, 67.0, 72.0, 58.0, 81.0];
  static const _blockedTrend = [38.0, 45.0, 35.0, 58.0, 65.0, 52.0, 71.0];

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Threat Trends',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 24),
          Expanded(
            child: LineChart(
              duration: const Duration(milliseconds: 800),
              LineChartData(
                minY: 0,
                gridData: FlGridData(
                  show: true,
                  drawVerticalLine: false,
                  getDrawingHorizontalLine: (_) => FlLine(color: AppColors.border, dashArray: [3, 3]),
                ),
                titlesData: FlTitlesData(
                  leftTitles: AxisTitles(
                    sideTitles: SideTitles(
                      showTitles: true,
                      reservedSize: 28,
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
                      getTitlesWidget: (v, _) {
                        final i = v.toInt();
                        if (i < 0 || i >= _dates.length) return const SizedBox.shrink();
                        return Padding(
                          padding: const EdgeInsets.only(top: 6),
                          child: Text(_dates[i], style: TextStyle(color: AppColors.textDim, fontSize: 11)),
                        );
                      },
                    ),
                  ),
                ),
                borderData: FlBorderData(show: false),
                lineBarsData: [
                  LineChartBarData(
                    spots: List.generate(7, (i) => FlSpot(i.toDouble(), _threatTrend[i])),
                    isCurved: true,
                    color: AppColors.red,
                    barWidth: 2,
                    dotData: const FlDotData(show: true),
                  ),
                  LineChartBarData(
                    spots: List.generate(7, (i) => FlSpot(i.toDouble(), _blockedTrend[i])),
                    isCurved: true,
                    color: AppColors.green,
                    barWidth: 2,
                    dotData: const FlDotData(show: true),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              _LegendDot(color: AppColors.red, label: 'Threats Detected'),
              const SizedBox(width: 16),
              _LegendDot(color: AppColors.green, label: 'Threats Blocked'),
            ],
          ),
        ],
      ),
    );
  }
}

class _ThreatSourcePie extends StatelessWidget {
  const _ThreatSourcePie();

  static const _data = [
    ('Asia', 45.0, AppColors.red),
    ('Europe', 30.0, AppColors.amber),
    ('Americas', 15.0, AppColors.green),
    ('Other', 10.0, AppColors.grey),
  ];

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Threat Source Distribution',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 24),
          Expanded(
            child: TweenAnimationBuilder<double>(
              tween: Tween(begin: 0, end: 1),
              duration: const Duration(milliseconds: 800),
              curve: Curves.easeOutCubic,
              builder: (_, anim, _) {
                return PieChart(
                  PieChartData(
                    sectionsSpace: 2,
                    centerSpaceRadius: 0,
                    sections: _data
                        .map(
                          (d) => PieChartSectionData(
                            value: d.$2 * anim,
                            color: d.$3,
                            radius: 100,
                            title: '${d.$1} ${d.$2.round()}%',
                            titleStyle: TextStyle(color: AppColors.textPrimary, fontSize: 11),
                          ),
                        )
                        .toList(),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

class _AttackTypesBar extends StatelessWidget {
  const _AttackTypesBar({required this.threats});
  final int threats;

  static const _types = ['DDoS', 'Malware', 'SQL Injection', 'Brute Force', 'Phishing'];
  static const _counts = [342.0, 289.0, 234.0, 187.0, 156.0];

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Top Attack Types',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 24),
          Expanded(
            child: BarChart(
              duration: const Duration(milliseconds: 800),
              BarChartData(
                alignment: BarChartAlignment.spaceAround,
                maxY: 400,
                gridData: FlGridData(
                  show: true,
                  drawVerticalLine: false,
                  getDrawingHorizontalLine: (_) => FlLine(color: AppColors.border, dashArray: [3, 3]),
                ),
                titlesData: FlTitlesData(
                  leftTitles: AxisTitles(
                    sideTitles: SideTitles(
                      showTitles: true,
                      reservedSize: 32,
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
                      reservedSize: 32,
                      getTitlesWidget: (v, _) {
                        final i = v.toInt();
                        if (i < 0 || i >= _types.length) return const SizedBox.shrink();
                        return Padding(
                          padding: const EdgeInsets.only(top: 8),
                          child: Text(_types[i], style: TextStyle(color: AppColors.textDim, fontSize: 11)),
                        );
                      },
                    ),
                  ),
                ),
                borderData: FlBorderData(show: false),
                barGroups: List.generate(
                  _counts.length,
                  (i) => BarChartGroupData(
                    x: i,
                    barRods: [
                      BarChartRodData(
                        toY: _counts[i],
                        color: AppColors.cyan,
                        width: 32,
                        borderRadius: const BorderRadius.vertical(top: Radius.circular(4)),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
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
        const SizedBox(width: 6),
        Text(label, style: TextStyle(color: AppColors.textMuted, fontSize: 12, fontWeight: FontWeight.w500)),
      ],
    );
  }
}

class ReportsPage extends StatelessWidget {
  const ReportsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bg,
      body: const ReportsContent(),
    );
  }
}
