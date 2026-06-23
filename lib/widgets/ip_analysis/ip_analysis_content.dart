import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/services/ip_intel_parser.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/widgets/shared/animated_widgets.dart';
import 'package:cybersentinel/widgets/shared/cyber_card.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class IPAnalysisPageContent extends StatefulWidget {
  const IPAnalysisPageContent({super.key});

  @override
  State<IPAnalysisPageContent> createState() => _IPAnalysisPageContentState();
}

class _IPAnalysisPageContentState extends State<IPAnalysisPageContent> {
  final _ipController = TextEditingController();
  Map<String, dynamic>? _threat;
  IpGeoIntel? _geoIntel;
  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _ipController.dispose();
    super.dispose();
  }

  Future<void> _analyze() async {
    final ip = _ipController.text.trim();
    if (ip.isEmpty) return;

    if (!ApiConfig.isConfigured) {
      setState(() => _error = 'Set your API key in Settings');
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
      _threat = null;
      _geoIntel = null;
    });

    try {
      final threat = await ApiService.instance.getThreatScore(ip);
      IpGeoIntel? geo;

      try {
        final intel = await ApiService.instance.getFirewallIntel(ip);
        geo = IpGeoIntel.fromResponse(intel);
      } catch (_) {}

      geo ??= IpGeoIntel.fromResponse(threat);

      if (!mounted) return;
      setState(() {
        _threat = threat;
        _geoIntel = geo;
        _loading = false;
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
    return SingleChildScrollView(
      padding: const EdgeInsets.all(32),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1152),
          child: Column(
            children: [
              FadeSlideIn(
                child: CyberCard(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _ipController,
                          style: const TextStyle(color: AppColors.textPrimary, fontSize: 16),
                          cursorColor: AppColors.cyanLight,
                          decoration: InputDecoration(
                            prefixIcon: const Icon(Icons.search, color: AppColors.textMuted),
                            hintText: 'Enter IP address (e.g. 185.220.101.45)',
                            hintStyle: const TextStyle(color: AppColors.textDim),
                            filled: true,
                            fillColor: AppColors.border,
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: BorderSide.none,
                            ),
                            focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: BorderSide(color: AppColors.cyan.withValues(alpha: 0.5)),
                            ),
                          ),
                          onSubmitted: (_) => _analyze(),
                        ),
                      ),
                      const SizedBox(width: 16),
                      ElevatedButton(
                        onPressed: _loading ? null : _analyze,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.cyan,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 18),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                        child: _loading
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                              )
                            : const Text('Analyze', style: TextStyle(fontWeight: FontWeight.w600)),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 32),
              AnimatedSwitcher(
                duration: const Duration(milliseconds: 450),
                switchInCurve: Curves.easeOutCubic,
                child: _buildResults(),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildResults() {
    if (_error != null) {
      return FadeSlideIn(
        key: const ValueKey('error'),
        child: Text(_error!, style: const TextStyle(color: AppColors.redLight)),
      );
    }

    if (_threat == null) {
      return FadeSlideIn(
        key: const ValueKey('empty'),
        child: CyberCard(
          child: Column(
            children: [
              Icon(Icons.search, size: 64, color: AppColors.textDim.withValues(alpha: 0.5)),
              const SizedBox(height: 24),
              const Text(
                'No IP Analyzed Yet',
                style: TextStyle(color: AppColors.textPrimary, fontSize: 24, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 12),
              const Text(
                'Enter an IP address above to view threat intelligence',
                style: TextStyle(color: AppColors.textMuted, fontSize: 16),
              ),
            ],
          ),
        ),
      );
    }

    final severity = _threat!['severity']?.toString() ?? 'medium';
    final color = severityColor(severity);
    final score = (_threat!['final_score'] as num?)?.toDouble() ?? 0;
    final geo = _geoIntel;
    final location = geo?.locationLabel ?? 'Unknown';
    final isp = geo?.isp ?? 'Unknown ISP';
    final country = geo?.countryLabel ?? '--';
    final countrySubtitle = geo != null && geo.countryName.isNotEmpty
        ? '${geo.countryCode.isNotEmpty ? geo.countryCode : geo.countryName}'
        : country;

    return Column(
      key: const ValueKey('results'),
      children: [
        LayoutBuilder(
          builder: (context, c) {
            final cols = c.maxWidth > 768 ? 3 : 1;
            return GridView.count(
              crossAxisCount: cols,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              mainAxisSpacing: 16,
              crossAxisSpacing: 16,
              childAspectRatio: cols == 1 ? 2.5 : 1.8,
              children: [
                FadeSlideIn(
                  delay: const Duration(milliseconds: 0),
                  child: _InfoCard(
                    icon: Icons.location_on,
                    iconColor: AppColors.blue,
                    title: location,
                    subtitle: countrySubtitle,
                    label: 'Location (GeoIP)',
                  ),
                ),
                FadeSlideIn(
                  delay: const Duration(milliseconds: 80),
                  child: _InfoCard(
                    icon: Icons.language,
                    iconColor: AppColors.purple,
                    title: isp,
                    subtitle: geo?.asn.isNotEmpty == true ? 'ASN ${geo!.asn}' : 'Internet Service Provider',
                    label: 'ISP',
                  ),
                ),
                FadeSlideIn(
                  delay: const Duration(milliseconds: 160),
                  child: _ReputationCard(
                    score: score,
                    color: color,
                    abuseConfidence: geo?.abuseConfidence,
                    totalReports: geo?.totalReports,
                  ),
                ),
              ],
            );
          },
        ),
        const SizedBox(height: 24),
        LayoutBuilder(
          builder: (context, c) {
            if (c.maxWidth < 900) {
              return Column(
                children: [
                  FadeSlideIn(
                    delay: const Duration(milliseconds: 240),
                    child: _MapPlaceholder(ip: _threat!['ip']?.toString() ?? '', geo: geo),
                  ),
                  const SizedBox(height: 16),
                  FadeSlideIn(
                    delay: const Duration(milliseconds: 320),
                    child: _IpDetails(threat: _threat!, severity: severity, color: color, geo: geo),
                  ),
                ],
              );
            }
            return SizedBox(
              height: 320,
              child: Row(
                children: [
                  Expanded(
                    child: FadeSlideIn(
                      delay: const Duration(milliseconds: 240),
                      child: _MapPlaceholder(ip: _threat!['ip']?.toString() ?? '', geo: geo),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: FadeSlideIn(
                      delay: const Duration(milliseconds: 320),
                      child: _IpDetails(threat: _threat!, severity: severity, color: color, geo: geo),
                    ),
                  ),
                ],
              ),
            );
          },
        ),
        const SizedBox(height: 24),
        FadeSlideIn(
          delay: const Duration(milliseconds: 400),
          child: _ActivityChart(scores: [
            (_threat!['packet_score'] as num?)?.toDouble() ?? 0,
            (_threat!['anomaly_score'] as num?)?.toDouble() ?? 0,
            (_threat!['intel_score'] as num?)?.toDouble() ?? 0,
            score,
            score * 0.8,
            score * 0.6,
          ]),
        ),
      ],
    );
  }
}

class _InfoCard extends StatelessWidget {
  const _InfoCard({
    required this.icon,
    required this.iconColor,
    required this.title,
    required this.subtitle,
    required this.label,
  });

  final IconData icon;
  final Color iconColor;
  final String title;
  final String subtitle;
  final String label;

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: iconColor.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: iconColor, size: 24),
          ),
          const Spacer(),
          Text(title, style: const TextStyle(color: AppColors.textPrimary, fontSize: 22, fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
          Text(subtitle, style: const TextStyle(color: AppColors.textMuted, fontSize: 13)),
          const SizedBox(height: 4),
          Text(label, style: const TextStyle(color: AppColors.textDim, fontSize: 12)),
        ],
      ),
    );
  }
}

class _ReputationCard extends StatelessWidget {
  const _ReputationCard({
    required this.score,
    required this.color,
    this.abuseConfidence,
    this.totalReports,
  });
  final double score;
  final Color color;
  final int? abuseConfidence;
  final int? totalReports;

  @override
  Widget build(BuildContext context) {
    final barColor = score >= 70 ? AppColors.green : score >= 40 ? AppColors.amber : AppColors.red;
    final abuseLabel = abuseConfidence != null
        ? 'AbuseIPDB: $abuseConfidence% · $totalReports reports'
        : 'Threat score';

    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: AppColors.red.withValues(alpha: 0.1), borderRadius: BorderRadius.circular(8)),
            child: const Icon(Icons.shield, color: AppColors.red, size: 24),
          ),
          const Spacer(),
          AnimatedCounter(
            value: score.round(),
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 22, fontWeight: FontWeight.bold),
          ),
          Text('/100 · $abuseLabel', style: const TextStyle(color: AppColors.textMuted, fontSize: 13), maxLines: 2, overflow: TextOverflow.ellipsis),
          const SizedBox(height: 12),
          AnimatedProgressBar(value: score / 100, color: barColor),
        ],
      ),
    );
  }
}

class _MapPlaceholder extends StatelessWidget {
  const _MapPlaceholder({required this.ip, this.geo});
  final String ip;
  final IpGeoIntel? geo;

  @override
  Widget build(BuildContext context) {
    final coords = geo?.hasCoordinates == true
        ? '${geo!.latitude!.toStringAsFixed(2)}, ${geo!.longitude!.toStringAsFixed(2)}'
        : null;

    return CyberCard(
      child: AspectRatio(
        aspectRatio: 16 / 9,
        child: Stack(
          alignment: Alignment.center,
          children: [
            Container(
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(8),
                gradient: LinearGradient(
                  colors: [
                    AppColors.cyan.withValues(alpha: 0.05),
                    AppColors.blue.withValues(alpha: 0.05),
                  ],
                ),
              ),
            ),
            const SizedBox(width: 128, height: 128, child: PulsingDot(color: AppColors.cyan, size: 12)),
            Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.location_on, color: AppColors.cyanLight, size: 48),
                const SizedBox(height: 8),
                Text(ip, style: GoogleFonts.jetBrainsMono(color: AppColors.textPrimary, fontSize: 16)),
                if (geo != null && geo!.locationLabel != 'Unknown') ...[
                  const SizedBox(height: 4),
                  Text(
                    geo!.locationLabel,
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 14),
                    textAlign: TextAlign.center,
                  ),
                ],
                if (coords != null) ...[
                  const SizedBox(height: 4),
                  Text(
                    coords,
                    style: GoogleFonts.jetBrainsMono(color: AppColors.textDim, fontSize: 12),
                  ),
                ],
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _IpDetails extends StatelessWidget {
  const _IpDetails({
    required this.threat,
    required this.severity,
    required this.color,
    this.geo,
  });
  final Map<String, dynamic> threat;
  final String severity;
  final Color color;
  final IpGeoIntel? geo;

  String _providerLabel(String key) {
    final status = geo?.providerStatus[key]?.toLowerCase() ?? '';
    if (status.isEmpty) return '—';
    return status == 'ok' ? 'Connected' : status;
  }

  @override
  Widget build(BuildContext context) {
    final rows = <(String, String)>[
      ('IP Address', threat['ip']?.toString() ?? '-'),
      if (geo != null) ('Country', '${geo!.countryName} (${geo!.countryCode})'),
      if (geo != null && geo!.city.isNotEmpty) ('City', geo!.city),
      if (geo != null) ('ISP', geo!.isp),
      if (geo != null) ('Abuse Confidence', '${geo!.abuseConfidence}%'),
      if (geo != null) ('Abuse Reports', geo!.totalReports.toString()),
      if (geo != null) ('Whitelisted', geo!.isWhitelisted ? 'Yes' : 'No'),
      ('Threat Level', severity.toUpperCase()),
      ('Block Recommended', threat['block_recommended'] == true ? 'Yes' : 'No'),
      ('Reason', threat['reason']?.toString() ?? '-'),
    ];

    return CyberCard(
      child: LayoutBuilder(
        builder: (context, constraints) {
          final rowWidgets = rows.map(
            (r) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppColors.border,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(r.$1, style: const TextStyle(color: AppColors.textMuted, fontSize: 13)),
                    if (r.$1 == 'Threat Level')
                      CyberBadge(label: severity, color: color)
                    else
                      Flexible(
                        child: Text(
                          r.$2,
                          textAlign: TextAlign.right,
                          style: GoogleFonts.jetBrainsMono(color: AppColors.textPrimary, fontSize: 13),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                  ],
                ),
              ),
            ),
          ).toList();

          final header = Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'IP Information',
                style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
              ),
              if (geo != null && geo!.providerStatus.isNotEmpty) ...[
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    if (geo!.providerStatus.containsKey('geoip'))
                      CyberBadge(label: 'GeoIP: ${_providerLabel('geoip')}', color: AppColors.blue),
                    if (geo!.providerStatus.containsKey('abuseipdb'))
                      CyberBadge(label: 'AbuseIPDB: ${_providerLabel('abuseipdb')}', color: AppColors.purple),
                  ],
                ),
              ],
            ],
          );

          if (constraints.hasBoundedHeight) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                header,
                const SizedBox(height: 16),
                Expanded(
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: rowWidgets,
                    ),
                  ),
                ),
              ],
            );
          }

          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              header,
              const SizedBox(height: 16),
              ...rowWidgets,
            ],
          );
        },
      ),
    );
  }
}

class _ActivityChart extends StatelessWidget {
  const _ActivityChart({required this.scores});
  final List<double> scores;

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Activity History', style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600)),
          const SizedBox(height: 16),
          SizedBox(
            height: 250,
            child: LineChart(
              duration: const Duration(milliseconds: 800),
              LineChartData(
                gridData: FlGridData(
                  show: true,
                  getDrawingHorizontalLine: (_) => const FlLine(color: AppColors.border, dashArray: [3, 3]),
                ),
                titlesData: const FlTitlesData(
                  leftTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                  rightTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                  topTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                  bottomTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                ),
                borderData: FlBorderData(show: false),
                lineBarsData: [
                  LineChartBarData(
                    spots: List.generate(scores.length, (i) => FlSpot(i.toDouble(), scores[i])),
                    isCurved: true,
                    color: AppColors.cyan,
                    barWidth: 2,
                    dotData: const FlDotData(show: true),
                  ),
                ],
                minY: 0,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
