import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:flutter/material.dart';

void showNotImplemented(BuildContext context) {
  Navigator.of(
    context,
  ).push(MaterialPageRoute(builder: (_) => const NotImplementedPage()));
}

class DashboardLayout extends StatelessWidget {
  const DashboardLayout({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SidebarPanel(
              onNavigateNotImplemented: () => showNotImplemented(context),
              onNavigateDashboard: () {
                Navigator.of(context).pushAndRemoveUntil(
                  MaterialPageRoute(builder: (_) => const DashboardScreen()),
                  (route) => false,
                );
              },
            ),
            Expanded(child: child),
          ],
        ),
      ),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  late ScrollController _horizontalController;
  late ScrollController _verticalController;

  @override
  void initState() {
    super.initState();
    _horizontalController = ScrollController();
    _verticalController = ScrollController();
  }

  @override
  void dispose() {
    _horizontalController.dispose();
    _verticalController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return DashboardLayout(
      child: LayoutBuilder(
        builder: (context, constraints) {
          final desktopBodyWidth = constraints.maxWidth < 960
              ? 960.0
              : constraints.maxWidth;

          return Scrollbar(
            controller: _horizontalController,
            thumbVisibility: true,
            child: SingleChildScrollView(
              controller: _horizontalController,
              scrollDirection: Axis.horizontal,
              child: SizedBox(
                width: desktopBodyWidth,
                child: _DashboardBody(verticalController: _verticalController),
              ),
            ),
          );
        },
      ),
    );
  }
}

class _DashboardBody extends StatefulWidget {
  const _DashboardBody({required this.verticalController});

  final ScrollController verticalController;

  @override
  State<_DashboardBody> createState() => _DashboardBodyState();
}

class _DashboardBodyState extends State<_DashboardBody> {
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Container(
          height: 64,
          padding: const EdgeInsets.symmetric(horizontal: 32),
          decoration: const BoxDecoration(
            color: Color(0xFF0F1420),
            border: Border(
              bottom: BorderSide(color: Color(0xFF1A1F2E), width: 1),
            ),
          ),
          child: Row(
            children: [
              const Text(
                'Dashboard',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 24,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const Spacer(),
              Row(
                children: [
                  Container(
                    width: 340,
                    height: 44,
                    decoration: BoxDecoration(
                      color: const Color(0xFF1A1F2E),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: const Color(0xFF2A2F3E)),
                    ),
                    padding: const EdgeInsets.symmetric(horizontal: 12),
                    child: const Row(
                      children: [
                        Icon(Icons.search, color: Color(0xFF6B7280), size: 18),
                        SizedBox(width: 8),
                        Expanded(
                          child: TextField(
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 15,
                              fontWeight: FontWeight.w500,
                            ),
                            cursorColor: Color(0xFF22D3EE),
                            decoration: InputDecoration(
                              hintText: 'Global search...',
                              hintStyle: TextStyle(
                                color: Color(0xFF6B7280),
                                fontSize: 15,
                                fontWeight: FontWeight.w500,
                              ),
                              border: InputBorder.none,
                              isDense: true,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 2),
                  _ActionButton(
                    onTap: () => showNotImplemented(context),
                    child: const SizedBox(
                      width: 48,
                      height: 48,
                      child: Stack(
                        children: [
                          Center(
                            child: Icon(
                              Icons.notifications_none,
                              color: Color(0xFF9CA3AF),
                              size: 24,
                            ),
                          ),
                          Positioned(
                            right: 9,
                            top: 9,
                            child: Icon(
                              Icons.circle,
                              color: Color(0xFFEF4444),
                              size: 10,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  _ActionButton(
                    onTap: () => showNotImplemented(context),
                    child: const SizedBox(
                      width: 48,
                      height: 48,
                      child: Center(
                        child: DecoratedBox(
                          decoration: BoxDecoration(
                            color: Color(0x3300D3FF),
                            shape: BoxShape.circle,
                          ),
                          child: SizedBox(
                            width: 38,
                            height: 38,
                            child: Icon(
                              Icons.person_outline,
                              color: Color(0xFF22D3EE),
                              size: 22,
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        Expanded(
          child: Scrollbar(
            controller: widget.verticalController,
            thumbVisibility: true,
            child: SingleChildScrollView(
              controller: widget.verticalController,
              padding: const EdgeInsets.all(20),
              child: Container(
                margin: const EdgeInsets.fromLTRB(10, 12, 10, 12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    SizedBox(
                      height: 225,
                      child: Row(
                        children: [
                          const Expanded(
                            child: _HoverableCard(child: _ThreatScoreCard()),
                          ),
                          const SizedBox(width: 12),
                          const Expanded(
                            child: _HoverableCard(
                              child: _KpiCard(
                                icon: Icons.warning_amber_rounded,
                                iconColor: Color(0xFFEF4444),
                                iconBackground: Color(0x22EF4444),
                                value: '23',
                                label: 'Active Threats',
                                delta: '+5',
                                deltaColor: Color(0xFFF87171),
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          const Expanded(
                            child: _HoverableCard(
                              child: _KpiCard(
                                icon: Icons.show_chart_rounded,
                                iconColor: Color(0xFF3B82F6),
                                iconBackground: Color(0x223B82F6),
                                value: '2.4M',
                                label: 'Packets Analyzed',
                                delta: '+12.5%',
                                deltaColor: Color(0xFF98A2B3),
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          const Expanded(
                            child: _HoverableCard(
                              child: _KpiCard(
                                icon: Icons.language,
                                iconColor: Color(0xFFF59E0B),
                                iconBackground: Color(0x22F59E0B),
                                value: '156',
                                label: 'Suspicious IPs',
                                delta: '-8',
                                deltaColor: Color(0xFF34D399),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 12),
                    Padding(
                      padding: const EdgeInsets.only(top: 10, bottom: 6),
                      child: SizedBox(
                        height: 430,
                        child: Row(
                          children: [
                            Expanded(
                              flex: 2,
                              child: _HoverableCard(child: _TrafficCard()),
                            ),
                            SizedBox(width: 12),
                            Expanded(
                              child: _HoverableCard(child: _AlertsCard()),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    const SizedBox(
                      height: 430,
                      child: Row(
                        children: [
                          Expanded(
                            child: _HoverableCard(
                              child: _PacketClassificationCard(),
                            ),
                          ),
                          SizedBox(width: 12),
                          Expanded(
                            flex: 2,
                            child: _HoverableCard(
                              child: _MaliciousIPsTableCard(),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _HoverableCard extends StatefulWidget {
  const _HoverableCard({required this.child});

  final Widget child;

  @override
  State<_HoverableCard> createState() => _HoverableCardState();
}

class _HoverableCardState extends State<_HoverableCard> {
  bool _isHovering = false;

  @override
  Widget build(BuildContext context) {
    return MouseRegion(
      onEnter: (_) => setState(() => _isHovering = true),
      onExit: (_) => setState(() => _isHovering = false),
      child: Container(
        decoration: _isHovering
            ? BoxDecoration(
                border: Border.all(color: const Color(0xFF22D3EE), width: 0.6),
                borderRadius: BorderRadius.circular(12),
              )
            : null,
        child: widget.child,
      ),
    );
  }
}

class _CardShell extends StatelessWidget {
  const _CardShell({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF0F1420),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF1A1F2E)),
      ),
      child: child,
    );
  }
}

class _ThreatScoreCard extends StatelessWidget {
  const _ThreatScoreCard();

  @override
  Widget build(BuildContext context) {
    return const _CardShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              _IconPill(
                icon: Icons.shield_outlined,
                color: Color(0xFF10B981),
                background: Color(0x2210B981),
              ),
              Text(
                'RISK LEVEL',
                style: TextStyle(
                  color: Color(0xFF667085),
                  fontSize: 11,
                  letterSpacing: 1.2,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
          SizedBox(height: 18),
          Text(
            '0%',
            style: TextStyle(
              color: Colors.white,
              fontSize: 34,
              height: 1,
              fontWeight: FontWeight.w700,
            ),
          ),
          SizedBox(height: 6),
          Text(
            'Threat Score',
            style: TextStyle(
              color: Color(0xFF98A2B3),
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
          SizedBox(height: 16),
          ClipRRect(
            borderRadius: BorderRadius.all(Radius.circular(20)),
            child: LinearProgressIndicator(
              value: 0,
              minHeight: 8,
              backgroundColor: Color(0xFF1A1F2E),
              valueColor: AlwaysStoppedAnimation(Color(0xFF10B981)),
            ),
          ),
          SizedBox(height: 12),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Critical',
                style: TextStyle(
                  color: Color(0xFF667085),
                  fontSize: 11,
                  fontWeight: FontWeight.w500,
                ),
              ),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  'High Risk Detected',
                  textAlign: TextAlign.right,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: Color(0xFF00E68A),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
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
    required this.iconBackground,
    required this.value,
    required this.label,
    required this.delta,
    required this.deltaColor,
  });

  final IconData icon;
  final Color iconColor;
  final Color iconBackground;
  final String value;
  final String label;
  final String delta;
  final Color deltaColor;

  @override
  Widget build(BuildContext context) {
    return _CardShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _IconPill(icon: icon, color: iconColor, background: iconBackground),
          const SizedBox(height: 30),
          Text(
            value,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 34,
              height: 1,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            label,
            style: const TextStyle(
              color: Color(0xFF98A2B3),
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 6),
          RichText(
            text: TextSpan(
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
              children: [
                TextSpan(
                  text: delta,
                  style: TextStyle(color: deltaColor),
                ),
                const TextSpan(
                  text: ' last hour',
                  style: TextStyle(color: Color(0xFF667085)),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _IconPill extends StatelessWidget {
  const _IconPill({
    required this.icon,
    required this.color,
    required this.background,
  });

  final IconData icon;
  final Color color;
  final Color background;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 48,
      height: 48,
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Icon(icon, color: color, size: 24),
    );
  }
}

class _TrafficCard extends StatelessWidget {
  const _TrafficCard();

  @override
  Widget build(BuildContext context) {
    return _CardShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Wrap(
            spacing: 12,
            runSpacing: 10,
            alignment: WrapAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Real-Time Network Traffic',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    'Packets per 5-minute interval',
                    style: TextStyle(
                      color: Color(0xFF98A2B3),
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
              _ChartLegend(),
            ],
          ),
          const SizedBox(height: 16),
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                color: const Color(0xFF0B1120),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF1A1F2E)),
              ),
              child: const Padding(
                padding: EdgeInsets.all(12),
                child: CustomPaint(painter: _TrafficChartPainter()),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ChartLegend extends StatelessWidget {
  const _ChartLegend();

  @override
  Widget build(BuildContext context) {
    return const Wrap(
      spacing: 14,
      runSpacing: 6,
      children: [
        _LegendDot(color: Color(0xFF10B981), label: 'Normal'),
        _LegendDot(color: Color(0xFFF59E0B), label: 'Suspicious'),
        _LegendDot(color: Color(0xFFEF4444), label: 'Malicious'),
      ],
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
      children: [
        Container(
          width: 10,
          height: 10,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 7),
        Text(
          label,
          style: const TextStyle(
            color: Color(0xFF98A2B3),
            fontSize: 12,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }
}

class _AlertsCard extends StatelessWidget {
  const _AlertsCard();

  @override
  Widget build(BuildContext context) {
    const alerts = [
      ('DDoS Attack', '192.168.1.45', '2m ago', 'critical', Color(0xFFEF4444)),
      ('Port Scan', '10.0.0.234', '5m ago', 'high', Color(0xFFF59E0B)),
      ('SQL Injection', '172.16.0.88', '8m ago', 'critical', Color(0xFFEF4444)),
      (
        'Malware Detected',
        '192.168.0.156',
        '12m ago',
        'high',
        Color(0xFFF59E0B),
      ),
    ];

    return _CardShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Active Alerts',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    'Recent security events',
                    style: TextStyle(
                      color: Color(0xFF98A2B3),
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
              _RedBadge(label: '6 active'),
            ],
          ),
          const SizedBox(height: 12),
          Expanded(
            child: ListView.separated(
              itemCount: alerts.length,
              separatorBuilder: (_, _) => const SizedBox(height: 10),
              itemBuilder: (context, index) {
                final item = alerts[index];
                final levelColor = item.$5;
                return Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1A1F2E),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: const Color(0xFF2A2F3E)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            Icons.warning_amber_rounded,
                            color: levelColor,
                            size: 16,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              item.$1,
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 15,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: levelColor.withOpacity(0.12),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: levelColor.withOpacity(0.3),
                              ),
                            ),
                            child: Text(
                              item.$4,
                              style: TextStyle(
                                color: levelColor,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 6),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            item.$2,
                            style: const TextStyle(
                              color: Color(0xFF98A2B3),
                              fontSize: 13,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                          Text(
                            item.$3,
                            style: const TextStyle(
                              color: Color(0xFF667085),
                              fontSize: 13,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ],
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

class _RedBadge extends StatelessWidget {
  const _RedBadge({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: const Color(0x22EF4444),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: const Color(0x33EF4444)),
      ),
      child: Text(
        label,
        style: const TextStyle(
          color: Color(0xFFF87171),
          fontSize: 12,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

class _PacketClassificationCard extends StatelessWidget {
  const _PacketClassificationCard();

  @override
  Widget build(BuildContext context) {
    const items = [
      ('HTTP/HTTPS', '45%', Color(0xFF06B6D4)),
      ('SSH', '20%', Color(0xFF10B981)),
      ('FTP', '15%', Color(0xFFF59E0B)),
      ('DNS', '12%', Color(0xFF8B5CF6)),
      ('Other', '8%', Color(0xFF6B7280)),
    ];

    return _CardShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Packet Classification',
            style: TextStyle(
              color: Colors.white,
              fontSize: 18,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 4),
          const Text(
            'By protocol type',
            style: TextStyle(
              color: Color(0xFF98A2B3),
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 12),
          const Expanded(
            child: Center(
              child: AspectRatio(
                aspectRatio: 1,
                child: CustomPaint(painter: _DonutPainter()),
              ),
            ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 14,
            runSpacing: 8,
            children: items
                .map(
                  (item) => Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: item.$3,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        '${item.$1} ${item.$2}',
                        style: const TextStyle(
                          color: Color(0xFFB7C0CF),
                          fontSize: 12,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                )
                .toList(),
          ),
        ],
      ),
    );
  }
}

class _MaliciousIPsTableCard extends StatelessWidget {
  const _MaliciousIPsTableCard();

  @override
  Widget build(BuildContext context) {
    const rows = [
      ('185.220.101.45', 'RU', '342', 'CRITICAL', Color(0xFFEF4444)),
      ('103.56.207.23', 'CN', '289', 'CRITICAL', Color(0xFFEF4444)),
      ('45.142.120.67', 'NL', '234', 'HIGH', Color(0xFFF59E0B)),
      ('193.164.132.88', 'DE', '187', 'HIGH', Color(0xFFF59E0B)),
    ];

    return _CardShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Top Malicious IPs',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    'Most frequent threat sources',
                    style: TextStyle(
                      color: Color(0xFF98A2B3),
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
              Text(
                'View All',
                style: TextStyle(
                  color: Color(0xFF00D3FF),
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          const Divider(color: Color(0xFF1A1F2E), height: 1),
          const SizedBox(height: 8),
          const Row(
            children: [
              Expanded(
                flex: 3,
                child: Text(
                  'IP ADDRESS',
                  style: TextStyle(
                    color: Color(0xFF667085),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'COUNTRY',
                  style: TextStyle(
                    color: Color(0xFF667085),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'ATTEMPTS',
                  textAlign: TextAlign.right,
                  style: TextStyle(
                    color: Color(0xFF667085),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'RISK LEVEL',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Color(0xFF667085),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Expanded(
            child: ListView.separated(
              itemCount: rows.length,
              separatorBuilder: (_, _) =>
                  const Divider(color: Color(0xFF1A1F2E), height: 1),
              itemBuilder: (context, index) {
                final row = rows[index];
                final levelColor = row.$5;
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Row(
                    children: [
                      Expanded(
                        flex: 3,
                        child: Text(
                          row.$1,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 15,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                      Expanded(
                        flex: 2,
                        child: Text(
                          row.$2,
                          style: const TextStyle(
                            color: Color(0xFFB7C0CF),
                            fontSize: 14,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ),
                      Expanded(
                        flex: 2,
                        child: Text(
                          row.$3,
                          textAlign: TextAlign.right,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                      Expanded(
                        flex: 2,
                        child: Align(
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 3,
                            ),
                            decoration: BoxDecoration(
                              color: levelColor.withOpacity(0.12),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: levelColor.withOpacity(0.3),
                              ),
                            ),
                            child: Text(
                              row.$4,
                              style: TextStyle(
                                color: levelColor,
                                fontSize: 11,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ],
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

class _ActionButton extends StatelessWidget {
  const _ActionButton({required this.onTap, required this.child});

  final VoidCallback onTap;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        mouseCursor: SystemMouseCursors.click,
        borderRadius: BorderRadius.circular(12),
        child: child,
      ),
    );
  }
}

class _TrafficChartPainter extends CustomPainter {
  const _TrafficChartPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final gridPaint = Paint()
      ..color = const Color(0xFF1A1F2E)
      ..strokeWidth = 1;

    for (var i = 0; i <= 5; i++) {
      final dy = size.height * i / 5;
      canvas.drawLine(Offset(0, dy), Offset(size.width, dy), gridPaint);
    }

    for (var i = 0; i <= 9; i++) {
      final dx = size.width * i / 9;
      canvas.drawLine(Offset(dx, 0), Offset(dx, size.height), gridPaint);
    }

    _drawSeries(canvas, size, const Color(0xFF10B981), const [
      0.22,
      0.34,
      0.27,
      0.6,
      0.42,
      0.52,
      0.3,
      0.46,
      0.24,
      0.36,
      0.22,
    ]);
    _drawSeries(canvas, size, const Color(0xFFF59E0B), const [
      0.92,
      0.88,
      0.9,
      0.86,
      0.89,
      0.84,
      0.9,
      0.88,
      0.87,
      0.85,
      0.86,
    ]);
    _drawSeries(canvas, size, const Color(0xFFEF4444), const [
      0.97,
      0.96,
      0.95,
      0.96,
      0.95,
      0.97,
      0.95,
      0.96,
      0.94,
      0.95,
      0.94,
    ]);
  }

  void _drawSeries(Canvas canvas, Size size, Color color, List<double> points) {
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..color = color
      ..strokeWidth = 2.3;

    final path = Path();
    for (var i = 0; i < points.length; i++) {
      final x = size.width * i / (points.length - 1);
      final y = size.height * points[i];
      if (i == 0) {
        path.moveTo(x, y);
      } else {
        path.lineTo(x, y);
      }
    }
    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class _DonutPainter extends CustomPainter {
  const _DonutPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width * 0.34;
    const stroke = 22.0;

    final segments = [
      (0.45, const Color(0xFF06B6D4)),
      (0.20, const Color(0xFF10B981)),
      (0.15, const Color(0xFFF59E0B)),
      (0.12, const Color(0xFF8B5CF6)),
      (0.08, const Color(0xFF6B7280)),
    ];

    var start = -1.5708;
    for (final segment in segments) {
      final sweep = 6.28318 * segment.$1;
      final paint = Paint()
        ..style = PaintingStyle.stroke
        ..strokeCap = StrokeCap.butt
        ..strokeWidth = stroke
        ..color = segment.$2;

      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        start,
        sweep - 0.04,
        false,
        paint,
      );
      start += sweep;
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class NotImplementedPage extends StatelessWidget {
  const NotImplementedPage({super.key});

  @override
  Widget build(BuildContext context) {
    return DashboardLayout(
      child: Container(
        decoration: const BoxDecoration(color: Color(0xFF0A0E1A)),
        child: const Center(
          child: Text(
            'This is not implemented yet',
            style: TextStyle(
              color: Colors.white,
              fontSize: 24,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ),
    );
  }
}
