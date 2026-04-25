import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:flutter/material.dart';

const List<Map<String, String>> firewallLogsData = [
  {
    'ip': '185.220.101.45',
    'port': '22',
    'action': 'blocked',
    'rule': 'SSH-BRUTE-FORCE',
    'time': '2026-04-12 14:23:45',
    'severity': 'high',
  },
  {
    'ip': '103.56.207.23',
    'port': '443',
    'action': 'allowed',
    'rule': 'HTTPS-ALLOW',
    'time': '2026-04-12 14:23:42',
    'severity': 'low',
  },
  {
    'ip': '45.142.120.67',
    'port': '3389',
    'action': 'blocked',
    'rule': 'RDP-BLOCK',
    'time': '2026-04-12 14:23:38',
    'severity': 'high',
  },
  {
    'ip': '193.164.132.88',
    'port': '80',
    'action': 'allowed',
    'rule': 'HTTP-ALLOW',
    'time': '2026-04-12 14:23:35',
    'severity': 'low',
  },
  {
    'ip': '91.234.55.13',
    'port': '53',
    'action': 'allowed',
    'rule': 'DNS-ALLOW',
    'time': '2026-04-12 14:23:31',
    'severity': 'low',
  },
  {
    'ip': '177.21.9.77',
    'port': '25',
    'action': 'blocked',
    'rule': 'SMTP-SHIELD',
    'time': '2026-04-12 14:23:28',
    'severity': 'high',
  },
  {
    'ip': '210.48.12.19',
    'port': '8080',
    'action': 'blocked',
    'rule': 'PORT-SCAN',
    'time': '2026-04-12 14:23:21',
    'severity': 'high',
  },
];

const List<Map<String, String>> topBlockedIps = [
  {'ip': '185.220.101.45', 'rule': 'SSH-BRUTE-FORCE'},
  {'ip': '45.142.120.67', 'rule': 'RDP-BLOCK'},
  {'ip': '89.248.167.131', 'rule': 'TELNET-BLOCK'},
  {'ip': '167.99.241.32', 'rule': 'SQL-BLOCK'},
];

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
  bool _autoFetchLogs = true;

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
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
    return Scrollbar(
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
            onTap: () {},
          ),
          const SizedBox(width: 14),
          _buildTopButton(
            label: 'Export',
            icon: Icons.download_outlined,
            filled: false,
            onTap: () {},
          ),
          const Spacer(),
          Row(
            children: [
              Checkbox(
                value: _autoFetchLogs,
                onChanged: (value) {
                  setState(() => _autoFetchLogs = value ?? false);
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
          const Padding(
            padding: EdgeInsets.fromLTRB(24, 30, 24, 14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Firewall Activity',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  '7 events in the last hour',
                  style: TextStyle(
                    color: Color(0xFF9DA9BD),
                    fontSize: 12,
                    fontWeight: FontWeight.w400,
                  ),
                ),
              ],
            ),
          ),
          _buildTableHeader(),
          ...firewallLogsData.map((row) => _buildTableRow(row)),
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

  Widget _buildTableRow(Map<String, String> row) {
    final status = row['action'] ?? 'allowed';
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
                row['ip'] ?? '-',
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
                row['port'] ?? '-',
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
            child: Center(child: _buildStatusBadge(status, statusColor)),
          ),
          Expanded(
            flex: 3,
            child: Center(
              child: Text(
                row['rule'] ?? '-',
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
                row['time'] ?? '-',
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
          _buildInsightRow('Blocked', 4, const Color(0xFFFF3B57), 0.58),
          const SizedBox(height: 12),
          _buildInsightRow('Allowed', 3, const Color(0xFF18E26D), 0.42),
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
          ...topBlockedIps.map(
            (item) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _buildTopBlockedRow(
                item['ip'] ?? '-',
                item['rule'] ?? '-',
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
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(14, 16, 14, 16),
      decoration: BoxDecoration(
        color: const Color(0xFF2C1D16),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF7A3D18)),
      ),
      child: const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Anomaly Detected',
            style: TextStyle(
              color: Color(0xFFFF8A00),
              fontSize: 14,
              fontWeight: FontWeight.w700,
            ),
          ),
          SizedBox(height: 8),
          Text(
            'Unusual spike in SSH connection attempts from Eastern Europe',
            style: TextStyle(
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
