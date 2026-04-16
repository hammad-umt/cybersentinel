import 'package:flutter/material.dart';
import './dashbaord/dashboard_screen.dart';
import './packet_tracing/packet_tracing.dart';
import './firewall_logs/firewall_logs.dart';
import './virus_scanner/virus_scanner.dart';
import './ip_analysis/ip_analysis.dart';
import './reports/reports.dart';
import './setings/settings.dart';

/// Creates a fully configured SidebarPanel with all navigation callbacks
Widget buildSidebarPanel(BuildContext context, int activePageIndex) {
  return SidebarPanel(
    activePageIndex: activePageIndex,
    onNavigateDashboard: () {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const DashboardScreen()),
        (route) => false,
      );
    },
    onNavigatePacketTracing: () {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const PacketTracingPage()),
        (route) => false,
      );
    },
    onNavigateFirewallLogs: () {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const FirewallLogsPage()),
        (route) => false,
      );
    },
    onNavigateVirusScanner: () {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const VirusScannerPage()),
        (route) => false,
      );
    },
    onNavigateIPLogAnalysis: () {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const IPLogAnalysisPage()),
        (route) => false,
      );
    },
    onNavigateReports: () {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const ReportsPage()),
        (route) => false,
      );
    },
    onNavigateSettings: () {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const SettingsPage()),
        (route) => false,
      );
    },
  );
}

class SidebarPanel extends StatefulWidget {
  const SidebarPanel({
    super.key,
    this.onNavigateDashboard,
    this.onNavigatePacketTracing,
    this.onNavigateFirewallLogs,
    this.onNavigateVirusScanner,
    this.onNavigateIPLogAnalysis,
    this.onNavigateReports,
    this.onNavigateSettings,
    this.activePageIndex = 0,
  });

  final VoidCallback? onNavigateDashboard;
  final VoidCallback? onNavigatePacketTracing;
  final VoidCallback? onNavigateFirewallLogs;
  final VoidCallback? onNavigateVirusScanner;
  final VoidCallback? onNavigateIPLogAnalysis;
  final VoidCallback? onNavigateReports;
  final VoidCallback? onNavigateSettings;
  final int activePageIndex;

  @override
  State<SidebarPanel> createState() => _SidebarPanelState();
}

class _SidebarPanelState extends State<SidebarPanel> {
  late int _activeIndex;

  @override
  void initState() {
    super.initState();
    _activeIndex = widget.activePageIndex;
  }

  @override
  void didUpdateWidget(SidebarPanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.activePageIndex != widget.activePageIndex) {
      setState(() => _activeIndex = widget.activePageIndex);
    }
  }

  void _setActive(int index) {
    setState(() => _activeIndex = index);
  }

  void _openDashboard(BuildContext context) {
    _setActive(0);
    if (widget.onNavigateDashboard != null) {
      widget.onNavigateDashboard!();
    }
  }

  void _openPacketTracing(BuildContext context) {
    _setActive(1);
    if (widget.onNavigatePacketTracing != null) {
      widget.onNavigatePacketTracing!();
    }
  }

  void _openFirewallLogs(BuildContext context) {
    _setActive(2);
    if (widget.onNavigateFirewallLogs != null) {
      widget.onNavigateFirewallLogs!();
    }
  }

  void _openVirusScanner(BuildContext context) {
    _setActive(3);
    if (widget.onNavigateVirusScanner != null) {
      widget.onNavigateVirusScanner!();
    }
  }

  void _openIPLogAnalysis(BuildContext context) {
    _setActive(4);
    if (widget.onNavigateIPLogAnalysis != null) {
      widget.onNavigateIPLogAnalysis!();
    }
  }

  void _openReports(BuildContext context) {
    _setActive(5);
    if (widget.onNavigateReports != null) {
      widget.onNavigateReports!();
    }
  }

  void _openSettings(BuildContext context) {
    _setActive(6);
    if (widget.onNavigateSettings != null) {
      widget.onNavigateSettings!();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 240,
      decoration: const BoxDecoration(
        color: Color(0xFF0F1420),
        border: Border(right: BorderSide(color: Color(0xFF1A1F2E), width: 1)),
      ),
      child: Column(
        children: [
          Container(
            height: 72,
            padding: const EdgeInsets.symmetric(horizontal: 20),
            decoration: const BoxDecoration(
              border: Border(
                bottom: BorderSide(color: Color(0xFF1A1F2E), width: 1),
              ),
            ),
            child: const Padding(
              padding: EdgeInsets.fromLTRB(4, 10, 10, 10),
              child: Row(
                children: [
                  Icon(
                    Icons.shield_outlined,
                    color: Color(0xFF00D3FF),
                    size: 26,
                  ),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'CyberSentinel',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.only(top: 18, bottom: 8),
              children: [
                _NavTile(
                  icon: Icons.grid_view_rounded,
                  label: 'Dashboard',
                  isActive: _activeIndex == 0,
                  onTap: () => _openDashboard(context),
                ),
                _NavTile(
                  icon: Icons.account_tree_outlined,
                  label: 'Packet Tracing',
                  isActive: _activeIndex == 1,
                  onTap: () => _openPacketTracing(context),
                ),
                _NavTile(
                  icon: Icons.shield_outlined,
                  label: 'Firewall Logs',
                  isActive: _activeIndex == 2,
                  onTap: () => _openFirewallLogs(context),
                ),
                _NavTile(
                  icon: Icons.bug_report_outlined,
                  label: 'Virus Scanner',
                  isActive: _activeIndex == 3,
                  onTap: () => _openVirusScanner(context),
                ),
                _NavTile(
                  icon: Icons.location_on_outlined,
                  label: 'IP Analysis',
                  isActive: _activeIndex == 4,
                  onTap: () => _openIPLogAnalysis(context),
                ),
                _NavTile(
                  icon: Icons.description_outlined,
                  label: 'Reports',
                  isActive: _activeIndex == 5,
                  onTap: () => _openReports(context),
                ),
                _NavTile(
                  icon: Icons.settings_outlined,
                  label: 'Settings',
                  isActive: _activeIndex == 6,
                  onTap: () => _openSettings(context),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
            child: Container(
              height: 40,
              padding: const EdgeInsets.symmetric(horizontal: 14),
              decoration: BoxDecoration(
                color: const Color(0xFF1A1F2E),
                borderRadius: BorderRadius.circular(12),
              ),
              child: const Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'System Status',
                    style: TextStyle(
                      color: Color(0xFF98A2B3),
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  Row(
                    children: [
                      Icon(Icons.circle, color: Color(0xFFFF3B57), size: 9),
                      SizedBox(width: 6),
                      Text(
                        'LIVE',
                        style: TextStyle(
                          color: Color(0xFFFF4D61),
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _NavTile extends StatelessWidget {
  const _NavTile({
    required this.icon,
    required this.label,
    this.isActive = false,
    this.onTap,
  });

  final IconData icon;
  final String label;
  final bool isActive;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final backgroundColor = isActive
        ? const Color(0x1100D3FF)
        : Colors.transparent;
    final borderColor = isActive ? const Color(0x3300D3FF) : Colors.transparent;
    final textColor = isActive
        ? const Color.fromARGB(255, 27, 217, 255)
        : const Color(0xFFB7C0CF);

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          mouseCursor: onTap != null
              ? SystemMouseCursors.click
              : SystemMouseCursors.basic,
          borderRadius: BorderRadius.circular(12),
          child: Container(
            height: 44,
            decoration: BoxDecoration(
              color: backgroundColor,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: borderColor),
            ),
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Row(
              children: [
                Icon(icon, size: 24, color: textColor),
                const SizedBox(width: 12),
                Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: textColor,
                    fontSize: 14,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
