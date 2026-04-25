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

/// Creates a consistent top navbar across all pages
Widget buildTopNavbar(BuildContext context, String pageTitle) {
  return Container(
    height: 72,
    padding: const EdgeInsets.symmetric(horizontal: 32),
    decoration: const BoxDecoration(
      color: Color(0xFF0F1420),
      border: Border(bottom: BorderSide(color: Color(0xFF1A1F2E), width: 1)),
    ),
    child: Row(
      children: [
        Text(
          pageTitle,
          style: const TextStyle(
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
            _TopNavbarActionButton(
              onTap: () {},
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
            _TopNavbarActionButton(
              onTap: () {},
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
  );
}

class _TopNavbarActionButton extends StatelessWidget {
  const _TopNavbarActionButton({required this.onTap, required this.child});

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
    widget.onNavigateDashboard?.call();
  }

  void _openPacketTracing(BuildContext context) {
    _setActive(1);
    widget.onNavigatePacketTracing?.call();
  }

  void _openFirewallLogs(BuildContext context) {
    _setActive(2);
    widget.onNavigateFirewallLogs?.call();
  }

  void _openVirusScanner(BuildContext context) {
    _setActive(3);
    widget.onNavigateVirusScanner?.call();
  }

  void _openIPLogAnalysis(BuildContext context) {
    _setActive(4);
    widget.onNavigateIPLogAnalysis?.call();
  }

  void _openReports(BuildContext context) {
    _setActive(5);
    widget.onNavigateReports?.call();
  }

  void _openSettings(BuildContext context) {
    _setActive(6);
    widget.onNavigateSettings?.call();
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
