import 'package:flutter/material.dart';

class SidebarPanel extends StatelessWidget {
  const SidebarPanel({
    super.key,
    this.onNavigateNotImplemented,
    this.onNavigateDashboard,
  });

  final VoidCallback? onNavigateNotImplemented;
  final VoidCallback? onNavigateDashboard;

  void _openNotImplemented(BuildContext context) {
    if (onNavigateNotImplemented != null) {
      onNavigateNotImplemented!();
    }
  }

  void _openDashboard(BuildContext context) {
    if (onNavigateDashboard != null) {
      onNavigateDashboard!();
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
                  isActive: true,
                  onTap: () => _openDashboard(context),
                ),
                _NavTile(
                  icon: Icons.account_tree_outlined,
                  label: 'Packet Tracing',
                  onTap: () => _openNotImplemented(context),
                ),
                _NavTile(
                  icon: Icons.shield_outlined,
                  label: 'Firewall Logs',
                  onTap: () => _openNotImplemented(context),
                ),
                _NavTile(
                  icon: Icons.bug_report_outlined,
                  label: 'Virus Scanner',
                  onTap: () => _openNotImplemented(context),
                ),
                _NavTile(
                  icon: Icons.location_on_outlined,
                  label: 'IP Analysis',
                  onTap: () => _openNotImplemented(context),
                ),
                _NavTile(
                  icon: Icons.description_outlined,
                  label: 'Reports',
                  onTap: () => _openNotImplemented(context),
                ),
                _NavTile(
                  icon: Icons.settings_outlined,
                  label: 'Settings',
                  onTap: () => _openNotImplemented(context),
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
