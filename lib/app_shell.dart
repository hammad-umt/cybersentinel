import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/widgets/copilot/copilot_assistant.dart';
import 'package:cybersentinel/widgets/dashbaord/dashboard_screen.dart';
import 'package:cybersentinel/widgets/firewall_logs/firewall_logs.dart';
import 'package:cybersentinel/widgets/ip_analysis/ip_analysis.dart';
import 'package:cybersentinel/widgets/packet_tracing/packet_tracing.dart';
import 'package:cybersentinel/widgets/reports/reports.dart';
import 'package:cybersentinel/widgets/setings/settings.dart';
import 'package:cybersentinel/widgets/shared/animated_widgets.dart';
import 'package:cybersentinel/widgets/virus_scanner/virus_scanner.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:flutter/material.dart';

const _pageTitles = [
  'Dashboard',
  'Packet Tracing',
  'Firewall Logs',
  'Virus Scanner',
  'IP Analysis',
  'Reports',
  'Settings',
];

const _mobileNavItems = [
  (Icons.grid_view_rounded, 'Dashboard'),
  (Icons.account_tree_outlined, 'Packet'),
  (Icons.shield_outlined, 'Firewall'),
  (Icons.bug_report_outlined, 'Virus'),
  (Icons.location_on_outlined, 'IP'),
];

class MainAppShell extends StatefulWidget {
  const MainAppShell({super.key, this.initialIndex = 0});

  final int initialIndex;

  @override
  State<MainAppShell> createState() => _MainAppShellState();
}

class _MainAppShellState extends State<MainAppShell> {
  late int _pageIndex;
  bool _backendLive = false;
  bool _copilotOpen = false;

  static const _pages = [
    DashboardContent(),
    PacketTracingContent(),
    FirewallLogsContent(),
    VirusScannerContent(),
    IPAnalysisContent(),
    ReportsContent(),
    SettingsContent(),
  ];

  @override
  void initState() {
    super.initState();
    _pageIndex = widget.initialIndex;
    _checkHealth();
  }

  Future<void> _checkHealth() async {
    try {
      await ApiService.instance.getHealth();
      if (mounted) setState(() => _backendLive = true);
    } catch (_) {
      if (mounted) setState(() => _backendLive = false);
    }
  }

  void _navigate(int index) {
    if (index == _pageIndex) return;
    setState(() => _pageIndex = index);
  }

  void _openCopilot() => setState(() => _copilotOpen = true);
  void _toggleCopilot() => setState(() => _copilotOpen = !_copilotOpen);

  Future<void> _showProfileMenu(BuildContext context, Offset anchor) async {
    final auth = AuthService.instance;
    final result = await showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(
        anchor.dx,
        anchor.dy,
        anchor.dx + 1,
        anchor.dy + 1,
      ),
      color: AppColors.panel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
        side: const BorderSide(color: AppColors.borderElevated),
      ),
      items: [
        PopupMenuItem<String>(
          enabled: false,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                auth.email,
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontWeight: FontWeight.w600,
                  fontSize: 14,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                auth.role,
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ),
        const PopupMenuDivider(),
        const PopupMenuItem<String>(
          value: 'logout',
          child: Row(
            children: [
              Icon(Icons.logout, color: AppColors.redLight, size: 18),
              SizedBox(width: 8),
              Text('Log out', style: TextStyle(color: AppColors.textPrimary)),
            ],
          ),
        ),
      ],
    );

    if (result == 'logout') {
      await auth.logout();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!AuthService.instance.isAuthenticated) {
      return const SizedBox.shrink();
    }

    final isWide = MediaQuery.sizeOf(context).width >= 1024;

    if (isWide) {
      return Scaffold(
        backgroundColor: AppColors.bg,
        body: Stack(
          children: [
            SafeArea(
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  _DesktopSidebar(
                    activeIndex: _pageIndex,
                    backendLive: _backendLive,
                    onNavigate: _navigate,
                  ),
                  Expanded(
                    child: Column(
                      children: [
                        _TopNavbar(
                          title: _pageTitles[_pageIndex],
                          onProfileTap: _showProfileMenu,
                          onCopilotTap: _openCopilot,
                        ),
                        Expanded(
                          child: ColoredBox(
                            color: AppColors.bg,
                            child: _buildPageContent(),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            CopilotAssistantOverlay(
              isOpen: _copilotOpen,
              onToggle: _toggleCopilot,
            ),
          ],
        ),
      );
    }

    return Scaffold(
      backgroundColor: AppColors.bg,
      body: Stack(
        children: [
          SafeArea(
            child: Column(
              children: [
                _MobileHeader(
                  backendLive: _backendLive,
                  pageTitle: _pageTitles[_pageIndex],
                  onCopilotTap: _openCopilot,
                ),
                Expanded(child: _buildPageContent()),
                _MobileBottomNav(activeIndex: _pageIndex, onNavigate: _navigate),
              ],
            ),
          ),
          CopilotAssistantOverlay(
            isOpen: _copilotOpen,
            onToggle: _toggleCopilot,
          ),
        ],
      ),
    );
  }

  Widget _buildPageContent() {
    return AnimatedSwitcher(
      duration: const Duration(milliseconds: 350),
      switchInCurve: Curves.easeOutCubic,
      switchOutCurve: Curves.easeInCubic,
      transitionBuilder: (child, animation) {
        return FadeTransition(
          opacity: animation,
          child: SlideTransition(
            position: Tween<Offset>(
              begin: const Offset(0.02, 0),
              end: Offset.zero,
            ).animate(animation),
            child: child,
          ),
        );
      },
      child: KeyedSubtree(
        key: ValueKey(_pageIndex),
        child: _pages[_pageIndex],
      ),
    );
  }
}

class _DesktopSidebar extends StatelessWidget {
  const _DesktopSidebar({
    required this.activeIndex,
    required this.backendLive,
    required this.onNavigate,
  });

  final int activeIndex;
  final bool backendLive;
  final ValueChanged<int> onNavigate;

  static const _items = [
    (Icons.grid_view_rounded, 'Dashboard'),
    (Icons.account_tree_outlined, 'Packet Tracing'),
    (Icons.shield_outlined, 'Firewall Logs'),
    (Icons.bug_report_outlined, 'Virus Scanner'),
    (Icons.location_on_outlined, 'IP Analysis'),
    (Icons.description_outlined, 'Reports'),
    (Icons.settings_outlined, 'Settings'),
  ];

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 240,
      decoration: const BoxDecoration(
        color: AppColors.panel,
        border: Border(right: BorderSide(color: AppColors.border)),
      ),
      child: Column(
        children: [
          Container(
            height: 64,
            padding: const EdgeInsets.symmetric(horizontal: 24),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: AppColors.border)),
            ),
            child: const Row(
              children: [
                Icon(Icons.shield_outlined, color: AppColors.cyanLight, size: 24),
                SizedBox(width: 12),
                Text(
                  'CyberSentinel',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 24),
              children: [
                for (var i = 0; i < _items.length; i++)
                  _NavTile(
                    icon: _items[i].$1,
                    label: _items[i].$2,
                    isActive: activeIndex == i,
                    onTap: () => onNavigate(i),
                  ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: AppColors.border,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text(
                    'System Status',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                  ),
                  Row(
                    children: [
                      if (backendLive)
                        const PulsingDot(color: AppColors.red, size: 8)
                      else
                        const Icon(Icons.circle, color: AppColors.textDim, size: 8),
                      const SizedBox(width: 8),
                      Text(
                        backendLive ? 'LIVE' : 'OFFLINE',
                        style: TextStyle(
                          color: backendLive ? AppColors.redLight : AppColors.textDim,
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
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
    required this.isActive,
    required this.onTap,
  });

  final IconData icon;
  final String label;
  final bool isActive;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(8),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: isActive ? AppColors.cyan.withValues(alpha: 0.1) : Colors.transparent,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: isActive ? AppColors.cyan.withValues(alpha: 0.2) : Colors.transparent,
              ),
            ),
            child: Row(
              children: [
                Icon(
                  icon,
                  size: 20,
                  color: isActive ? AppColors.cyanLight : AppColors.textMuted,
                ),
                const SizedBox(width: 12),
                Text(
                  label,
                  style: TextStyle(
                    color: isActive ? AppColors.cyanLight : AppColors.textMuted,
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

class _TopNavbar extends StatelessWidget {
  const _TopNavbar({
    required this.title,
    required this.onProfileTap,
    required this.onCopilotTap,
  });

  final String title;
  final void Function(BuildContext context, Offset anchor) onProfileTap;
  final VoidCallback onCopilotTap;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 64,
      padding: const EdgeInsets.symmetric(horizontal: 32),
      decoration: const BoxDecoration(
        color: AppColors.panel,
        border: Border(bottom: BorderSide(color: AppColors.border)),
      ),
      child: Row(
        children: [
          Text(
            title,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 20,
              fontWeight: FontWeight.w600,
            ),
          ),
          const Spacer(),
          SizedBox(
            width: 320,
            height: 40,
            child: TextField(
              style: const TextStyle(color: AppColors.textPrimary, fontSize: 14, fontWeight: FontWeight.w500),
              cursorColor: AppColors.cyanLight,
              decoration: InputDecoration(
                hintText: 'Global search...',
                hintStyle: const TextStyle(color: AppColors.textDim, fontSize: 14, fontWeight: FontWeight.w500),
                filled: true,
                fillColor: AppColors.border,
                prefixIcon: const Icon(Icons.search, color: AppColors.textDim, size: 18),
                contentPadding: const EdgeInsets.symmetric(vertical: 0),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: AppColors.borderElevated),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: AppColors.cyan.withValues(alpha: 0.5)),
                ),
              ),
            ),
          ),
          const SizedBox(width: 16),
          _NavIconButton(
            icon: Icons.notifications_none,
            badge: true,
            onTap: (_, __) {},
          ),
          const SizedBox(width: 8),
          _CopilotNavButton(onTap: onCopilotTap),
          const SizedBox(width: 4),
          _NavIconButton(
            icon: Icons.person_outline,
            avatar: true,
            onTap: (context, position) => onProfileTap(context, position),
          ),
        ],
      ),
    );
  }
}

class _CopilotNavButton extends StatefulWidget {
  const _CopilotNavButton({required this.onTap});

  final VoidCallback onTap;

  @override
  State<_CopilotNavButton> createState() => _CopilotNavButtonState();
}

class _CopilotNavButtonState extends State<_CopilotNavButton> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: Tooltip(
        message: 'Security Copilot',
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            onTap: widget.onTap,
            borderRadius: BorderRadius.circular(8),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: _hover ? AppColors.cyan.withValues(alpha: 0.12) : AppColors.border,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: _hover ? AppColors.cyan.withValues(alpha: 0.35) : AppColors.borderElevated,
                ),
              ),
              child: const Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.auto_awesome, color: AppColors.cyanLight, size: 16),
                  SizedBox(width: 6),
                  Text(
                    'Copilot',
                    style: TextStyle(
                      color: AppColors.cyanLight,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _NavIconButton extends StatefulWidget {
  const _NavIconButton({
    required this.icon,
    required this.onTap,
    this.badge = false,
    this.avatar = false,
  });

  final IconData icon;
  final void Function(BuildContext context, Offset globalPosition) onTap;
  final bool badge;
  final bool avatar;

  @override
  State<_NavIconButton> createState() => _NavIconButtonState();
}

class _NavIconButtonState extends State<_NavIconButton> {
  bool _hover = false;
  final _key = GlobalKey();

  @override
  Widget build(BuildContext context) {
    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        key: _key,
        onTap: () {
          final box = _key.currentContext?.findRenderObject() as RenderBox?;
          if (box == null) return;
          final position = box.localToGlobal(Offset.zero);
          widget.onTap(context, Offset(position.dx, position.dy + box.size.height));
        },
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: _hover ? AppColors.border : Colors.transparent,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Stack(
            clipBehavior: Clip.none,
            children: [
              if (widget.avatar)
                Container(
                  width: 32,
                  height: 32,
                  decoration: BoxDecoration(
                    color: AppColors.cyan.withValues(alpha: 0.2),
                    shape: BoxShape.circle,
                  ),
                  child: Icon(widget.icon, color: AppColors.cyanLight, size: 20),
                )
              else
                Icon(widget.icon, color: AppColors.textMuted, size: 20),
              if (widget.badge)
                const Positioned(
                  right: 0,
                  top: 0,
                  child: Icon(Icons.circle, color: AppColors.red, size: 8),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _MobileHeader extends StatelessWidget {
  const _MobileHeader({
    required this.backendLive,
    required this.pageTitle,
    required this.onCopilotTap,
  });

  final bool backendLive;
  final String pageTitle;
  final VoidCallback onCopilotTap;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 64,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: const BoxDecoration(
        color: AppColors.panel,
        border: Border(bottom: BorderSide(color: AppColors.border)),
      ),
      child: Row(
        children: [
          const Icon(Icons.shield_outlined, color: AppColors.cyanLight, size: 22),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  pageTitle,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  backendLive ? 'Backend connected' : 'Backend offline',
                  style: TextStyle(
                    color: backendLive ? AppColors.greenLight : AppColors.textDim,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: onCopilotTap,
            icon: const Icon(Icons.auto_awesome, color: AppColors.cyanLight, size: 22),
            tooltip: 'Security Copilot',
          ),
          const Icon(Icons.notifications_none, color: AppColors.textMuted, size: 22),
        ],
      ),
    );
  }
}

class _MobileBottomNav extends StatelessWidget {
  const _MobileBottomNav({required this.activeIndex, required this.onNavigate});

  final int activeIndex;
  final ValueChanged<int> onNavigate;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 64,
      decoration: const BoxDecoration(
        color: AppColors.panel,
        border: Border(top: BorderSide(color: AppColors.border)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: [
          for (var i = 0; i < _mobileNavItems.length; i++)
            GestureDetector(
              onTap: () => onNavigate(i),
              behavior: HitTestBehavior.opaque,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      _mobileNavItems[i].$1,
                      size: 20,
                      color: activeIndex == i ? AppColors.cyanLight : AppColors.textDim,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      _mobileNavItems[i].$2,
                      style: TextStyle(
                        color: activeIndex == i ? AppColors.cyanLight : AppColors.textDim,
                        fontSize: 11,
                      ),
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

