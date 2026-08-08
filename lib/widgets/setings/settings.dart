import 'package:cybersentinel/auth/require_auth.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/theme/theme_service.dart';
import 'package:cybersentinel/widgets/shared/cyber_card.dart';
import 'package:cybersentinel/widgets/shared/page_header.dart';
import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// HCI layout constants — readable width, touch targets, rhythm.
abstract final class _Hci {
  static const pagePadding = 32.0;
  static const sectionGap = 24.0;
  static const maxContentWidth = 720.0;
  static const minTouchTarget = 48.0;
}

class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return RequireAuth(
      child: Scaffold(
        backgroundColor: AppColors.bg,
        body: SafeArea(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              buildSidebarPanel(context, 6),
              Expanded(
                child: Column(
                  children: [
                    buildTopNavbar(context, 'Settings'),
                    const Expanded(child: SettingsContent()),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class SettingsContent extends StatefulWidget {
  const SettingsContent({super.key});

  @override
  State<SettingsContent> createState() => _SettingsContentState();
}

class _SettingsContentState extends State<SettingsContent> {
  bool backgroundMonitoring = true;
  bool emailAlerts = true;
  bool pushNotifications = false;
  String selectedTheme = 'dark';
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    selectedTheme = ThemeService.instance.themeName;
  }

  @override
  void dispose() {
    super.dispose();
  }

  Future<void> _saveSettings() async {
    setState(() => _saving = true);
    try {
      await ThemeService.instance.setFromName(selectedTheme);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            selectedTheme == 'light'
                ? 'Preferences saved. Light theme is now active.'
                : 'Preferences saved. Dark theme is now active.',
          ),
        ),
      );
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _confirmLogout() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.panel,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: AppColors.borderElevated),
        ),
        title: Text(
          'Sign out?',
          style: TextStyle(color: AppColors.textPrimary),
        ),
        content: Text(
          'You will need to sign in again to access dashboards and security tools.',
          style: TextStyle(color: AppColors.textMuted, height: 1.45),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text('Cancel', style: TextStyle(color: AppColors.textMuted)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(
              'Sign out',
              style: TextStyle(color: AppColors.redLight),
            ),
          ),
        ],
      ),
    );
    if (confirmed == true) await AuthService.instance.logout();
  }

  String _initials(String email) {
    if (email.isEmpty) return '?';
    final local = email.split('@').first;
    if (local.contains('.')) {
      final parts = local.split('.');
      return '${parts.first[0]}${parts.last[0]}'.toUpperCase();
    }
    return local.length >= 2
        ? local.substring(0, 2).toUpperCase()
        : local[0].toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: AuthService.instance,
      builder: (context, _) {
        final auth = AuthService.instance;
        final email = auth.email;
        final role = auth.role;

        return SingleChildScrollView(
          padding: const EdgeInsets.all(_Hci.pagePadding),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: _Hci.maxContentWidth),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  PageHeader(
                    title: 'Settings',
                    subtitle:
                        'Manage your account, notifications, and how CyberSentinel looks and feels.',
                    icon: Icons.settings_outlined,
                  ),
                  _AccountCard(
                    initials: _initials(email),
                    email: email,
                    role: role,
                    isOnline: true,
                    onSignOut: _confirmLogout,
                  ),
                  const SizedBox(height: _Hci.sectionGap),
                  _SettingsSection(
                    icon: Icons.brightness_4_outlined,
                    title: 'Appearance',
                    subtitle:
                        'Choose a theme that is comfortable for long investigation sessions.',
                    child: _ThemePicker(
                      selected: selectedTheme,
                      onChanged: (v) => setState(() => selectedTheme = v),
                    ),
                  ),
                  const SizedBox(height: _Hci.sectionGap),
                  _SettingsSection(
                    icon: Icons.notifications_outlined,
                    title: 'Notifications',
                    subtitle:
                        'Control how and when you are alerted to new threats.',
                    child: Column(
                      children: [
                        _SettingToggle(
                          title: 'Email alerts',
                          description:
                              'Receive a summary when high-severity threats are detected.',
                          value: emailAlerts,
                          onChanged: (v) => setState(() => emailAlerts = v),
                        ),
                        const SizedBox(height: 12),
                        _SettingToggle(
                          title: 'Push notifications',
                          description:
                              'Get real-time alerts on this device while the app is open.',
                          value: pushNotifications,
                          onChanged: (v) =>
                              setState(() => pushNotifications = v),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: _Hci.sectionGap),
                  _SettingsSection(
                    icon: Icons.public_outlined,
                    title: 'Monitoring',
                    subtitle:
                        'Background services that keep your environment under watch.',
                    child: _SettingToggle(
                      title: 'Background monitoring',
                      description:
                          'Continuously analyse network traffic for suspicious activity.',
                      value: backgroundMonitoring,
                      onChanged: (v) =>
                          setState(() => backgroundMonitoring = v),
                    ),
                  ),
                  const SizedBox(height: _Hci.sectionGap),
                  _SettingsSection(
                    icon: Icons.key_outlined,
                    title: 'Threat intelligence keys',
                    subtitle:
                        'Optional integrations for deeper file, URL, and IP lookups.',
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        _ApiKeyField(
                          label: 'VirusTotal',
                          hint: 'Paste your VirusTotal API key',
                          helper: 'Used for file and URL reputation scans.',
                        ),
                        const SizedBox(height: 16),
                        _ApiKeyField(
                          label: 'AbuseIPDB',
                          hint: 'Paste your AbuseIPDB API key',
                          helper: 'Adds community abuse reports to IP scoring.',
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: _Hci.sectionGap),
                  Align(
                    alignment: Alignment.centerRight,
                    child: SizedBox(
                      height: _Hci.minTouchTarget,
                      child: ElevatedButton.icon(
                        onPressed: _saving ? null : _saveSettings,
                        icon: _saving
                            ? const SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Colors.white,
                                ),
                              )
                            : const Icon(Icons.check_rounded, size: 18),
                        label: Text(_saving ? 'Saving…' : 'Save preferences'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.cyan,
                          foregroundColor: Colors.white,
                          disabledBackgroundColor: AppColors.borderElevated,
                          padding: const EdgeInsets.symmetric(horizontal: 24),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(8),
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

/// Top profile card — identity, role, status, sign-out (no technical backend details).
class _AccountCard extends StatelessWidget {
  const _AccountCard({
    required this.initials,
    required this.email,
    required this.role,
    required this.isOnline,
    required this.onSignOut,
  });

  final String initials;
  final String email;
  final String role;
  final bool? isOnline;
  final VoidCallback onSignOut;

  @override
  Widget build(BuildContext context) {
    final statusLabel = isOnline == null
        ? 'Checking status…'
        : isOnline!
        ? 'All services operational'
        : 'Some services unavailable';
    final statusColor = isOnline == null
        ? AppColors.textDim
        : isOnline!
        ? AppColors.greenLight
        : AppColors.orangeLight;

    return CyberCard(
      padding: const EdgeInsets.all(24),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  AppColors.cyan.withValues(alpha: 0.85),
                  AppColors.cyanLight.withValues(alpha: 0.7),
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: AppColors.cyan.withValues(alpha: 0.35)),
            ),
            alignment: Alignment.center,
            child: Text(
              initials,
              style: GoogleFonts.inter(
                color: Colors.white,
                fontSize: 20,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  email,
                  style: GoogleFonts.inter(
                    color: AppColors.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 6),
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 3,
                      ),
                      decoration: BoxDecoration(
                        color: AppColors.cyan.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(
                          color: AppColors.cyan.withValues(alpha: 0.25),
                        ),
                      ),
                      child: Text(
                        role,
                        style: GoogleFonts.inter(
                          color: AppColors.cyanLight,
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Container(
                      width: 7,
                      height: 7,
                      decoration: BoxDecoration(
                        color: statusColor,
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      statusLabel,
                      style: GoogleFonts.inter(
                        color: AppColors.textMuted,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  'Signed in · Session active',
                  style: GoogleFonts.inter(
                    color: AppColors.textDim,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          SizedBox(
            height: _Hci.minTouchTarget,
            child: OutlinedButton.icon(
              onPressed: onSignOut,
              icon: Icon(
                Icons.logout_rounded,
                size: 16,
                color: AppColors.redLight,
              ),
              label: Text(
                'Sign out',
                style: TextStyle(color: AppColors.redLight, fontSize: 13),
              ),
              style: OutlinedButton.styleFrom(
                side: BorderSide(color: AppColors.red.withValues(alpha: 0.35)),
                backgroundColor: AppColors.red.withValues(alpha: 0.06),
                padding: const EdgeInsets.symmetric(horizontal: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SettingsSection extends StatelessWidget {
  const _SettingsSection({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.child,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: AppColors.cyanLight, size: 20),
              const SizedBox(width: 10),
              Text(
                title,
                style: GoogleFonts.inter(
                  color: AppColors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            subtitle,
            style: GoogleFonts.inter(
              color: AppColors.textMuted,
              fontSize: 13,
              height: 1.4,
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 20),
            child: Divider(color: AppColors.borderElevated, height: 1),
          ),
          child,
        ],
      ),
    );
  }
}

/// HCI toggle row — label + helper on the left, switch on the right (48px min height).
class _SettingToggle extends StatelessWidget {
  const _SettingToggle({
    required this.title,
    required this.description,
    required this.value,
    required this.onChanged,
  });

  final String title;
  final String description;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: AppColors.alertItemBg,
      borderRadius: BorderRadius.circular(8),
      child: InkWell(
        onTap: () => onChanged(!value),
        borderRadius: BorderRadius.circular(8),
        child: Container(
          constraints: const BoxConstraints(minHeight: _Hci.minTouchTarget),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: AppColors.borderElevated),
          ),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: GoogleFonts.inter(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      description,
                      style: GoogleFonts.inter(
                        color: AppColors.textMuted,
                        fontSize: 12,
                        height: 1.35,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              Switch(
                value: value,
                onChanged: onChanged,
                activeThumbColor: AppColors.cyan,
                inactiveThumbColor: AppColors.textDim,
                inactiveTrackColor: AppColors.borderElevated,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ThemePicker extends StatelessWidget {
  const _ThemePicker({required this.selected, required this.onChanged});

  final String selected;
  final ValueChanged<String> onChanged;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: _ThemeOption(
            label: 'Light',
            icon: Icons.wb_sunny_outlined,
            previewColors: const [
              Color(0xFFF8FAFC),
              Color(0xFFFFFFFF),
              Color(0xFFE2E8F0),
            ],
            isSelected: selected == 'light',
            onTap: () => onChanged('light'),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _ThemeOption(
            label: 'Dark',
            icon: Icons.nights_stay_outlined,
            previewColors: const [
              Color(0xFF0A0E1A),
              Color(0xFF0F1420),
              Color(0xFF1A1F2E),
            ],
            isSelected: selected == 'dark',
            onTap: () => onChanged('dark'),
          ),
        ),
      ],
    );
  }
}

class _ThemeOption extends StatelessWidget {
  const _ThemeOption({
    required this.label,
    required this.icon,
    required this.previewColors,
    required this.isSelected,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final List<Color> previewColors;
  final bool isSelected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      selected: isSelected,
      label: '$label theme',
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(10),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 180),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppColors.alertItemBg,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(
                color: isSelected ? AppColors.cyan : AppColors.borderElevated,
                width: isSelected ? 2 : 1,
              ),
            ),
            child: Column(
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    for (final c in previewColors)
                      Container(
                        width: 22,
                        height: 22,
                        margin: const EdgeInsets.symmetric(horizontal: 2),
                        decoration: BoxDecoration(
                          color: c,
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: AppColors.borderElevated),
                        ),
                      ),
                  ],
                ),
                const SizedBox(height: 12),
                Icon(
                  icon,
                  color: isSelected ? AppColors.cyan : AppColors.textMuted,
                  size: 20,
                ),
                const SizedBox(height: 6),
                Text(
                  label,
                  style: GoogleFonts.inter(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                if (isSelected) ...[
                  const SizedBox(height: 4),
                  Icon(Icons.check_circle, size: 14, color: AppColors.cyan),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _ApiKeyField extends StatelessWidget {
  const _ApiKeyField({
    required this.label,
    required this.hint,
    required this.helper,
  });

  final String label;
  final String hint;
  final String helper;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.inter(
            color: AppColors.textPrimary,
            fontSize: 14,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 6),
        TextFormField(
          obscureText: true,
          style: GoogleFonts.inter(color: AppColors.textPrimary, fontSize: 14),
          cursorColor: AppColors.cyanLight,
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: GoogleFonts.inter(
              color: AppColors.textDim,
              fontSize: 14,
            ),
            helperText: helper,
            helperStyle: GoogleFonts.inter(
              color: AppColors.textDim,
              fontSize: 11,
            ),
            filled: true,
            fillColor: AppColors.alertItemBg,
            contentPadding: const EdgeInsets.symmetric(
              horizontal: 14,
              vertical: 14,
            ),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide.none,
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppColors.borderElevated),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(
                color: AppColors.cyan.withValues(alpha: 0.5),
              ),
            ),
          ),
        ),
      ],
    );
  }
}
