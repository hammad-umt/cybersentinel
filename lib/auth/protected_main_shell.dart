import 'package:cybersentinel/app_shell.dart';
import 'package:cybersentinel/auth/require_auth.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:cybersentinel/services/firewall_monitor_service.dart';
import 'package:cybersentinel/services/packet_capture_service.dart';
import 'package:cybersentinel/services/security_alert_service.dart';
import 'package:flutter/material.dart';

/// Dashboard shell — only mounted while the user is signed in.
class ProtectedMainShell extends StatefulWidget {
  const ProtectedMainShell({super.key});

  @override
  State<ProtectedMainShell> createState() => _ProtectedMainShellState();
}

class _ProtectedMainShellState extends State<ProtectedMainShell> {
  @override
  void initState() {
    super.initState();
    if (AuthService.instance.isAuthenticated) {
      PacketCaptureService.instance.initialize();
      FirewallMonitorService.instance.initialize();
      SecurityAlertService.instance.initialize();
    }
  }

  @override
  Widget build(BuildContext context) {
    return RequireAuth(
      child: ListenableBuilder(
        listenable: AuthService.instance,
        builder: (context, _) {
          if (!AuthService.instance.isAuthenticated) {
            return const SizedBox.shrink();
          }
          return const MainAppShell();
        },
      ),
    );
  }
}
