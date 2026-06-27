import 'package:cybersentinel/auth/auth_navigator.dart';
import 'package:cybersentinel/auth/protected_main_shell.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';

/// Routes users to auth screens or the protected app based on session state.
class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  @override
  void initState() {
    super.initState();
    AuthService.instance.initialize();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: AuthService.instance,
      builder: (context, _) {
        final auth = AuthService.instance;

        if (!auth.isInitialized || auth.isLoading) {
          return const Scaffold(
            backgroundColor: AppColors.bg,
            body: Center(
              child: CircularProgressIndicator(color: AppColors.cyan),
            ),
          );
        }

        if (auth.isAuthenticated) {
          return const ProtectedMainShell();
        }

        final resetToken = Uri.base.queryParameters['token'];
        return AuthNavigator(initialResetToken: resetToken);
      },
    );
  }
}
