import 'package:cybersentinel/services/auth_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';

/// Blocks [child] unless the user has a valid authenticated session.
class RequireAuth extends StatelessWidget {
  const RequireAuth({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: AuthService.instance,
      builder: (context, _) {
        if (!AuthService.instance.isAuthenticated) {
          return Scaffold(
            backgroundColor: AppColors.bg,
            body: Center(
              child: CircularProgressIndicator(color: AppColors.cyan),
            ),
          );
        }
        return child;
      },
    );
  }
}
