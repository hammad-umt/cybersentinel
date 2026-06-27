import 'package:cybersentinel/auth/forgot_password_screen.dart';
import 'package:cybersentinel/auth/login_screen.dart';
import 'package:cybersentinel/auth/register_screen.dart';
import 'package:cybersentinel/auth/reset_password_screen.dart';
import 'package:flutter/material.dart';

/// Public auth routes only — kept separate from the protected app shell.
class AuthNavigator extends StatelessWidget {
  const AuthNavigator({super.key, this.initialResetToken});

  final String? initialResetToken;

  static const loginRoute = '/';
  static const registerRoute = '/register';
  static const forgotRoute = '/forgot-password';
  static const resetRoute = '/reset-password';

  @override
  Widget build(BuildContext context) {
    final initialRoute =
        initialResetToken != null && initialResetToken!.isNotEmpty
            ? resetRoute
            : loginRoute;

    return Navigator(
      initialRoute: initialRoute,
      onGenerateRoute: (settings) {
        switch (settings.name) {
          case registerRoute:
            return MaterialPageRoute<void>(
              settings: settings,
              builder: (_) => const RegisterScreen(),
            );
          case forgotRoute:
            return MaterialPageRoute<void>(
              settings: settings,
              builder: (_) => const ForgotPasswordScreen(),
            );
          case resetRoute:
            final token = settings.arguments as String? ??
                initialResetToken ??
                '';
            return MaterialPageRoute<void>(
              settings: settings,
              builder: (_) => ResetPasswordScreen(token: token),
            );
          case loginRoute:
          default:
            return MaterialPageRoute<void>(
              settings: settings,
              builder: (_) => const LoginScreen(),
            );
        }
      },
    );
  }
}
