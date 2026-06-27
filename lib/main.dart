import 'package:cybersentinel/auth/auth_gate.dart';
import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/theme/app_theme.dart';
import 'package:cybersentinel/theme/theme_service.dart';
import 'package:flutter/material.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await ApiConfig.load();
  await ThemeService.instance.load();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: ThemeService.instance,
      builder: (context, _) {
        final themeService = ThemeService.instance;
        // Keep design tokens in sync with the active theme mode.
        AppColors.setLightMode(themeService.isLight);

        return MaterialApp(
          key: ValueKey(themeService.mode),
          debugShowCheckedModeBanner: false,
          themeMode: themeService.mode,
          theme: AppTheme.light(),
          darkTheme: AppTheme.dark(),
          home: const AuthGate(),
        );
      },
    );
  }
}
