import 'package:cybersentinel/auth/auth_gate.dart';
import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/backend_launcher.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/theme/app_theme.dart';
import 'package:cybersentinel/theme/theme_service.dart';
import 'package:cybersentinel/widgets/shared/engine_boot_screen.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

final _rootMessengerKey = GlobalKey<ScaffoldMessengerState>();

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await ApiConfig.load();
  // Desktop bundles a local engine; web uses ApiConfig.baseUrl from settings.
  if (!kIsWeb) {
    ApiConfig.baseUrl = BackendLauncher.apiBaseUrl;
  }
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
          scaffoldMessengerKey: _rootMessengerKey,
          debugShowCheckedModeBanner: false,
          themeMode: themeService.mode,
          theme: AppTheme.light(),
          darkTheme: AppTheme.dark(),
          home: const EngineBootScreen(child: AuthGate()),
        );
      },
    );
  }
}
