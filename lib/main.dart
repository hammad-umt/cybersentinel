import 'dart:async';

import 'package:cybersentinel/auth/auth_gate.dart';
import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/backend_launcher.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/theme/app_theme.dart';
import 'package:cybersentinel/theme/theme_service.dart';
import 'package:cybersentinel/widgets/shared/engine_boot_screen.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

final _rootMessengerKey = GlobalKey<ScaffoldMessengerState>();

class DesktopScrollBehavior extends MaterialScrollBehavior {
  const DesktopScrollBehavior();

  @override
  Set<PointerDeviceKind> get dragDevices => const {
    PointerDeviceKind.touch,
    PointerDeviceKind.mouse,
    PointerDeviceKind.stylus,
    PointerDeviceKind.invertedStylus,
    PointerDeviceKind.trackpad,
    PointerDeviceKind.unknown,
  };
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await ApiConfig.load();
  // Desktop uses the local backend service on port 8000; web uses ApiConfig.baseUrl from settings.
  if (!kIsWeb) {
    ApiConfig.baseUrl = ApiConfig.defaultBaseUrl;
    ApiConfig.chatbotBaseUrl = ApiConfig.defaultBaseUrl;
  }
  await ThemeService.instance.load();
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    if (!kIsWeb) {
      unawaited(BackendLauncher.instance.stop());
    }
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.detached && !kIsWeb) {
      unawaited(BackendLauncher.instance.stop());
    }
  }

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
          scrollBehavior: const DesktopScrollBehavior(),
          theme: AppTheme.light(),
          darkTheme: AppTheme.dark(),
          home: const EngineBootScreen(child: AuthGate()),
        );
      },
    );
  }
}
